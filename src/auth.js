const crypto = require('crypto');
const common = require('common');

const Promise = require('promise/lib/es6-extensions');
const { OAuth2Client } = require('google-auth-library');

const OAUTH_CLIENT_ID = process.env.GOOGLE_AUTH_CLIENT_ID;
const OAUTH_CLIENT_SECRET = process.env.GOOGLE_AUTH_CLIENT_SECRET;
const OAUTH_REDIRECT_URI = process.env.GOOGLE_AUTH_REDIRECT_URI;
const OATH_STATE_TTL = 1000 * 60 * 10; // 10 minutes in ms
// more valid client URIs can be added when needed
const OAUTH_CLIENT_REDIRECT_URIS_REGEX = [
    /(^https:\/\/inni.blank.no)(\/.*)?$/,
    /(^https:\/\/blank-test.floq.no)(\/.*)?$/,
    /(^https:\/\/folq.floq.no)(\/.*)?$/,
    /(^https?:\/\/)(localhost)(:[0-9]+)?(\/.*)?$/,
];

const ACCEPTED_EMAIL_DOMAINS = (process.env.FLOQ_ACCEPTED_EMAIL_DOMAINS || 'blank.no').split(",");

const TOKEN_BUFFER_SECONDS = 3600 * 12;

const authRequestState = {};

function newOauthClient() {
    return new OAuth2Client(
        OAUTH_CLIENT_ID,
        OAUTH_CLIENT_SECRET,
        OAUTH_REDIRECT_URI
    );
}

function requiresLogin(req, res, next) {
    // TODO: Check if valid employee loaded.
    if (req.session.apiToken) {
        common.auth.verifyAPIAccessToken(req.session.apiToken)
            .then(
                (data) => {
                    var date = new Date();
                    var currentTime = date.getTime() / 1000;

                    if (data.exp - currentTime < TOKEN_BUFFER_SECONDS) {
                        res.redirect('login?to=' + req.originalUrl);
                    }
                },
                (err) => res.status(401).send(err)
            );
        return next();
    }
    res.redirect('/login?to=' + req.originalUrl);
}

function validRedirect(app, path) {
    var routes = app._router.stack
        .filter((layer) => layer.route !== undefined);

    for (var route in routes) {
        var re = routes[route].regexp;
        if (re.test(path)) {
            return true;
        }
    }

    return false;
}

async function authenticateWithGoogleAuth(res, clientRedirect, saveSession) {
    // relative URLs and those matching certain domains are accepted
    if (!clientRedirect.startsWith('/') && 
        (!clientRedirect || !OAUTH_CLIENT_REDIRECT_URIS_REGEX.find(regex => regex.test(clientRedirect)))
    ) {
        res.status(400).send('Value of query parameter to is invalid');
        return;
    }

    const oAuth2Client = newOauthClient();

    const state = crypto.randomBytes(20).toString('hex');
    authRequestState[state] = { clientRedirect: clientRedirect, saveSession, created: Date.now() };

    const authorizeUrl = oAuth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: 'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email',
        state,
        prompt: 'consent',
    });
    res.redirect(authorizeUrl);
}

async function handleGoogleAuthCallback(req, res) {
    const reqCode = req.query.code;
    if (!reqCode) {
        res.status(400).send('Missing required code parameter in Google Auth callback');
        return;
    }

    const state = loadAuthRequestStateOrSetResponse(req, res);
    clearLongOverdueStates();
    if (!state) {
        return;
    }

    const oAuth2Client = newOauthClient();
    const tokenRes = await oAuth2Client.getToken(reqCode);

    const data = await authenticateGoogleIdToken(tokenRes.tokens.id_token, oAuth2Client);
    
    const apiToken = common.auth.signAPIAccessToken({
        role: process.env.API_ROLE || 'employee',
        // TODO: Should fetch employee ID instead.
        email: data.email
    });

    if (state.saveSession) {
        req.session.apiToken = apiToken;
        req.session.email = data.email;
        // TODO: Supplying google id_token too for now, until all apps are changed over.
        req.session.id_token = req.body.id_token;

        res.redirect(state.clientRedirect);
    } else {
        res.redirect(`${state.clientRedirect}?access_token=${apiToken}&refresh_token=${tokenRes.tokens.refresh_token}`);
    }
}

function loadAuthRequestStateOrSetResponse(req, res) {
    const reqState = req.query.state;
    if (!reqState) {
        res.status(400).send('Missing required state parameter in Google Auth callback');
        return null;
    }
    const cachedState = authRequestState[reqState];
    if (!cachedState) {
        res.status(400).send('Unknown value in state parameter');
        return null;
    }
    delete authRequestState[reqState];
    if (Date.now() - cachedState.created > OATH_STATE_TTL) {
        res.status(400).send(`State has expired, please complete authentication within ${OATH_STATE_TTL / 1000 / 60} minutes`);
        return null;
    }
    return cachedState;
}

/**
 * Removes abandoned auth request states
 */
function clearLongOverdueStates() {
    for (const key in authRequestState) {
        if (Date.now() - authRequestState[key].created > OATH_STATE_TTL * 10) {
            delete authRequestState[key];
        }
    }
}

function authenticateGoogleIdToken(idToken, authClient) {
    return new Promise((resolve, reject) => {
        if (!idToken) {
            reject('No token');
            return;
        }

        var callback = (err, data) => {
            if (err) {
                reject(err);
                return;
            }

            var payload = data.getPayload();

            if (payload.aud !== OAUTH_CLIENT_ID) {
                reject('Unrecognized client.');
                return;
            }

            if (payload.iss !== 'accounts.google.com'
                    && payload.iss !== 'https://accounts.google.com') {
                reject('Wrong issuer.');
                return;
            }

            if (ACCEPTED_EMAIL_DOMAINS.indexOf(payload.hd) === -1) {
                reject('Wrong hosted domain: ' + payload.hd);
                return;
            }

            resolve(payload);
        }
        authClient.verifyIdToken({idToken}, callback);
    });
}

async function refreshAccessToken(req, res) {
    const refresh_token = req.body.refresh_token;
    if (!refresh_token) {
        res.status(400).send('Missing required field refresh_token in body');
        return;
    }

    const oauthClient = newOauthClient();
    oauthClient.setCredentials({
        refresh_token,
    })
    const tokenRes = await oauthClient.getAccessToken();

    res.status(200).send({access_token: tokenRes.token});
    return;
}

function logout(req, res) {
    req.session.destroy();
    res.status(200).send('See ya! 👋');
}

module.exports = {
    requiresLogin,
    validRedirect,
    authenticateWithGoogleAuth,
    handleGoogleAuthCallback,
    refreshAccessToken,
    logout,
};
