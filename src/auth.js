const crypto = require('crypto');
const common = require('common');

const Promise = require('promise/lib/es6-extensions');
const { OAuth2Client } = require('google-auth-library');

const OAUTH_CLIENT_ID = process.env.GOOGLE_AUTH_CLIENT_ID;
const OAUTH_CLIENT_SECRET = process.env.GOOGLE_AUTH_CLIENT_SECRET;
const OAUTH_REDIRECT_URI = process.env.GOOGLE_AUTH_REDIRECT_URI;
const OAUTH_STATE_TTL = 1000 * 60 * 10; // 10 minutes in ms
// more valid client URIs can be added when needed
const OAUTH_EXTERNAL_REDIRECT_URIS_REGEX = [
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

// Starts a OAuth authentication flow that saves credentials in session and redirects to a relative URL
async function authenticateWithGoogleAuthForLocalSystem(req, res) {
    var clientRedirect = req.query.to;
    if (!clientRedirect) {
        clientRedirect = '/';
    } else if (!clientRedirect.startsWith('/')) {
        res.status(400).send('Value of query parameter "to" is invalid, must be relative URL when logging in this way.');
        return;
    }

    const oAuth2Client = newOauthClient();

    const state = crypto.randomBytes(20).toString('hex');
    authRequestState[state] = { clientRedirect: clientRedirect, local: true, created: Date.now() };

    const authorizeUrl = oAuth2Client.generateAuthUrl({
        access_type: 'online', // no refresh token is created
        scope: 'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email',
        state,
        prompt: 'consent',
    });
    res.redirect(authorizeUrl);
}

// Starts a OAuth authentication flow that sends credentials to an external system, saving nothing in session
async function authenticateWithGoogleAuthForExternalSystem(req, res) {
    const clientRedirect = req.query.to;
    if (!clientRedirect) {
        res.status(400).send('Required query parameter "to" is missing');
    }
    if (!clientRedirect || !OAUTH_EXTERNAL_REDIRECT_URIS_REGEX.find(regex => regex.test(clientRedirect))) {
        res.status(400).send('Value of query parameter "to" is invalid');
        return;
    }

    const oAuth2Client = newOauthClient();

    const state = crypto.randomBytes(20).toString('hex');
    authRequestState[state] = { clientRedirect: clientRedirect, local: false, created: Date.now() };

    const authorizeUrl = oAuth2Client.generateAuthUrl({
        access_type: 'offline', // creates a refresh token
        scope: 'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email',
        state,
        prompt: 'consent',
    });
    res.redirect(authorizeUrl);
}

async function handleGoogleAuthCallback(req, res) {
    const reqCode = req.query.code;
    if (!reqCode) {
        res.status(400).send('Required "code" parameter in Google Auth callback is missing');
        return;
    }

    const state = loadAuthRequestStateOrSetResponse(req, res);
    clearLongOverdueStates();
    if (!state) {
        return;
    }

    const oauthClient = newOauthClient();
    const tokenRes = await oauthClient.getToken(reqCode);

    const data = await authenticateGoogleIdToken(tokenRes.tokens.id_token, oauthClient);
    if (data.err) {
        res.status(401).send(data.err);
        return;
    }

    const accessToken = toSignedJWT(data);

    if (state.local) {
        req.session.apiToken = accessToken;
        req.session.email = data.email;
        // TODO: Supplying google id_token too for now, until all apps are changed over.
        req.session.id_token = req.body.id_token;

        res.redirect(state.clientRedirect);
    } else {
        const expiry_date = new Date(tokenRes.tokens.expiry_date);
        expiry_date.setDate(expiry_date.getDate() + 7);

        res.redirect(`${state.clientRedirect}?access_token=${accessToken}&expiry_date=${expiry_date.toISOString()}&refresh_token=${tokenRes.tokens.refresh_token}`);
    }
}

function loadAuthRequestStateOrSetResponse(req, res) {
    const reqState = req.query.state;
    if (!reqState) {
        res.status(400).send('Required "state" parameter in Google Auth callback is missing');
        return null;
    }
    const cachedState = authRequestState[reqState];
    if (!cachedState) {
        res.status(400).send('Unrecognized value in "state" parameter');
        return null;
    }
    delete authRequestState[reqState];
    if (Date.now() - cachedState.created > OAUTH_STATE_TTL) {
        res.status(400).send(`State has expired, please complete authentication within ${OAUTH_STATE_TTL / 1000 / 60} minutes`);
        return null;
    }
    return cachedState;
}

// Removes abandoned auth request states
function clearLongOverdueStates() {
    for (const key in authRequestState) {
        if (Date.now() - authRequestState[key].created > OAUTH_STATE_TTL * 10) {
            delete authRequestState[key];
        }
    }
}

async function authenticateGoogleIdToken(idToken, authClient) {
    if (!idToken) {
        return { err: 'No token' };
    }

    return authClient.verifyIdToken({idToken})
        .then(login => {    
            var payload = login.getPayload();
    
            if (payload.aud !== OAUTH_CLIENT_ID) {
                return { err: 'Unrecognized client' };
            }
    
            if (payload.iss !== 'accounts.google.com'
                    && payload.iss !== 'https://accounts.google.com') {
                return { err: 'Wrong issuer' };
            }
    
            if (ACCEPTED_EMAIL_DOMAINS.indexOf(payload.hd) === -1) {
                return { err: 'Wrong hosted domain: ' + (payload.hd || 'unknown') };
            }
    
            return payload;
        })
        .catch(err => {
            return { err };
        });
}

function toSignedJWT(data) {
    return common.auth.signAPIAccessToken({
        role: process.env.API_ROLE || 'employee',
        // TODO: Should fetch employee ID instead.
        email: data.email
    });
}

async function refreshAccessToken(req, res) {
    const refresh_token = req.body.refresh_token;
    if (!refresh_token) {
        res.status(400).send('Missing required field "refresh_token" in body');
        return;
    }

    const oauthClient = newOauthClient();
    oauthClient.setCredentials({
        refresh_token,
    })
    const tokenRes = await oauthClient.getAccessToken();
    const expiry_date = tokenRes.res.data.expiry_date;

    const data = await authenticateGoogleIdToken(tokenRes.res.data.id_token, oauthClient);
    if (data.err) {
        res.status(401).send(data.err);
        return;
    }

    const jwt_expiry_date = new Date(expiry_date);
    jwt_expiry_date.setDate(jwt_expiry_date.getDate() + 7);

    res.status(200).send({
        access_token: toSignedJWT(data), 
        expiry_date: jwt_expiry_date.toISOString(),
    });
    return;
}

function logout(req, res) {
    req.session.destroy();
    res.status(200).send('See ya! 👋');
}

module.exports = {
    requiresLogin,
    validRedirect,
    authenticateWithGoogleAuthForLocalSystem,
    authenticateWithGoogleAuthForExternalSystem,
    handleGoogleAuthCallback,
    refreshAccessToken,
    logout,
};
