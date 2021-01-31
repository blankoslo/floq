const crypto = require('crypto');
const url = require('url');

var common = require('common');

const Promise = require('promise/lib/es6-extensions');
const { auth, OAuth2Client } = require('google-auth-library');

const clientSecret = require('../client-secret.json');

const JWT_AUD = '1085640931155-0f6l02jv973og8mi4nb124k6qlrh470p.apps.googleusercontent.com';

const OAUTH_CLIENT_ID = process.env.GOOGLE_AUTH_CLIENT_ID;
const OAUTH_CLIENT_SECRET = process.env.GOOGLE_AUTH_CLIENT_SECRET;
const OAUTH_REDIRECT_URI = process.env.GOOGLE_AUTH_REDIRECT_URI;
const OATH_STATE_TTL = 1000 * 60 * 10; // 10 minutes in ms
// more client URIs can be added when needed
const OAUTH_CLIENT_REDIRECT_URI_REGEX = /^https?:\/\/)?(localhost)(:[0-9]+)?(\/.*)?$/; // any localhost address

const ACCEPTED_EMAIL_DOMAINS = (process.env.FLOQ_ACCEPTED_EMAIL_DOMAINS || 'blank.no').split(",");

const TOKEN_BUFFER_SECONDS = 3600 * 12;

const authRequestState = {};

const jwtClient = auth.fromJSON(clientSecret);

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

function authenticateGoogleIdToken(idToken) {
    return authenticateGoogleIdTokenWithClient(idToken, JWT_AUD, jwtClient);
}

function authenticateGoogleIdTokenWithClient(idToken, clientId, authClient) {
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
            console.log(`Payload ${JSON.stringify(payload)}`);

            if (payload.aud !== clientId) {
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

async function authenticateWithGoogleAuth(req, res) {
    if (!req.query.to || !OAUTH_CLIENT_REDIRECT_URI_REGEX.test(req.query.to)) {
        res.status(400).text('Value of query parameter "to" is invalid');
        return;
    }

    const oAuth2Client = new OAuth2Client(
        OAUTH_CLIENT_ID,
        OAUTH_CLIENT_SECRET,
        OAUTH_REDIRECT_URI,
    );

    const state = crypto.randomBytes(20).toString('hex');
    authRequestState[state] = { to: req.query.to, created: Date.now() };

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
        res.status(400).text('Missing required code parameter in Google Auth callback');
        return;
    }

    const state = loadAuthRequestStateOrSetResponse(req, res);
    clearLongOverdueStates();
    if (!state) {
        return;
    }

    const oAuth2Client = new OAuth2Client(
        OAUTH_CLIENT_ID,
        OAUTH_CLIENT_SECRET,
        OAUTH_REDIRECT_URI,
    );
    const tokenRes = await oAuth2Client.getToken(reqCode);
    console.log(`Tokens ${JSON.stringify(tokenRes)}`); // TODO remove log

    const data = await authenticateGoogleIdTokenWithClient(tokenRes.tokens.id_token, OAUTH_CLIENT_ID, oAuth2Client);
    
    const apiToken = common.auth.signAPIAccessToken({
        role: process.env.API_ROLE || 'employee',
        // TODO: Should fetch employee ID instead.
        email: data.email
    });

    res.redirect(`${state.to}?access_token=${apiToken}&refresh_token=${tokenRes.tokens.refresh_token}`);
}

function loadAuthRequestStateOrSetResponse(req, res) {
    const reqState = req.query.state;
    if (!reqState) {
        res.status(400).text('Missing required state parameter in Google Auth callback');
        return null;
    }
    const cachedState = authRequestState[reqState];
    if (!cachedState) {
        res.status(400).text('Unknown value in state parameter');
        return null;
    }
    delete authRequestState[reqState];
    if (Date.now() - cachedState.created > OATH_STATE_TTL) {
        res.status(400).text(`State has expired, please complete authentication within ${OATH_STATE_TTL / 1000 / 60} minutes`);
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

module.exports = {
    requiresLogin,
    validRedirect,
    authenticateGoogleIdToken,
    authenticateWithGoogleAuth,
    handleGoogleAuthCallback,
};
