var express = require('express');
var session = require('express-session');
var bodyParser = require('body-parser');
const fetch = require('node-fetch');

var auth = require('./auth.js');
var common = require('common');
var URL = require('url');
var helmet = require('helmet');

// Get all registered apps.
var appRegs = require('../config/apps.json');

Array.prototype.unique = function () {
    return this.filter((elem, pos) => this.indexOf(elem) == pos);
}

var scriptHosts = appRegs
    .filter(a => a.script !== undefined)
    .map(a => URL.parse(a.script))
    .map(u => u.protocol + "//" + u.host)
    .unique();

// Collect all API URLs as XHR hosts (for CSP)
var xhrHosts = appRegs
    .filter(a => a.config !== undefined)
    .filter(a => a.config.apiUri !== undefined)
    .map(a => URL.parse(a.config.apiUri))
    .map(u => u.protocol + "//" + u.host)
    .unique();

var iframeHosts = appRegs
    .filter(a => a.type == 'iframe')
    .map(a => URL.parse(a.url))
    .map(u => u.protocol + "//" + u.host)
    .unique();

/* SETUP */
var app = express();
app.set('views', 'src/views');
app.set('view engine', 'jade');

app.use(helmet());
app.use(helmet.csp({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-eval'", 'https://apis.google.com:443', 'https://storage.googleapis.com:443', 'https://use.typekit.net:443', "'unsafe-inline'"].concat(scriptHosts),
    styleSrc: ["'unsafe-inline'", "'self'", "blob:", 'https://fonts.googleapis.com:443', 'https://storage.googleapis.com:443', 'https://fonts.googleapis.com:443'],
    frameSrc: ['https://accounts.google.com:443'],
    fontSrc: ['data:', 'https://fonts.gstatic.com:443', 'https://use.typekit.net:443', "'self'"],
    connectSrc: ["'self'", "https://api.cloudinary.com", "https://tripletex.no"].concat(xhrHosts).concat(
      // allow localhost:8080 and localhost:8002 when in dev mode
      process.env.NODE_ENV === 'production' ? [] : ['http://localhost:8080', 'ws://localhost:8080', 'http://localhost:8002', 'ws://localhost:8002', 'http://localhost:8081', 'ws://localhost:8081']
    ),
    imgSrc: ["'self'", 'data:', 'https://apis.google.com:443', 'https://www.gravatar.com:443', 'https://source.unsplash.com:443', 'https://images.unsplash.com:443', 'https://p.typekit.net:443', 'https://res.cloudinary.com', 'https://storage.googleapis.com:443'],
    frameSrc: ["'self'", 'https://accounts.google.com/', 'https://content-sheets.googleapis.com/', 'https://content.googleapis.com/'].concat(iframeHosts)
  }
}))




// Redirect all requests to https
app.use(common.herokuHttpsRedirect);
app.use('/static', express.static('src/static'));
app.use('/', express.static('favicon'));

app.use(helmet.noCache())


app.use(session({
    resave: false,
    saveUninitialized: false,
    secret: "TODO: DO THIS RIGHT"
        // TODO: cookie: { secure: true }
}));
app.use(bodyParser.urlencoded({
    extended: false
}));
app.use(express.json());

/* PUBLIC PATHS */
app.get('/login', (req, res) =>  auth.authenticateWithGoogleAuthForLocalSystem(req, res,));
app.get('/login/oauth', (req, res) => auth.authenticateWithGoogleAuthForExternalSystem(req, res));
app.get('/login/oauth/callback', (req, res) => auth.handleGoogleAuthCallback(req, res));
app.post('/login/oauth/refresh', (req, res) => auth.refreshAccessToken(req, res));
app.get('/logout', (req, res) => auth.logout(req, res));

/* PRIVATE PATHS */
app.use(auth.requiresLogin);

app.get('/', (req, res) => {
    res.render('index', {
        title: 'Forside',
        apps: appRegs
    });
});

const invoiceApiUrl = (dateFrom, dateTo) => `https://tripletex.no/v2/invoice?invoiceDateFrom=${dateFrom}&invoiceDateTo=${dateTo}&count=1000&fields=isCreditNote,invoiceDate`
const tripleTexSessionUrl = (expirationDate) => `https://tripletex.no/v2/token/session/:create?consumerToken=${process.env.TRIPLETEX_CONSUMER_TOKEN}&employeeToken=${process.env.TRIPLETEX_EMPLOYEE_TOKEN}&expirationDate=${expirationDate}`
const tripleTexSessionExpired = (token) => new Date(token.expirationDate) <= new Date()

const tomorrow = () => {
    var tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    return tomorrow;
}

var tripleTexSession = null;

const getTripleTexSession = async () => await (await fetch(tripleTexSessionUrl(tomorrow().toISOString().split('T')[0]), {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    })).json()


app.get('/invoices', async (req, res) => {
    if (tripleTexSession === null || tripleTexSessionExpired(tripleTexSession)) {
        session = await getTripleTexSession()
        tripleTexSession = session.value
    }
    const dateFrom = req.query.dateFrom
    const dateTo = req.query.dateTo
    const headers = { 'Authorization': `Basic ${Buffer.from(`0:${tripleTexSession.token}`).toString('base64')}` }
    fetch( invoiceApiUrl(dateFrom, dateTo), { headers } )
        .then( invoiceResult => invoiceResult.status === 200 ? invoiceResult.json() : Promise.reject() )
        .then( data => res.json(data) )
        .catch( err => {
            res.status(500).send(err)
        } )
})

// Set up paths for each registered app.
appRegs.forEach((appReg) => {
    switch (appReg.type) {
        case 'app':
            app.get('/' + appReg.short_name + '*', (req, res) => {
                res.render('app', {
                    title: appReg.name,
                    script: appReg.script,
                    // TODO: Remove google id_token once all apps are changed over.
                    id_token: req.session.id_token,
                    apiToken: req.session.apiToken,
                    email: req.session.email,
                    config: JSON.stringify(appReg.config),
                    apps: appRegs
                });
            });
            break;
        case 'iframe':
            app.get('/' + appReg.short_name + '*', (req, res) => {
                res.render('iframe', {
                    url: appReg.url,
                    apps: appRegs
                })
            });
            break;
        default:

    }

});

app.use(function(err, _req, res, _next) {
    console.error(err);

    res.status(500).send("An unhandled error occurred");
});

/* START SERVER */
var server = app.listen(process.env.PORT || 3000, () => {
    var host = server.address().address;
    var port = server.address().port;

    console.log('Listening at http://%s:%s', host, port);
});
