var express = require('express');
var bodyParser = require('body-parser');
var session = require('express-session');
var http = require('http');
var samlp = require('samlp');
var xtend = require('xtend');
var fs = require('fs');
var path = require('path');
var passport = require('passport');
var SamlpStrategy = require('../../lib/sso-kit').Strategy.Samlp;

/**
 * Globals
 */

var idpSsoUrl = 'http://localhost:5051/samlp';
var relayState = '/deep/link/state';

var defaultOptions = {
    path: '/callback',
    audience: 'urn:fixture:sp',
    issuer: 'urn:fixture:idp',
    idpSsoUrl: idpSsoUrl,
    thumbprint: '5ca6e1202eafc0a63a5b93a43572eb2376fed309',
    checkInResponseTo: false,
    checkDestination: false
}

var fakeUser = {
  id: '12345678',
  displayName: 'Saml Jackson',
  name: {
    familyName: 'Saml',
    givenName: 'Jackson'
  },
  emails: [
    {
      type: 'work',
      value: 'saml.jackson@example.com'
    }
  ]
};

var credentials = {
  cert:     fs.readFileSync(path.join(__dirname, '../test-auth0.pem')),
  key:      fs.readFileSync(path.join(__dirname, '../test-auth0.key'))
};

var verifyProfile = function(profile, response, done) {
  return done(null, profile);
}

/**
 * Passport Fixture Setup
 */

passport.use('samlp', new SamlpStrategy(defaultOptions, verifyProfile)
);

passport.use('samlp-idpurl-with-querystring', new SamlpStrategy(xtend(defaultOptions, {
    audience: 'https://auth0-dev-ed.my.salesforce.com',
    idpSsoUrl: idpSsoUrl + '?foo=bar'
  }), verifyProfile)
);

passport.use('samlp-signedassertion', new SamlpStrategy(xtend(defaultOptions, {
    audience: 'https://auth0-dev-ed.my.salesforce.com',
    requireResponseSignature: false
  }), verifyProfile)
);

passport.use('samlp-signedresponse', new SamlpStrategy(xtend(defaultOptions, {
    audience: 'https://auth0-dev-ed.my.salesforce.com'
  }), verifyProfile)
);

passport.use('samlp-signedresponse-invalidcert', new SamlpStrategy(xtend(defaultOptions, {
    thumbprint: '11111111111111111a5b93a43572eb2376fed309'
  }), verifyProfile)
);

passport.use('samlp-invalidcert', new SamlpStrategy(xtend(defaultOptions, {
    thumbprint: '11111111111111111a5b93a43572eb2376fed309'
  }), verifyProfile)
);

passport.use('samlp-signedresponse-signedassertion', new SamlpStrategy(xtend(defaultOptions, {
    audience: 'urn:auth0:login-dev3',
    issuer: 'https://openidp.feide.no',
    // we are using a precomputed assertion generated from a sample idp feide
    thumbprint: 'C9ED4DFB07CAF13FC21E0FEC1572047EB8A7A4CB',
    checkExpiration: false
  }), verifyProfile)
);

passport.use('samlp-adfs', new SamlpStrategy(xtend(defaultOptions, {
  audience: 'urn:example:sp',
  acsUrl: "https://localhost:5051/callback",
  issuer: 'http://kdc.corp.example.com/adfs/services/trust',
  thumbprint: 'F127098178127B5B5EB051CD54F7E0C2E5038D65',
  requireResponseSignature: false,
  checkInResponseTo: false,
  checkDestination: true,
  checkExpiration: false
  }), verifyProfile)
);

passport.use('samlp-ping', new SamlpStrategy(xtend(defaultOptions, {
    audience: 'urn:auth0:login-dev3',
    // we are using a precomputed assertion generated from a sample idp feide
    thumbprint: '44340220770a348444be34970939cff8a2d74f08',
    issuer: 'PingConnect',
    requireResponseSignature: false,
    checkExpiration: false
  }), verifyProfile)
);

passport.use('samlp-okta', new SamlpStrategy(xtend(defaultOptions, {
    audience: 'https://auth0145.auth0.com',
    // we are using a precomputed assertion generated from a sample idp feide
    thumbprint: 'a0c7dbb790e3476d3c5dd236f9f2060b1fd6e253',
    issuer: 'http://www.okta.com/k7xkhq0jUHUPQAXVMUAN',
    requireResponseSignature: false,
    checkExpiration: false
  }), verifyProfile)
);

passport.use('samlp-with-utf8', new SamlpStrategy(xtend(defaultOptions, {
    // we are using a precomputed assertion generated from a sample idp feide
    issuer: 'https://aai-logon.ethz.ch/idp/shibboleth',
    thumbprint: '42FA24A83E107F6842E05D2A2CA0A0A0CA8A2031',
    decryptionKey: fs.readFileSync(path.join(__dirname, '../test-decryption.key')),
    requireResponseSignature: false,
    checkExpiration: false,
    checkAudience: false
  }), verifyProfile)
);

passport.use('samlp-with-inresponseto-validation', new SamlpStrategy(xtend(defaultOptions, {
    checkInResponseTo: true
  }), verifyProfile)
);

passport.use('samlp-signed-request', new SamlpStrategy(xtend(defaultOptions, {
    signRequest: true,
    signatureKey: credentials.key
  }), verifyProfile)
);

passport.use('samlp-slo', new SamlpStrategy(xtend(defaultOptions, {
    signRequest: true,
    signatureKey: credentials.key
  }), verifyProfile)
);


/**
 * SAMLP Server
 */

module.exports.options = {};

module.exports.start = function(options, callback){
  module.exports.options = options;
  if (typeof options === 'function') {
    callback = options;
    module.exports.options = {};
  }

  var app = express();

  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(session({
    secret: "keyboard cat",
    resave: false,
    saveUninitialized: true}));
  app.use(passport.initialize());
  app.use(passport.session());
  app.use(function(req,res,next){
    req.user = fakeUser;
    next();
  });

  function getPostURL (audience, samlRequestDom, req, callback) {
    callback(null, 'http://localhost:5051/callback');
  }

  //configure samlp middleware
  app.get('/samlp', function(req, res, next) {
    samlp.auth(xtend({}, {
        issuer:             'urn:fixture:idp',
        getPostURL:         getPostURL,
        cert:               credentials.cert,
        key:                credentials.key
      }, module.exports.options))(req, res);
  });

  app.get('/login', passport.authenticate('samlp', { relayState: relayState }));
  app.get('/login-idp-with-querystring', passport.authenticate('samlp-idpurl-with-querystring', { relayState: relayState }));

  app.get('/login-with-inresponseto-validation',
    passport.authenticate('samlp-with-inresponseto-validation', { relayState: relayState }));

  app.get('/login-with-signed-request', passport.authenticate('samlp-signed-request', { relayState: relayState }));

  app.post('/callback',
    function(req, res, next) {
      //console.log('req.body');
      next();
    },
    passport.authenticate('samlp'),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-signedassertion',
    passport.authenticate('samlp-signedassertion'),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-signedresponse',
    passport.authenticate('samlp-signedresponse'),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-signedresponse-invalidcert',
    passport.authenticate('samlp-signedresponse-invalidcert'),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-invalidcert',
    passport.authenticate('samlp-invalidcert'),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-signedresponse-signedassertion',
    passport.authenticate('samlp-signedresponse-signedassertion'),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-adfs',
    passport.authenticate('samlp-adfs'),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-ping',
    passport.authenticate('samlp-ping'),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-okta',
    passport.authenticate('samlp-okta'),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-with-utf8',
    passport.authenticate('samlp-with-utf8'),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-with-inresponseto-validation',
    passport.authenticate('samlp-with-inresponseto-validation'),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.get('/callback/slo', function(req, res, next) {
    var stategy = passport._strategy(passport);

  })

  app.use(function(err, req, res, next) {
    console.log(err);
    next();
  });

  var server = http.createServer(app).listen(5051, callback);
  module.exports.close = server.close.bind(server);
};

module.exports.relayState = relayState;
module.exports.idpSsoUrl = idpSsoUrl;
module.exports.fakeUser = fakeUser;
module.exports.credentials = credentials;
