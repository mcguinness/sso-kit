var express = require('express');
var bodyParser = require('body-parser');
var session = require('express-session');
var http = require('http');
var samlp = require('samlp');
var xtend = require('xtend');
var fs = require('fs');
var path = require('path');
var passport = require('passport');
var Strategy = require('../../lib/passport-wsfed-saml2').Strategy;

/**
 * Globals
 */

var identityProviderUrl = 'http://localhost:5051/samlp';
var relayState = '/deep/link/state';

var defaultOptions = {
    path: '/callback',
    realm: 'urn:fixture:sp',
    identityProviderUrl: identityProviderUrl,
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

/**
 * Passport Fixture Setup
 */

passport.use('samlp', new Strategy(defaultOptions, function(profile, done) {
    return done(null, profile);
  })
);

passport.use('samlp-idpurl-with-querystring', new Strategy(xtend(defaultOptions, {
    realm: 'https://auth0-dev-ed.my.salesforce.com',
    identityProviderUrl: identityProviderUrl + '?foo=bar'
  }),
  function(profile, done) {
    return done(null, profile);
  })
);

passport.use('samlp-signedassertion', new Strategy(xtend(defaultOptions, {
    realm: 'https://auth0-dev-ed.my.salesforce.com'
  }), function(profile, done) {
    return done(null, profile);
  })
);

passport.use('samlp-signedresponse', new Strategy(xtend(defaultOptions, {
    realm: 'https://auth0-dev-ed.my.salesforce.com'
  }), function(profile, done) {
    return done(null, profile);
  })
);

passport.use('samlp-signedresponse-invalidcert', new Strategy(xtend(defaultOptions, {
    thumbprint: '11111111111111111a5b93a43572eb2376fed309'
  }), function(profile, done) {
    return done(null, profile);
  })
);

passport.use('samlp-invalidcert', new Strategy(xtend(defaultOptions, {
    thumbprint: '11111111111111111a5b93a43572eb2376fed309'
  }), function(profile, done) {
    return done(null, profile);
  })
);

passport.use('samlp-signedresponse-signedassertion', new Strategy(xtend(defaultOptions, {
    realm: 'urn:auth0:login-dev3',
    // we are using a precomputed assertion generated from a sample idp feide
    thumbprint: 'C9ED4DFB07CAF13FC21E0FEC1572047EB8A7A4CB',
    checkExpiration: false
  }), function(profile, done) {
    return done(null, profile);
  })
);

passport.use('samlp-ping', new Strategy(xtend(defaultOptions, {
    realm: 'urn:auth0:login-dev3',
    // we are using a precomputed assertion generated from a sample idp feide
    thumbprint: '44340220770a348444be34970939cff8a2d74f08',
    checkExpiration: false
  }), function(profile, done) {
    return done(null, profile);
  })
);

passport.use('samlp-okta', new Strategy(xtend(defaultOptions, {
    realm: 'https://auth0145.auth0.com',
    // we are using a precomputed assertion generated from a sample idp feide
    thumbprint: 'a0c7dbb790e3476d3c5dd236f9f2060b1fd6e253',
    checkExpiration: false
  }), function(profile, done) {
    return done(null, profile);
  })
);


passport.use('samlp-with-utf8', new Strategy(xtend(defaultOptions, {
    // we are using a precomputed assertion generated from a sample idp feide
    thumbprint: '42FA24A83E107F6842E05D2A2CA0A0A0CA8A2031',
    decryptionKey: fs.readFileSync(path.join(__dirname, '../test-decryption.key')),
    checkExpiration: false,
    checkAudience: false
  }), function(profile, done) {
    return done(null, profile);
  })
);

passport.use('samlp-with-inresponseto-validation', new Strategy(xtend(defaultOptions, {
    checkInResponseTo: true
  }), function(profile, done) {
    return done(null, profile);
  })
);

passport.use('samlp-signed-request', new Strategy(xtend(defaultOptions, {
    signRequest: true,
    signatureKey: credentials.key
  }), function(profile, done) {
    return done(null, profile);
  })
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

  app.get('/login', passport.authenticate('samlp', { protocol: 'samlp', RelayState: relayState }));
  app.get('/login-idp-with-querystring', passport.authenticate('samlp-idpurl-with-querystring', { protocol: 'samlp', RelayState: relayState }));

  app.get('/login-with-inresponseto-validation',
    passport.authenticate('samlp-with-inresponseto-validation', { protocol: 'samlp', RelayState: relayState }));

  app.get('/login-with-signed-request', passport.authenticate('samlp-signed-request', { protocol: 'samlp', RelayState: relayState }));

  app.post('/callback',
    function(req, res, next) {
      //console.log('req.body');
      next();
    },
    passport.authenticate('samlp', { protocol: 'samlp' }),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-signedassertion',
    passport.authenticate('samlp-signedassertion', { protocol: 'samlp' }),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-signedresponse',
    passport.authenticate('samlp-signedresponse', { protocol: 'samlp' }),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-signedresponse-invalidcert',
    passport.authenticate('samlp-signedresponse-invalidcert', { protocol: 'samlp' }),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-invalidcert',
    passport.authenticate('samlp-invalidcert', { protocol: 'samlp' }),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-signedresponse-signedassertion',
    passport.authenticate('samlp-signedresponse-signedassertion', { protocol: 'samlp' }),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-ping',
    passport.authenticate('samlp-ping', { protocol: 'samlp' }),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-okta',
    passport.authenticate('samlp-okta', { protocol: 'samlp' }),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-with-utf8',
    passport.authenticate('samlp-with-utf8', { protocol: 'samlp' }),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-with-inresponseto-validation',
    passport.authenticate('samlp-with-inresponseto-validation', { protocol: 'samlp' }),
    function(req, res) {
      res.json(req.user);
    }
  );

  var server = http.createServer(app).listen(5051, callback);
  module.exports.close = server.close.bind(server);
};

module.exports.relayState = relayState;
module.exports.identityProviderUrl = identityProviderUrl;
module.exports.fakeUser = fakeUser;
module.exports.credentials = credentials;
