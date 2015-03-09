var passport = require('passport-strategy');
var url = require('url');
var util = require('util');
var xtend = require('xtend');
var saml = require('./saml');
var wsfed = require('./wsfederation');
var samlp = require('./samlp');
var xmldom = require('xmldom');
var jwt = require('jsonwebtoken');

function SamlpStrategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }

  if (!verify) {
    throw new Error('this strategy requires a verify function');
  }

  this.name = 'samlp';
  this.options = options || {};
  this._verify = verify;
  this._saml = new saml.SAML(this.options);
  this._samlp =  new samlp(this.options, this._saml);

  passport.Strategy.call(this);
}
util.inherits(SamlpStrategy, passport.Strategy);

SamlpStrategy.prototype.authenticate = function(req, options) {
  var self = this;
  options = xtend(this.options, options);

  if (req.body && req.method == 'POST' && req.body.SAMLResponse) {
    var samlResponse = self._samlp.decodeResponse(req);
    if (samlResponse.indexOf('<') === -1) {
      return self.fail('SAMLResponse should be a valid xml', 400);
    }

    // We have a response, get the user identity out of it
    var samlResponseDom = new xmldom.DOMParser().parseFromString(samlResponse);
    self._samlp.validateSamlResponse(samlResponseDom, options, function (err, profile, response) {
      console.log(err);
      if (err) return self.fail(err, 400);

      self._verify(profile, response, function (err, user, info) {
        if (err) return self.error(err);
        if (!user) return self.fail(info);
        self.success(user, info);
      });
    });
  } else {
    if (!options.idpSsoUrl && options.path) {
      options.idpSsoUrl = url.resolve((req.protocol || 'http').concat('://') + 
        req.headers.host, options.path);
    }

    // Initiate new samlp authentication request
    var authnRequest = self._samlp.generateAuthnRequest(req, options);
    self._samlp.getSamlRequestUrl(authnRequest, options.idpSsoUrl, options, function(err, url) {
      if (err) return self.error(err);
      self.redirect(url);
    });
  }  
}

SamlpStrategy.prototype.logout = function(req, options) {
  var self = this;
  options = xtend(this.options, options);



  
  if ((req.method === 'POST' && req.body && req.body.SAMLRequest) || 
    req.metod === 'GET' && req.query.SAMLRequest) {

    if (req.user && req.user.nameId && req.user.nameIdFormat) {

  
      self._samlp.validateRequest(req, options, function(err, logoutRequest) {
        if (err) { return self.error(err); }


      })
    }
  }


          req.logout();
        if (profile) {
          req.samlLogoutRequest = profile;
          return self._saml.getLogoutResponseUrl(req, redirectIfSuccess);
        }
        return self.pass();

}

SamlpStrategy.prototype.authorizationParams = function(options) {
  return options;
};

function WsFedStrategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }

  if (!verify) {
    throw new Error('this strategy requires a verify function');
  }

  this.name = 'wsfed';
  this.options = options || {};
  this._verify = verify;
  this._saml = new saml.SAML(this.options);
  if (this.options.jwt) {
    this._jwt = this.options.jwt;
  }
  this._wsfed =  new wsfed(options.realm, options.homeRealm, options.idpSsoUrl, options.wreply);


  passport.Strategy.call(this);
}
util.inherits(WsFedStrategy, passport.Strategy);

WsFedStrategy.prototype.authenticate = function(req, options) {
  var self = this;
  options = xtend(this.options, options);

  if (req.body && req.method == 'POST' && req.body.wresult) {
    // We have a response, get the user identity out of it
    if (self._jwt) {
      self._authenticate_jwt(req);
    } else {
      self._authenticate_saml(req);
    }
  } else {
    // Initiate new ws-fed authentication request
    var params = self.authorizationParams(options);
    var idpUrl = self._wsfed.getRequestSecurityTokenUrl(params);
    self.redirect(idpUrl);
  }
}

WsFedStrategy.prototype._authenticate_saml = function (req) {
  var self = this;

  if (req.body.wresult.indexOf('<') === -1) {
    return self.fail('wresult should be a valid xml', 400);
  }

  var token = self._wsfed.extractToken(req);
  if (!token) {
    return self.fail('missing RequestedSecurityToken element', 400);
  }

  self._saml.validateSamlAssertion(token, function (err, profile) {
    if (err) {
      return self.error(err);
    }

    var verified = function (err, user, info) {
      if (err) {
        return self.error(err);
      }

      if (!user) {
        return self.fail(info);
      }

      self.success(user, info);
    };

    self._verify(profile, verified);
  });
};

WsFedStrategy.prototype._authenticate_jwt = function (req) {
  var self = this;
  var token = req.body.wresult;
  jwt.verify(token, this.options.cert, this._jwt, function (err, profile) {
    if (err) {
      return self.error(err);
    }

    var verified = function (err, user, info) {
      if (err) {
        return self.error(err);
      }

      if (!user) {
        return self.fail(info);
      }

      self.success(user, info);
    };

    self._verify(profile, verified);
  });
};

WsFedStrategy.prototype.authorizationParams = function(options) {
  return options;
};

module.exports.Samlp = SamlpStrategy;
module.exports.WsFed = WsFedStrategy;