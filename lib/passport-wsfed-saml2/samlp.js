var path = require('path');
var xmldom = require('xmldom');
var xpath = require('xpath');
var qs = require('querystring');
var zlib = require('zlib');
var xtend = require('xtend');
var xmlbuilder = require('xmlbuilder');
var url = require('url');
var crypto = require('crypto');
var xmlenc = require('xml-encryption');
var async = require('async');
var InMemoryCacheProvider = require('./inmemory-cache-provider.js').CacheProvider;


var algorithms = {
  'rsa-sha256': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
  'rsa-sha1':  'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
};

var namespaces = {
  assertion: 'urn:oasis:names:tc:SAML:2.0:assertion'
}

var Samlp = module.exports = function Samlp (options, saml) {
  this.options = xtend({}, options);

  this.options.protocolBinding = options.protocolBinding || 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';

  this.options.deflate = (typeof this.options.deflate !== 'undefined') ? this.options.deflate : true;
  this.options.forceAuthn = (typeof this.options.forceAuthn !== 'undefined') ? this.options.forceAuthn : false;
  this.options.isPassive = (typeof this.options.isPassive !== 'undefined') ? this.options.isPassive : false;

  this.options.checkInResponseTo = (typeof this.options.checkInResponseTo !== 'undefined') ? this.options.checkInResponseTo : true;
  this.options.checkDestination = (typeof this.options.checkDestination !== 'undefined') ? this.options.checkDestination : true;

  this.options.signatureAlgorithm = options.signatureAlgorithm || 'rsa-sha256';
  this.options.digestAlgorithm = options.digestAlgorithm || 'sha256';

  if (typeof options.authnContext === 'undefined') {
    this.options.authnContext = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
  }

  if(!options.requestIdExpirationPeriodMs){
    this.options.requestIdExpirationPeriodMs = 28800000;  // 8 hours
  }

  if(!options.cacheProvider){
    this.options.cacheProvider = new InMemoryCacheProvider({
      keyExpirationPeriodMs: options.requestIdExpirationPeriodMs
    });
    this.cacheProvider = this.options.cacheProvider;
  }

  /*
    options.identityProviderUrl
    options.acsUrl
    options.destination
    options.attributeConsumingServiceIndex
    options.identifierFormat
    options.authnContext
    options.requestAuthnContext
    options.cert
    options.thumbprint
    options.RelayState
    options.decryptionKey
    options.autopadding
  */

  this._saml = saml;
};

var trimXml = function (xml) {
  return xml.replace(/\r\n/g, '')
      .replace(/\n/g,'')
      .replace(/>(\s*)</g, '><') //unindent
      .trim();
};

Samlp.prototype = {

  toSamlRequestUrl: function (samlMessage, idpUrl, options, callback) {
    var self = this;

    if (typeof options === 'function') {
      callback = options;
      options = {};
    }
    options = xtend(options || {}, this.options);

    if (!samlMessage || !samlMessage.SAMLRequest) {
      callback(new Error("SAMLRequest message is required"));
    }

    if (!idpUrl) {
      callback(new Error("IdP Consumer URL is required"));
    }

    async.waterfall([
      function(cb) {
        if (options.checkInResponseTo) {
          var request = new xmldom.DOMParser().parseFromString(samlMessage.SAMLRequest).documentElement;
          if (request.getAttribute('ID') && request.getAttribute('IssueInstant')) {
            return self.cacheProvider.save(request.getAttribute('ID'), request.getAttribute('IssueInstant'),
              function(err) {
                if (err) { return cb(err); }
                return cb();
            });
          }
        }
        return cb();
      },
      function(cb) {
        var buffer = new Buffer(samlMessage.SAMLRequest);
        if (options.deflate) {
          // add deflate hint
          samlMessage.SAMLEncoding = "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE";
          return zlib.deflateRaw(buffer, cb);
        }
        return cb(null, buffer);
      },
      function(buffer, cb) {
        samlMessage.SAMLRequest = buffer.toString('base64');
        return cb(null, samlMessage);
      },
      function(buffer, cb) {
        if (options.signRequest) {
          if (!options.signatureKey) {
            return cb(new Error('Unable to sign SAML Request because private key is not specified in options.signatureKey'));
          }

          options.signatureKey = stripHeaders(options.signatureKey);
          var sigAlg = algorithms[options.signatureAlgorithm] ? options.signatureAlgorithm : 'rsa-sha1';
          samlMessage.SigAlg = algorithms[sigAlg];

          var signer = crypto.createSign(sigAlg.toUpperCase());
          signer.update(toSignatureString(samlMessage));
          samlMessage.Signature = signer.sign(options.signatureKey, 'base64');
        }
        return cb(null);
      }
    ], function (err) {
      if (err) { return callback(err); }

      var requestUrl = url.parse(idpUrl, true);
      requestUrl.query = xtend(requestUrl.query, samlMessage);
      requestUrl.search = null;

      callback(null, url.format(requestUrl));
    });
  },

  generateAuthnRequest: function (req, options) {
    var request;
    options = xtend(options || {}, this.options);

    if (!options.issuer && !options.realm) {
      throw new Error('Unable to generate an AuthnRequest because a SAML issuer is not specifed in options.issuer or options.realm');
    }

    if (!options.acsUrl && options.path) {
      options.acsUrl = url.resolve((req.protocol || 'http').concat('://') +
          req.headers.host, options.path);
    }

    request = {
      'samlp:AuthnRequest': {
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '@ID': '_' + generateUniqueID(),
        '@Version': '2.0',
        '@IssueInstant': generateInstant(),
        '@ProtocolBinding': options.protocolBinding,
        '@Destination': options.destination || options.identityProviderUrl,
        'saml:Issuer' : {
          '@xmlns:saml' : 'urn:oasis:names:tc:SAML:2.0:assertion',
          '#text': options.issuer || options.realm
        }
      }
    };

    if (options.acsUrl) {
      request['samlp:AuthnRequest']['@AssertionConsumerServiceURL'] = options.acsUrl;
    }

    if (options.forceAuthn) {
      request['samlp:AuthnRequest']['@ForceAuthn'] = options.forceAuthn;
    }

    if (options.isPassive) {
      request['samlp:AuthnRequest']['@IsPassive'] = true;
    }

    if (options.attributeConsumingServiceIndex) {
      request['samlp:AuthnRequest']['@AttributeConsumingServiceIndex'] =
          options.attributeConsumingServiceIndex;
    }

    if (options.identifierFormat) {
      request['samlp:AuthnRequest']['samlp:NameIDPolicy'] = {
        '@Format': options.identifierFormat,
        '@AllowCreate': 'true'
      };
    }

    if (options.authnContext && options.requestAuthnContext) {
      request['samlp:AuthnRequest']['samlp:RequestedAuthnContext'] = {
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '@Comparison': 'exact',
        'saml:AuthnContextClassRef': {
          '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
          '#text': options.authnContext
        }
      };
    }

    return {
      SAMLRequest: trimXml(xmlbuilder.create(request).end()),
      RelayState: req.query && req.query.RelayState || req.body && req.body.RelayState || options.RelayState || ''
    };
  },

  generateLogoutRequest: function (req, options) {
    var request;
    options = xtend(options || {}, this.options);

    if (!options.issuer && !options.realm) {
      throw new Error('Unable to generate an LogoutRequest because a SAML issuer is not specifed in options.issuer or options.realm');
    }

    if (!options.acsUrl && options.path) {
      options.acsUrl = url.resolve((req.protocol || 'http').concat('://') +
          req.headers.host, options.path);
    }

    var request = {
      'samlp:LogoutRequest' : {
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        '@ID': generateUniqueID(),
        '@Version': '2.0',
        '@IssueInstant': generateInstant(),
        '@Destination': options.destination || options.idpLogoutUrl,
        'saml:Issuer' : {
          '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
          '#text': options.issuer || options.realm
        },
        'saml:NameID' : {
          '@Format': req.user.nameIDFormat,
          '#text': req.user.nameID
        }
      }
    };

    return {
      SAMLRequest: trimXml(xmlbuilder.create(request).end()),
      RelayState: req.query && req.query.RelayState || req.body && req.body.RelayState || options.RelayState || ''
    };
  },

  generateLogoutResponse: function (req, logoutRequest) {

    var request = {
      'samlp:LogoutResponse' : {
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        '@ID': generateUniqueID(),
        '@Version': '2.0',
        '@IssueInstant': generateInstant(),
        '@InResponseTo': logoutRequest.ID,
        'saml:Issuer' : {
          '#text': options.issuer || options.realm
        },
        'samlp:Status': {
          'samlp:StatusCode': {
            '@Value': 'urn:oasis:names:tc:SAML:2.0:status:Success'
          }
        }
      }
    };

    return xmlbuilder.create(request).end();
  },

  decodeResponse: function(req) {
    var decoded = new Buffer(req.body['SAMLResponse'], 'base64').toString();
    return decoded;
  },

  extractAssertion: function(samlpResponse, callback) {
    if (typeof samlpResponse === 'string') {
      samlpResponse = new xmldom.DOMParser().parseFromString(samlpResponse);
    }

    var done = function (err, assertion) {
      if (err) { return callback(err); }

      if (typeof assertion === 'string') {
        assertion = new xmldom.DOMParser().parseFromString(assertion);
      }

      // if saml assertion has a prefix but namespace is defined on parent, copy it to assertion
      if (assertion && assertion.prefix && !assertion.getAttributeNS(namespaces.assertion, assertion.prefix)) {
        assertion.setAttribute('xmlns:' + assertion.prefix, assertion.lookupNamespaceURI(assertion.prefix));
      }

      callback(null, assertion);
    };

    var token = samlpResponse.getElementsByTagNameNS(namespaces.assertion, 'Assertion')[0];
    if (!token) {
      // check for encrypted assertion
      var encryptedToken = samlpResponse.getElementsByTagNameNS(namespaces.assertion, 'EncryptedAssertion')[0];
      if (encryptedToken) {

        var encryptedData = encryptedToken.getElementsByTagNameNS('http://www.w3.org/2001/04/xmlenc#', 'EncryptedData')[0];
        if (!encryptedData) {
          return done(new Error('EncryptedData not found.'));
        }

        if (!this.options.decryptionKey) {
          return done(new Error('Assertion is encrypted. Please set options.decryptionKey with your decryption private key.'));
        }

        return xmlenc.decrypt(encryptedData.toString(), { key: this.options.decryptionKey, autopadding: this.options.autopadding }, done);
      }
    }

    done(null, token);
  },

  validateUrlSignature: function(requestUrl, options) {
    if (typeof requestUrl === 'string') {
      requestUrl = url.parse(requestUrl, true);
    }
    options = xtend(options || {}, this.options);

    var sigArg = 'rsa-sha1';
    Object.keys(algorithms).forEach(function(k) {
      if (algorithms[k] === requestUrl.query.SigAlg) {
        sigArg = k;
      }
    });

    var verifier = crypto.createVerify(sigArg.toUpperCase());
    var signedData = toSignatureString(requestUrl.query);

    verifier.update(toSignatureString(requestUrl.query));

    return verifier.verify(options.cert, requestUrl.query.Signature, 'base64');
  },

  validateSamlResponse: function (samlResponse, options, callback) {
    var self = this;

    if (typeof options === 'function') {
      callback = options;
      options = {};
    }
    options = xtend(self.options, options);

    if (typeof samlResponse === 'string') {
      samlResponse = new xmldom.DOMParser().parseFromString(samlResponse);
    }

    async.waterfall([
      function(cb) {
        if(options.checkInResponseTo) {
          var inResponseTo = xpath.select("/*[local-name()='Response' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']/@InResponseTo", samlResponse);
          if(inResponseTo){
            inResponseTo = inResponseTo.length ? inResponseTo[0].nodeValue : null;
          }

          if (inResponseTo) {
            self.cacheProvider.get(inResponseTo, function(err, issueInstant) {
              if (err) { return cb(err); }
              if (!issueInstant) {
                return cb(new Error('SAML Response contains InResponseTo [' + inResponseTo + '] ID that was not issued in a previous Request'));
              }
              return cb();
            })
          }
        }
        return cb();
      },
      function(cb) {
        if (options.checkDestination) {
          var destination = xpath.select("/*[local-name()='Response' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']/@Destination", samlResponse);
          if (destination) {
            if (!options.acsUrl) {
              return cb(new Error('Unable to validate SAML Response Destination.  Please set options.acsUrl with the Assertion Consumer Service URL of the Service Provider'));
            }

            destination = destination.length ? destination[0].nodeValue : null;
            if (destination && (destination !== options.acsUrl)) {
              return cb(new Error('SAML Response Destination [' + destination + '] must match Assertion Consumer Service URL [' + options.acsUrl + ']'));
            }
          }
        }
        return cb();
      },
      function(cb) {
        return self.extractAssertion(samlResponse, cb);
      }
    ], function(err, assertion) {
      if (err) { return callback(err); }
      if (!assertion) {
        return callback(new Error('SAML Response does not contain an <Assertion> element'));
      }

      var samlResponseSignaturePath = "//*[local-name(.)='Response' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']" +
        "/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']";
      var isResponseSigned = xpath.select(samlResponseSignaturePath, samlResponse).length === 1;
      var samlAssertionSignaturePath = "//*[local-name(.)='Assertion']/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']";
      var isAssertionSigned =  xpath.select(samlAssertionSignaturePath, assertion).length === 1;

      if (!isResponseSigned && !isAssertionSigned) {
        return callback(new Error('SAML Response must contain a signature for either the <Response> or <Assertion> elements'));
      }

      if (isResponseSigned) {
        if (!options.cert && !options.thumbprint) {
          return callback(new Error('You must specify either a base64 encoded certificate (cert) or the thumbprint of the certificate to validate the SAML Response signature'));
        }

        self._saml.validateSignature(samlResponse, {
          cert: options.cert,
          thumbprint: options.thumbprint,
          signaturePath: samlResponseSignaturePath
        },
        function (err) {
          if (err) { return callback(err); }

          if (!isAssertionSigned) {
            return self._saml.parseAssertion(assertion, callback);
          }

          return self._saml.validateSamlAssertion(assertion, callback);
        });
      }
      else if (isAssertionSigned) {
        return self._saml.validateSamlAssertion(assertion, callback);
      }
    });
  }
};

function generateUniqueID() {
  var chars = "abcdef0123456789";
  var uniqueID = "";
  for (var i = 0; i < 20; i++) {
    uniqueID += chars.substr(Math.floor((Math.random()*15)), 1);
  }
  return uniqueID;
}

function generateInstant() {
  var date = new Date();
  return date.getUTCFullYear() + '-' + ('0' + (date.getUTCMonth()+1)).slice(-2) + '-' + ('0' + date.getUTCDate()).slice(-2) + 'T' + ('0' + date.getUTCHours()).slice(-2) + ":" + ('0' + date.getUTCMinutes()).slice(-2) + ":" + ('0' + date.getUTCSeconds()).slice(-2) + "Z";
}

function stripHeaders(cert) {
  var pem = /-----BEGIN (\w*)-----([^-]*)-----END (\w*)-----/g.exec(cert.toString());
  if (pem && pem.length > 0) {
    cert = pem[2].replace(/[\n|\r\n]/g, '');
  }
  return cert;
}

function toSignatureString(message) {
  // signature must only be SAMLRequest=value&RelayState=value&SigAlg=value (ordered)
  var params = [];
  if (message.SAMLRequest) {
    params.push('SAMLRequest=' + encodeURIComponent(message.SAMLRequest));
  } else if (query.SAMLResponse) {
    params.push('SAMLResponse=' + encodeURIComponent(message.SAMLResponse));
  } else {
    throw new Error("SAMLRequest or SAMLResponse parameter is required")
  }

  if (message.RelayState) {
    params.push('RelayState=' + encodeURIComponent(message.RelayState));
  }
  params.push('SigAlg=' + encodeURIComponent(message.SigAlg));
  return params.join('&');
}