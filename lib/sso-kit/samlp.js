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


var Algorithms = {
  'rsa-sha256': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
  'rsa-sha1': 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
};

var Namespaces = {
  protocol: 'urn:oasis:names:tc:SAML:2.0:protocol',
  assertion: 'urn:oasis:names:tc:SAML:2.0:assertion',
  xmlenc: 'http://www.w3.org/2001/04/xmlenc#',
  dsig: 'http://www.w3.org/2000/09/xmldsig#'
}

var makeSelector = function(namespace) {
  var result = "/*[(local-name()='";
  var args = Array.prototype.slice.call(arguments, 1);
  result += args.join("' or local-name()='");
  result += "') and namespace-uri(.)='" + namespace + "']";
  return result;
}

var Selector = {
  logoutRequest: makeSelector(Namespaces.protocol, 'LogoutRequest'),
  logoutResponse: makeSelector(Namespaces.protocol, 'LogoutResponse'),
  authnResponse: makeSelector(Namespaces.protocol, 'Response'),
  response: makeSelector(Namespaces.protocol, 'Response', 'LogoutResponse'),
  dsig: makeSelector(Namespaces.dsig, 'Signature'),
  issuer: makeSelector(Namespaces.assertion, 'Issuer'),
  assertion: makeSelector(Namespaces.assertion, 'Assertion'),
  encryptedAssertion: makeSelector(Namespaces.assertion, 'EncryptedAssertion'),
  encryptedData: makeSelector(Namespaces.xmlenc, 'EncryptedData'),
  nameID: makeSelector(Namespaces.assertion, 'NameID'),
  sessionIndex: makeSelector(Namespaces.protocol, 'SessionIndex'),
  statusCode: makeSelector(Namespaces.protocol, 'Status') + makeSelector(Namespaces.protocol, 'StatusCode')
}


var Samlp = module.exports = function Samlp (options, saml) {
  this.options = xtend({}, options);

  this.options.protocolBinding = options.protocolBinding || 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';

  this.options.deflate = isBoolean(options.deflate) ? options.deflate : true;
  this.options.forceAuthn = isBoolean(options.forceAuthn) ? options.forceAuthn : false;
  this.options.isPassive = isBoolean(options.isPassive) ? options.isPassive : false;

  this.options.checkInResponseTo = isBoolean(options.checkInResponseTo) ? options.checkInResponseTo : true;
  this.options.checkIssuer = isBoolean(options.checkIssuer) ? options.checkIssuer : true;
  this.options.checkDestination = isBoolean(options.checkDestination) ? options.checkDestination : true;
  this.options.checkRequestSignature = isBoolean(options.checkRequestSignature) ? options.checkRequestSignature : true;

  this.options.signRequest = isBoolean(options.signRequest) ? options.signRequest : false;
  if (this.options.signRequest && !options.signatureKey) {
    throw new Error('You must specify a base64 private key in options.signatureKey to sign SAML requests');
  }
  this.options.signatureAlgorithm = options.signatureAlgorithm || 'rsa-sha256';
  this.options.digestAlgorithm = options.digestAlgorithm || 'sha256';

  this.options.requestAuthnContext = isBoolean(options.requestAuthnContext) ? options.requestAuthnContext : false;
  if (typeof options.authnContext === 'undefined') {
    this.options.authnContext = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
  }

  this.options.requireResponseSignature = isBoolean(options.requireResponseSignature) ? options.requireResponseSignature : true;

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
    options.audience
    options.destination
    options.acsUrl
    options.path

    options.idpSsoUrl
    options.attributeConsumingServiceIndex
    options.identifierFormat
    options.authnContext

    options.issuer

    options.cert
    options.thumbprint
    options.relayState
    options.decryptionKey
    options.autopadding
  */

  this._saml = saml;
};

Samlp.prototype = {

  isSamlRequest: function(req) {
    return ((req.method === 'POST' && req.body && req.body.SAMLRequest) ||
    req.metjod === 'GET' && req.query.SAMLRequest);
  },

  isSamlResponse: function(req) {
    return ((req.method === 'POST' && req.body && req.body.SAMLResponse) ||
    req.method === 'GET' && req.query.SAMLResponse);
  },

  decodeResponse: function(req) {
    var decoded = new Buffer(req.body['SAMLResponse'], 'base64').toString();
    return decoded;
  },

  getSamlRequestUrl: function (samlMessage, idpServiceUrl, options, callback) {
    var self = this;

    if (typeof options === 'function') {
      callback = options;
      options = {};
    }
    options = xtend(options || {}, this.options);

    if (!samlMessage || !samlMessage.SAMLRequest) {
      callback(new Error("SAMLRequest message is required"));
    }

    if (!idpServiceUrl) {
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
          var sigAlg = Algorithms[options.signatureAlgorithm] ? options.signatureAlgorithm : 'rsa-sha1';
          samlMessage.SigAlg = Algorithms[sigAlg];

          var signer = crypto.createSign(sigAlg.toUpperCase());
          signer.update(toSignatureString(samlMessage));
          samlMessage.Signature = signer.sign(options.signatureKey, 'base64');
        }
        return cb(null);
      }
    ], function (err) {
      if (err) { return callback(err); }

      var requestUrl = url.parse(idpServiceUrl, true);
      requestUrl.query = xtend(requestUrl.query, samlMessage);
      requestUrl.search = null;

      callback(null, url.format(requestUrl));
    });
  },

  generateAuthnRequest: function (req, options) {
    var request;
    options = xtend(options || {}, this.options);

    if (!options.audience) {
      throw new Error('Unable to generate an AuthnRequest because a SAML Issuer URI is not specifed in options.audience');
    }

    request = {
      'samlp:AuthnRequest': {
        '@xmlns:samlp': Namespaces.protocol,
        '@ID': '_' + generateUniqueID(),
        '@Version': '2.0',
        '@IssueInstant': generateInstant(),
        '@ProtocolBinding': options.protocolBinding,
        '@Destination': options.destination || options.idpSsoUrl,
        'saml:Issuer' : {
          '@xmlns:saml' : Namespaces.assertion,
          '#text': options.audience
        }
      }
    };

    if (!options.acsUrl && options.path) {
      options.acsUrl = url.resolve((req.protocol || 'http').concat('://') +
          req.headers.host, options.path);
    }

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
        '@xmlns:samlp': Namespaces.protocol,
        '@Comparison': 'exact',
        'saml:AuthnContextClassRef': {
          '@xmlns:saml': Namespaces.assertion,
          '#text': options.authnContext
        }
      };
    }

    return {
      SAMLRequest: trimXml(xmlbuilder.create(request).end()),
      RelayState: req.query && req.query.RelayState || req.body && req.body.RelayState || options.relayState || ''
    };
  },

  generateLogoutRequest: function (req, options) {
    var request;
    options = xtend(options || {}, this.options);

    if (!options.audience) {
      throw new Error('Unable to generate an LogoutRequest because a SAML Issuer URI is not specifed in options.audience');
    }

    if (!options.acsUrl && options.path) {
      options.acsUrl = url.resolve((req.protocol || 'http').concat('://') +
          req.headers.host, options.path);
    }

    var request = {
      'samlp:LogoutRequest' : {
        '@xmlns:samlp': Namespaces.protocol,
        '@xmlns:saml': Namespaces.assertion,
        '@ID': generateUniqueID(),
        '@Version': '2.0',
        '@IssueInstant': generateInstant(),
        '@Destination': options.destination || options.idpSloUrl,
        'saml:Issuer' : {
          '@xmlns:saml': Namespaces.assertion,
          '#text': options.audience
        },
        'saml:NameID' : {
          '@Format': req.user.nameIDFormat,
          '#text': req.user.nameID
        }
      }
    };

    return {
      SAMLRequest: trimXml(xmlbuilder.create(request).end()),
      RelayState: req.query && req.query.RelayState || req.body && req.body.RelayState || options.relayState || ''
    };
  },

  generateLogoutResponse: function (req, logoutRequest) {

    var request = {
      'samlp:LogoutResponse' : {
        '@xmlns:samlp': Namespaces.protocol,
        '@xmlns:saml': Namespaces.assertion,
        '@ID': generateUniqueID(),
        '@Version': '2.0',
        '@IssueInstant': generateInstant(),
        '@InResponseTo': logoutRequest.ID,
        'saml:Issuer' : {
          '#text': options.audience
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

  extractAssertion: function(samlResponse, options, callback) {
    if (typeof samlResponse === 'string') {
      samlResponse = new xmldom.DOMParser().parseFromString(samlResponse);
    }

    var done = function (err, assertion, encrypted) {
      if (err) { return callback(err); }

      if (typeof assertion === 'string') {
        assertion = new xmldom.DOMParser().parseFromString(assertion);
      }

      // if saml assertion has a prefix but namespace is defined on parent, copy it to assertion
      if (assertion && assertion.prefix && !assertion.getAttributeNS(Namespaces.assertion, assertion.prefix)) {
        assertion.setAttribute('xmlns:' + assertion.prefix, assertion.lookupNamespaceURI(assertion.prefix));
      }
      debugger;
      callback(null, assertion, encrypted);
    };

    var assertion = xpath.select(Selector.authnResponse + Selector.assertion, samlResponse);
    var encryptedData = xpath.select(Selector.authnResponse + Selector.encryptedAssertion + Selector.encryptedData, samlResponse);

    if ((assertion.length + encryptedData.length) > 1) {
      return done(new Error('Unable to parse response because it contains too many <Assertion> or <EncryptedAssertion> elements.')); 
    }

    if ((assertion.length + encryptedData.length) !== 1) {
      return done(new Error('Unable to parse response because it does not contain a valid <Assertion> or <EncryptedAssertion> element.')); 
    }

    if (encryptedData.length === 1) {
      if (!this.options.decryptionKey) {
        return done(new Error('Assertion is encrypted. Please set options.decryptionKey with your decryption private key.'));
      }
      return xmlenc.decrypt(encryptedData[0].toString(), {
          key: this.options.decryptionKey,
          autopadding: this.options.autopadding
        }, function(err, assertion) {
          if (err) { return callback(err); }
          done(null, assertion, true)
        });
    }
    return done(null, assertion[0], false);
  },

  parseSamlRequest: function(samlRequest, options, callback) {

    var getAttributeValue = function(selector, attributeName) {
      if (arguments.length === 1) {
        attributeName = selector;
        selector = Selector.logoutRequest;
      }
      var attribute = xpath.select(selector + '/@' + attributeName, samlRequest);
      return (attribute && attribute.length === 1) ? attribute[0].nodeValue : null;
    }

    var getElementText = function(selector) {
      var element = xpath.select(selector, samlRequest);
      return (element && element.length === 1) ? element[0].textContent : null;
    }

    if (typeof samlRequest === 'string') {
      samlRequest = new xmldom.DOMParser().parseFromString(samlRequest);
    }

    samlRequest = xpath.select(Selector.logoutRequest, samlRequest);
    if (samlRequest.length !== 1) {
      return callback(new Error('SAMLRequest message must contain <LogoutRequest> element as document root'));
    }
    samlRequest = samlRequest[0];

    return callback(null, {
      message: samlRequest,
      messageType: samlRequest.documentElement.localName,
      id: getAttributeValue('ID'),
      version: getAttributeValue('Version'),
      issueInstant: getAttributeValue('IssueInstant'),
      consent: getAttributeValue('Consent'),
      destination: getAttributeValue('Destination'),
      issuer: getElementText(Selector.logoutRequest + Selector.issuer),
      nameID: getElementText(Selector.logoutRequest + Selector.nameID),
      nameIDFormat: getAttributeValue(Selector.logoutRequest + Selector.nameID, 'Format'),
      sessionIndex: getElementText(Selector.logoutRequest + Selector.sessionIndex)
    });
  },

  parseSamlResponse: function(samlResponse, options, callback) {
    var self = this;

    var samlResponse = xpath.select(Selector.response, samlResponse);
    if (samlResponse.length !== 1) {
      return callback(new Error("SAML Response message does not contain a valid root element"));
    }
    samlResponse = samlResponse[0];

    var getAttributeValue = function(selector, attributeName) {
      if (arguments.length === 1) {
        attributeName = selector;
        selector = Selector.response;
      }
      var attribute = xpath.select(selector + '/@' + attributeName, samlResponse);
      return (attribute && attribute.length === 1) ? attribute[0].nodeValue : null;
    }

    var getElementText = function(selector) {
      var element = xpath.select(selector, samlResponse);
      return (element && element.length === 1) ? element[0].textContent : null;
    }

    var result = {
      message: samlResponse,
      messageType: samlResponse.localName,
      id: getAttributeValue('ID'),
      inResponseTo: getAttributeValue('InResponseTo'),
      version: getAttributeValue('Version'),
      issueInstant: getAttributeValue('IssueInstant'),
      destination: getAttributeValue('Destination'),
      issuer: getElementText(Selector.response + Selector.issuer),
      statusCode: getAttributeValue(Selector.response + Selector.statusCode, 'Value')
    };

    if (result.messageType === 'Response') {
      return self.extractAssertion(samlResponse, options, function(err, assertion, encrypted) {
        var signSelector = (!encrypted ? Selector.authnResponse : '') + Selector.assertion + Selector.dsig;
        if (err) { return callback(err); }
        result.assertion = assertion;
        result.assertionEncrypted = encrypted;
        result.assertionSigned = xpath.select(signSelector, result.assertion).length === 1;
        return callback(null, result);
      });
    }
    return callback(null, result);
  },

  validateUrlSignature: function(requestUrl, options, callback) {

    if (typeof requestUrl === 'string') {
      requestUrl = url.parse(requestUrl, true);
    }
    options = xtend(options || {}, this.options);

    if (toString.call(requestUrl.query.SAMLRequest) !== '[object String]') {
      throw new Error("SAMLRequest query parameter is required to validate signature");
    }

    if (toString.call(requestUrl.query.Signature) !== '[object String]') {
      throw new Error("Signature query parameter is required to validate signature");
    }

    if (toString.call(requestUrl.query.SigAlg) !== '[object String]') {
      throw new Error("SigAlg query parameter is required to validate signature");
    }

    var sigArg = 'rsa-sha1';
    Object.keys(Algorithms).forEach(function(k) {
      if (Algorithms[k] === requestUrl.query.SigAlg) {
        sigArg = k;
      }
    });

    var verifier = crypto.createVerify(sigArg.toUpperCase());
    var signedData = toSignatureString(requestUrl.query);

    verifier.update(toSignatureString(requestUrl.query));

    return verifier.verify(options.cert, requestUrl.query.Signature, 'base64');
  },

  validateSamlRequest: function(samlRequest, options, callback) {
    var self = this;

    if (typeof options === 'function') {
      callback = options;
      options = {};
    }
    options = xtend(self.options, options);

    if (typeof samlRequest === 'string') {
      samlRequest = new xmldom.DOMParser().parseFromString(samlRequest);
    }

    return async.waterfall([
      function(cb) {
        return self.parseSamlRequest(samlRequest, cb);
      },
      function(result, cb) {
        if (options.checkRequestSignature) {
          var signatures = xpath.select(Selector.dsig, result.message);
          if (signatures.length !== 1) {
            return cb(new Error('SAMLRequest message must contain a single <Signature> element'));
          }

          return self._saml.validateSignature(result.message, {
            cert: options.cert,
            thumbprint: options.thumbprint,
            signaturePath: Selector.dsig
          }, function(err) {
            if (err) { return cb(err); }
            return cb(null, result);
          });
        }
        return cb(null, result);
      },
      function(result, cb) {
        if (options.checkDestination) {
          if (!options.logoutUrl) {
            return cb(new Error('Unable to validate SAML LogoutRequest Destination.  Please set options.logoutUrl with the Logout Consumer Service URL of the Identity Provider'));
          }
          if (result.destination !== options.logoutUrl) {
            return cb(new Error('SAML LogoutRequest Destination [' + result.destination + '] must match Logout Service URL [' + options.logoutUrl + ']'));
          }
        }
        return cb(null, result);
      },
      function(result, cb) {
        if (options.checkIssuer) {
          if (!options.issuer) {
            return cb(new Error('Unable to validate SAML LogoutRequest Issuer.  Please set options.issuer with the Issuer URI of the Identity Provider.'));
          }
          if (!result.issuer) {
            return cb(new Error('SAML LogoutRequest does not have a valid <Issuer> element'));
          }
          if (result.issuer !== options.issuer) {
            return cb(new Error('SAML LogoutRequest Issuer [' + result.issuer + '] must match [' + options.issuer + ']'));
          }
        }
        return cb(null, result);
      }          
    ], function(err, result) {
      if (err) { return callback(err); }
      return callback(null, result);
    })
  },

  validateRequest: function(req, options, callback) {
    var samlRequest;
    options = xtend({}, options);

    if (req.method === "GET" && req.query.SAMLRequest && options.checkRequestSignature) {
      try {
        if (!validateUrlSignature(req.url, options, callback)) {
          return callback(new Error("SAMLRequest signature is not valid!"));
        }
        samlRequest = req.query.SAMLRequest;
        options.checkRequestSignature = false;
      } catch (err) {
        return callback(err);
      }
    } else if (req.method === "POST" && req.body && req.body.SAMLRequest) {
      samlRequest = decodeResponse(req.body.SAMLRequest);
    }

    if (!samlRequest) {
      return callback(new Error("Request does not a contain a SAMLRequest message"));
    }

    return validateSamlRequest(samlRequest, options, callback);
  },

  validateSamlResponse: function(samlResponse, options, callback) {
    var self = this;

    if (typeof options === 'function') {
      callback = options;
      options = {};
    }
    options = xtend(self.options, options);

    if (typeof samlResponse === 'string') {
      samlResponse = new xmldom.DOMParser().parseFromString(samlResponse);
    }

    return async.waterfall([
      function(cb) {
        return self.parseSamlResponse(samlResponse, options, cb);
      },
      function(result, cb) {

        var signaturePath = Selector.response + Selector.dsig;
        result.responseSigned = xpath.select(signaturePath, result.message).length === 1;

        if (result.responseSigned) {
          if (!options.cert && !options.thumbprint) {
            return cb(new Error('You must specify either a base64 encoded certificate (cert) or the thumbprint of the certificate to validate the SAML Response message signature'));
          }
          return self._saml.validateSignature(result.message, {
            cert: options.cert,
            thumbprint: options.thumbprint,
            signaturePath: signaturePath
          }, function(err) {
            if (err) { return cb(err); }
            return cb(null, result);
          });
        }
        if (options.requireResponseSignature) {
          return cb(new Error("SAML Response message must contain a signature!"));
        }
        return cb(null, result);
      },
      function(result, cb) {
        if(options.checkInResponseTo) {
          if (result.inResponseTo) {
            self.cacheProvider.get(result.inResponseTo, function(err, issueInstant) {
              if (err) { return cb(err); }
              if (!issueInstant) {
                return cb(new Error('SAML Response contains InResponseTo [' + result.inResponseTo + '] ID that was not issued in a previous request'));
              }
              return cb(null, result);
            })
          }
        }
        return cb(null, result);
      },
      function(result, cb) {
        if (options.checkDestination) {
          if (result.messageType === 'LogoutResponse') {
            if (!options.logoutUrl) {
              return cb(new Error('Unable to validate SAML LogoutResponse Destination.  Please set options.logoutUrl with the Logout Service URL of the application'));
            }
            if (result.destination !== options.logoutUrl) {
              return cb(new Error('SAML LogoutResponse Destination [' + result.destination + '] must match Logout Service URL [' + options.logoutUrl + ']'));
            }
          } else if (result.messageType === 'Response') {
            if (!options.acsUrl) {
              return cb(new Error('Unable to validate SAML Response Destination.  Please set options.acsUrl with the Assertion Consumer Service URL of the application'));
            }
            if (result.destination !== options.acsUrl) {
              return cb(new Error('SAML Response Destination [' + result.destination + '] must match Assertion Consumer Service URL [' + options.acsUrl + ']'));
            }
          }
        }
        return cb(null, result);
      },
      function(result, cb) {
        if (options.checkIssuer) {
          if (!options.issuer) {
            return cb(new Error('Unable to validate SAML Response Issuer.  Please set options.issuer with the Issuer URI of the Identity Provider.'));
          }
          if (!result.issuer) {
            return cb(new Error('SAML Response does not have a valid <Issuer> element'));
          }
          if (result.issuer !== options.issuer) {
            return cb(new Error('SAML Response Issuer [' + result.issuer + '] must match [' + options.issuer + ']'));
          }
        }
        return cb(null, result);
      },
      function(result, cb) {
        if (!result.statusCode) {
          return cb(new Error('SAML Response message must contain a valid <StatusCode> element'));
        }
        if (result.statusCode !== 'urn:oasis:names:tc:SAML:2.0:status:Success') {
          return cb(new Error('SAML Response has invalid status ' + statusCode[0].nodeValue));
        }
        return cb(null, result);
      }
    ], function(err, result) {
      if (err) { return callback(err); }

      if (result.messageType === 'Response') {
        if (!result.responseSigned && !result.assertionSigned) {
          return callback(new Error('SAML Response message must contain a signature for either the <Response> or <Assertion> elements'));
        }
        var parseFunc = result.assertionSigned ? 'validateSamlAssertion' : 'parseAssertion';
        return self._saml[parseFunc](result.assertion, function(err, profile) {
          if (err) { return callback(err); }
          return callback(null, profile, result);
        });
      }
      return callback(null, result);
    });
  }
};


/**
 * Helpers
 */

function isBoolean(obj) {
  return obj === true || obj === false || toString.call(obj) === '[object Boolean]';
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

var trimXml = function (xml) {
  return xml.replace(/\r\n/g, '')
      .replace(/\n/g,'')
      .replace(/>(\s*)</g, '><') //unindent
      .trim();
};

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

module.exports = Samlp;