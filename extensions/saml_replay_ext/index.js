// Import the f5-nodejs module.
var f5 = require('f5-nodejs');

// Import the XML-Crypto Libraries
var zlib = require('zlib');
var crypto = require('crypto');
var xml2js = require('xml2js');
var xmlCrypto = require('xml-crypto');
var xmlbuilder = require('xmlbuilder');
var xmlenc = require('xml-encryption');
var select = require('xml-crypto').xpath;
var dom = require('xmldom').DOMParser;
var SignedXml = require('xml-crypto').SignedXml;
var FileKeyInfo = require('xml-crypto').FileKeyInfo;
var fs = require('fs');
var querystring = require('querystring');
var InMemoryCacheProvider = require('./inmemory-cache-provider.js').CacheProvider;
var Q = require('q');

//  Public Key of Issuer configured here  
var signaturePubKey = "othercert.pem";

function initialize(options) {
  if (!options) {
    options = {};
  }

  if (!options.path) {
    options.path = '/saml/consume';
  }
  
  if (!options.entryPoint) {
      options.entryPoint = 'https://192.168.2.60/'
  }

  if (!options.host) {
    options.host = 'localhost';
  }
  
  if (!options.issuerURL) {
      options.issuerURL = 'https://192.168.2.60/'
  }

  if (!options.issuer) {
    options.issuer = 'f5-saml-replay';
  }

  if (options.identifierFormat === undefined) {
    options.identifierFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
  }

  if (options.authnContext === undefined) {
    options.authnContext = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
  }

  if (!options.acceptedClockSkewMs) {
    // default to no skew
    options.acceptedClockSkewMs = 0;
  }

  if(!options.validateInResponseTo){
    options.validateInResponseTo = false;
  }

  if(!options.requestIdExpirationPeriodMs){
    options.requestIdExpirationPeriodMs = 28800000;  // 8 hours
  }

  if(!options.cacheProvider){
      options.cacheProvider = new InMemoryCacheProvider(
          {keyExpirationPeriodMs: options.requestIdExpirationPeriodMs });
  }

  if (!options.logoutUrl) {
    // Default to Entry Point
    options.logoutUrl = options.entryPoint || '';
  }

  // sha1, sha256, or sha512
  if (!options.signatureAlgorithm) {
    options.signatureAlgorithm = 'sha1';
  }

  return options;
}

function generateUniqueID() {
  return crypto.randomBytes(10).toString('hex');
}

function generateInstant() {
  return new Date().toISOString();
}

function signRequest(samlMessage) {
  var signer;
  var samlMessageToSign = {};
  var options = initialize(options);
  
  switch(options.signatureAlgorithm) {
    case 'sha256':
      samlMessage.SigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
      signer = crypto.createSign('RSA-SHA256');
      break;
    case 'sha512':
      samlMessage.SigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
      signer = crypto.createSign('RSA-SHA512');
      break;
    default:
      samlMessage.SigAlg = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
      signer = crypto.createSign('RSA-SHA1');
      break;
  }
  if (samlMessage.SAMLRequest) {
    samlMessageToSign.SAMLRequest = samlMessage.SAMLRequest;
  }
  if (samlMessage.SAMLResponse) {
    samlMessageToSign.SAMLResponse = samlMessage.SAMLResponse;
  }
  if (samlMessage.RelayState) {
    samlMessageToSign.RelayState = samlMessage.RelayState;
  }
  if (samlMessage.SigAlg) {
    samlMessageToSign.SigAlg = samlMessage.SigAlg;
  }
  signer.update(querystring.stringify(samlMessageToSign));
  samlMessage.Signature = signer.sign(options.privateCert, 'base64');
}

function requestToURL(request) {
    var self = this;
    var options = initialize(options);
    var deflated = new Buffer(zlib.deflateRawSync(request), 'utf8');

    var base64 = deflated.toString('base64');
    var urlEnc = encodeURIComponent(base64.toString());

    return urlEnc;
}

function getAdditionalParams(req, operation) {
  var additionalParams = {};

  var RelayState = req.query && req.query.RelayState || req.body && req.body.RelayState;
  if (RelayState) {
    additionalParams.RelayState = RelayState;
  }

  var optionsAdditionalParams = options.additionalParams || {};
  Object.keys(optionsAdditionalParams).forEach(function(k) {
    additionalParams[k] = optionsAdditionalParams[k];
  });

  var optionsAdditionalParamsForThisOperation = {};
  if (operation == "authorize") {
    optionsAdditionalParamsForThisOperation = options.additionalAuthorizeParams || {};
  }
  if (operation == "logout") {
    optionsAdditionalParamsForThisOperation = options.additionalLogoutParams || {};
  }

  Object.keys(optionsAdditionalParamsForThisOperation).forEach(function(k) {
    additionalParams[k] = optionsAdditionalParamsForThisOperation[k];
  });

  return additionalParams;
}

// Create a new rpc server for listening to TCL iRule calls.
var ilx = new f5.ILXServer();

ilx.addMethod('saml-request', function(req, res) {
    var method = req.params()[0];
    var landingURI = req.params()[1];
    var sign = req.params()[2]
    
    var isPassive = false;
    
    var self = this;
    var options = initialize(options);
    var id = "_" + generateUniqueID();
    var instant = generateInstant();
    var forceAuthn = options.forceAuthn || false;
    
    var request = {
      'samlp:AuthnRequest': {
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '@ID': id,
        '@Version': '2.0',
        '@IssueInstant': instant,
        '@ProtocolBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        '@AssertionConsumerServiceURL': 'https://' + landingURI,
        '@Destination': options.entryPoint,
        'saml:Issuer' : {
          '@xmlns:saml' : 'urn:oasis:names:tc:SAML:2.0:assertion',
          '#text': options.issuer
        }
      }
    };

    if (isPassive)
      request['samlp:AuthnRequest']['@IsPassive'] = true;

    if (forceAuthn) {
      request['samlp:AuthnRequest']['@ForceAuthn'] = true;
    }

    if (options.identifierFormat) {
      request['samlp:AuthnRequest']['samlp:NameIDPolicy'] = {
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '@Format': options.identifierFormat,
        '@AllowCreate': 'true'
      };
    }

    if (!options.disableRequestedAuthnContext) {
      request['samlp:AuthnRequest']['samlp:RequestedAuthnContext'] = {
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '@Comparison': 'exact',
        'saml:AuthnContextClassRef': {
          '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
          '#text': options.authnContext
        }
      };
    }

    if (options.attributeConsumingServiceIndex) {
      request['samlp:AuthnRequest']['@AttributeConsumingServiceIndex'] = options.attributeConsumingServiceIndex;
    }

    if (options.providerName) {
      request['samlp:AuthnRequest']['@ProviderName'] = options.providerName;
    }

    //callback(null, xmlbuilder.create(request).end());
    //console.log(xmlbuilder.create(request).end());
    //return xmlbuilder.create(request).end();
    var authrequest;
    //console.log("sign: " + sign);
    if (sign == "true") {
        authrequest = signRequest(xmlbuilder.create(request).end());
    } else {
        authrequest = xmlbuilder.create(request).end();        
    }

    var encodedAuthNRequest = requestToURL(authrequest);
    
    //console.log(encodedAuthNRequest);
    
    var redirectAuth = options.issuerURL + '?SAMLRequest=' + encodedAuthNRequest 
    
    res.reply(['OK', redirectAuth]);
});

ilx.addMethod('saml-validate', function(req, res) {
    var parse = req.params()[1];

    var URLDecodedAssertion = decodeURIComponent(req.params()[0]);
    var B64Assertion = new Buffer(URLDecodedAssertion, 'base64');
    var rawAssertion = zlib.inflateRawSync(B64Assertion).toString('utf8');
    var doc = new dom().parseFromString(rawAssertion);
    var signature = select(doc, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
    var sig = new SignedXml();
    //IF keep this method, move outside of function, sync/async
    
    var isvalid;
    if (typeof signature !== "undefined") {
        sig.keyInfoProvider = new FileKeyInfo(signaturePubKey);
        sig.loadSignature(signature);
    
        var result = sig.checkSignature(rawAssertion);
        if (!result) {
            isvalid = sig.validationErrors;
        } else {
            isvalid = result;
        }
    } else {
        isvalid = "Not Signed.";
    }
    
    var parsed;
    if (parse == 'true') {
        //var parser = new Saml2js(rawAssertion);
        //parsed = parser.asObject();
        //console.log(parsed);
        parsed = "parse=true;notimplemented";
    } else {
        parsed = "parse=false;notimplemented";
    }

   res.reply([isvalid, parsed]);
});

// Start listening for ILX::call and ILX::notify events.
ilx.listen();
