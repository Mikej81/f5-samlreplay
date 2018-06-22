// Import the f5-nodejs module.
var f5 = require('f5-nodejs')

// Import the XML-Crypto Libraries
var zlib = require('zlib')
var crypto = require('crypto')
var xmldom = require('xmldom')
//  var xmlCrypto = require('xml-crypto')
var xmlbuilder = require('xmlbuilder')
//  var xmlenc = require('xml-encryption')
var xpath = require('xpath')
var select = require('xml-crypto').xpath
var dom = require('xmldom').DOMParser
var SignedXml = require('xml-crypto').SignedXml
var FileKeyInfo = require('xml-crypto').FileKeyInfo
//  var fs = require('fs')
var _ = require('lodash')
var querystring = require('querystring')
var InMemoryCacheProvider = require('./inmemory-cache-provider.js').CacheProvider

//  Public Key of Issuer configured here
var signaturePubKey = 'othercert.pem'

function initialize (options) {
  if (!options) {
    options = {}
  }
  if (!options.path) {
    options.path = '/saml/consume'
  }
  if (!options.entryPoint) {
    options.entryPoint = 'https://192.168.2.60/'
  }
  if (!options.host) {
    options.host = 'localhost'
  }
  if (!options.issuerURL) {
    options.issuerURL = 'https://192.168.2.60/'
  }
  if (!options.issuer) {
    options.issuer = 'f5-saml-replay'
  }
  if (options.identifierFormat === undefined) {
    options.identifierFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
  }
  if (options.authnContext === undefined) {
    options.authnContext = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
  }
  if (!options.acceptedClockSkewMs) {
    // default to no skew
    options.acceptedClockSkewMs = 0
  }
  if (!options.validateInResponseTo) {
    options.validateInResponseTo = false
  }
  if (!options.requestIdExpirationPeriodMs) {
    options.requestIdExpirationPeriodMs = 28800000 // 8 hours
  }
  if (!options.cacheProvider) {
    options.cacheProvider = new InMemoryCacheProvider({keyExpirationPeriodMs: options.requestIdExpirationPeriodMs})
  }
  if (!options.logoutUrl) {
    // Default to Entry Point
    options.logoutUrl = options.entryPoint || ''
  }
  // sha1, sha256, or sha512
  if (!options.signatureAlgorithm) {
    options.signatureAlgorithm = 'sha1'
  }
  return options
}

var options = initialize(options)

function generateUniqueID () {
  return crypto.randomBytes(10).toString('hex')
}

function generateInstant () {
  return new Date().toISOString()
}

function inflateClean (samlResponse) {
  if (samlResponse.includes('samlp:Response')) {
    return samlResponse.toString('utf8')
  } else {
    var tmp = zlib.inflateRawSync(samlResponse).toString('utf8')
    return tmp
  }
}

function signRequest (samlMessage) {
  var signer
  var samlMessageToSign = {}

  switch (options.signatureAlgorithm) {
    case 'sha256':
      samlMessage.SigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
      signer = crypto.createSign('RSA-SHA256')
      break
    case 'sha512':
      samlMessage.SigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'
      signer = crypto.createSign('RSA-SHA512')
      break
    default:
      samlMessage.SigAlg = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
      signer = crypto.createSign('RSA-SHA1')
      break
  }
  if (samlMessage.SAMLRequest) {
    samlMessageToSign.SAMLRequest = samlMessage.SAMLRequest
  }
  if (samlMessage.SAMLResponse) {
    samlMessageToSign.SAMLResponse = samlMessage.SAMLResponse
  }
  if (samlMessage.RelayState) {
    samlMessageToSign.RelayState = samlMessage.RelayState
  }
  if (samlMessage.SigAlg) {
    samlMessageToSign.SigAlg = samlMessage.SigAlg
  }
  signer.update(querystring.stringify(samlMessageToSign))
  samlMessage.Signature = signer.sign(options.privateCert, 'base64')
}

function requestToURL (request) {
  var deflated = Buffer.from(zlib.deflateRawSync(request), 'utf8')
  var base64 = deflated.toString('base64')
  var urlEnc = encodeURIComponent(base64.toString())

  return urlEnc
}

function samlParse (saml) {
  var profile = {}
  var doc = new xmldom.DOMParser().parseFromString(saml)
  var attributes = xpath.select('//*[local-name() = "AttributeStatement"]/*', doc)
  attributes.forEach(function (attribute) {
    var name = xpath.select('string(@Name)', attribute)
    profile[_.camelCase(name)] = xpath.select('string(*[local-name() = "AttributeValue"]/text())', attribute)
  })
  return profile
}

// Create a new rpc server for listening to TCL iRule calls.
var ilx = new f5.ILXServer()

ilx.addMethod('saml-request', function (req, res) {
  // var method = req.params()[0]
  var landingURI = req.params()[1]
  var sign = req.params()[2]

  var isPassive = false

  var id = '_' + generateUniqueID()
  var instant = generateInstant()
  var forceAuthn = options.forceAuthn || false

  var request = {
    'samlp:AuthnRequest': {
      '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
      '@ID': id,
      '@Version': '2.0',
      '@IssueInstant': instant,
      '@ProtocolBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      '@AssertionConsumerServiceURL': 'https://' + landingURI,
      '@Destination': options.entryPoint,
      'saml:Issuer': {
        '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        '#text': options.issuer
      }
    }
  }

  if (isPassive) { request['samlp:AuthnRequest']['@IsPassive'] = true }

  if (forceAuthn) { request['samlp:AuthnRequest']['@ForceAuthn'] = true }

  if (options.identifierFormat) {
    request['samlp:AuthnRequest']['samlp:NameIDPolicy'] = {
      '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
      '@Format': options.identifierFormat,
      '@AllowCreate': 'true'
    }
  }

  if (!options.disableRequestedAuthnContext) {
    request['samlp:AuthnRequest']['samlp:RequestedAuthnContext'] = {
      '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
      '@Comparison': 'exact',
      'saml:AuthnContextClassRef': {
        '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        '#text': options.authnContext
      }
    }
  }

  if (options.attributeConsumingServiceIndex) {
    request['samlp:AuthnRequest']['@AttributeConsumingServiceIndex'] = options.attributeConsumingServiceIndex
  }

  if (options.providerName) {
    request['samlp:AuthnRequest']['@ProviderName'] = options.providerName
  }

  var authrequest

  if (sign === 'true') {
    authrequest = signRequest(xmlbuilder.create(request).end())
  } else {
    authrequest = xmlbuilder.create(request).end()
  }
  var encodedAuthNRequest = requestToURL(authrequest)
  var redirectAuth = options.issuerURL + '?SAMLRequest=' + encodedAuthNRequest

  res.reply(['OK', redirectAuth])
})

function isEncoded (url) {
  var url = url || ''
  return url !== decodeURIComponent(url)
}

function cleanURI (uri) {
  while (isEncoded(uri)) {
    uri = decodeURIComponent(uri)
  }
  return uri
}

ilx.addMethod('saml-validate', function (req, res) {
  var parse = req.params()[1]
  var saml = req.params()[0]

  var URLDecodedAssertion = cleanURI(saml)
  var B64Assertion = Buffer.from(URLDecodedAssertion, 'base64')
  var rawAssertion = inflateClean(B64Assertion)

  // var rawAssertion = inflateClean(B64Assertion)
  // Inflate Breaking on non Deflated
  // var rawAssertion = B64AssertionBuff.toString('utf8');

  var doc = new dom().parseFromString(rawAssertion)
  var signature = select(doc, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0]
  var sig = new SignedXml()

  var isvalid
  if (typeof signature !== 'undefined') {
    sig.keyInfoProvider = new FileKeyInfo(signaturePubKey)
    sig.loadSignature(signature)

    var result = sig.checkSignature(rawAssertion)
    if (!result) {
      isvalid = "1"
    } else {
      isvalid = "0"
    }
  } else {
    isvalid = '2'
  }

  var parsed
  if (parse === 'true') {
    var parser = samlParse(rawAssertion)
    parsed = JSON.stringify(parser)
  } else {
    parsed = 'parse=false'
  }

  res.reply([isvalid, parsed])
})

// Start listening for ILX::call and ILX::notify events.
ilx.listen()


