// Import the f5-nodejs module.
var f5 = require('f5-nodejs')

// Import the XML-Crypto Libraries
var zlib = require('zlib')
var crypto = require('crypto')
var xmldom = require('xmldom')
var xmlbuilder = require('xmlbuilder')
var xpath = require('xpath')
//var xmlCrypto = require('xml-crypto')
var select = require('xml-crypto').xpath
var dom = require('xmldom').DOMParser
var SignedXml = require('xml-crypto').SignedXml
var FileKeyInfo = require('xml-crypto').FileKeyInfo
var _ = require('lodash')
var querystring = require('querystring')
var Q = require('q')
var InMemoryCacheProvider = require('./inmemory-cache-provider.js').CacheProvider

//  Public Key of Issuer configured here
// var signaturePubKey = 'cert.pem'

// Testing Certs and Assertions
// Use POSTMAN to verify
// samltool = PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIElEPSJfOGU4ZGM1ZjY5YTk4Y2M0YzFmZjM0MjdlNWNlMzQ2MDZmZDY3MmY5MWU2IiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAxNC0wNy0xN1QwMTowMTo0OFoiIERlc3RpbmF0aW9uPSJodHRwOi8vc3AuZXhhbXBsZS5jb20vZGVtbzEvaW5kZXgucGhwP2FjcyIgSW5SZXNwb25zZVRvPSJPTkVMT0dJTl80ZmVlM2IwNDYzOTVjNGU3NTEwMTFlOTdmODkwMGI1MjczZDU2Njg1Ij4NCiAgPHNhbWw6SXNzdWVyPmh0dHA6Ly9pZHAuZXhhbXBsZS5jb20vbWV0YWRhdGEucGhwPC9zYW1sOklzc3Vlcj4NCiAgPHNhbWxwOlN0YXR1cz4NCiAgICA8c2FtbHA6U3RhdHVzQ29kZSBWYWx1ZT0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnN0YXR1czpTdWNjZXNzIi8+DQogIDwvc2FtbHA6U3RhdHVzPg0KICA8c2FtbDpBc3NlcnRpb24geG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiBJRD0icGZ4NmY4M2YwZDAtZjk1Yi00YjkwLTcyOTYtYmY1ZmE1ODk0NTEzIiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAxNC0wNy0xN1QwMTowMTo0OFoiPg0KICAgIDxzYW1sOklzc3Vlcj5odHRwOi8vaWRwLmV4YW1wbGUuY29tL21ldGFkYXRhLnBocDwvc2FtbDpJc3N1ZXI+PGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+DQogIDxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+DQogICAgPGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNyc2Etc2hhMSIvPg0KICA8ZHM6UmVmZXJlbmNlIFVSST0iI3BmeDZmODNmMGQwLWY5NWItNGI5MC03Mjk2LWJmNWZhNTg5NDUxMyI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3Jtcz48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3NoYTEiLz48ZHM6RGlnZXN0VmFsdWU+dGRNQzU3SVhxSTg0QmpQWERpUDRRZnA4QktFPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5temVIV2hDdnhtZFM0MkJFZ2Y3ZnIvY0FSeVNRZDVDTjBaMjl1OERFalcwOWQ4ZDhCVU9lclNBV09lU2I0Rld5M1hTenBZcmJPZ1VlekhidGsyNU1rMm9HdmFkU2VyZVN2dXdJVk82MGJxcWZwMS9LYWJlSjFqbDZLWGh3T1llTG1PQkpONVZtVHAvdnFvV3NNMDFHQTRPMm9NQmNZSnMzS1dFZU9yMnBiclU9PC9kczpTaWduYXR1cmVWYWx1ZT4NCjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YT48ZHM6WDUwOUNlcnRpZmljYXRlPk1JSUNhakNDQWRPZ0F3SUJBZ0lCQURBTkJna3Foa2lHOXcwQkFRMEZBREJTTVFzd0NRWURWUVFHRXdKMWN6RVRNQkVHQTFVRUNBd0tRMkZzYVdadmNtNXBZVEVWTUJNR0ExVUVDZ3dNVDI1bGJHOW5hVzRnU1c1ak1SY3dGUVlEVlFRRERBNXpjQzVsZUdGdGNHeGxMbU52YlRBZUZ3MHhOREEzTVRjeE5ERXlOVFphRncweE5UQTNNVGN4TkRFeU5UWmFNRkl4Q3pBSkJnTlZCQVlUQW5Wek1STXdFUVlEVlFRSURBcERZV3hwWm05eWJtbGhNUlV3RXdZRFZRUUtEQXhQYm1Wc2IyZHBiaUJKYm1NeEZ6QVZCZ05WQkFNTURuTndMbVY0WVcxd2JHVXVZMjl0TUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FEWngrT040SVVvSVd4Z3VrVGIxdE9pWDNiTVl6WVFpd1dQVU5NcCtGcTgyeG9Ob2dzbzJieWtaRzB5aUptNW84enYvc2Q2cEdvdWF5TWdreC8yRlNPZGMzNlQwakdiQ0h1UlNidGlhMFBFek5JUnRtVmlNcnQzQWVvV0JpZFJYbVpzeENOTHdnSVY2ZG4yV3B1RTVBejBiSGdwWm5ReFRLRmVrMEJNS1UvZDh3SURBUUFCbzFBd1RqQWRCZ05WSFE0RUZnUVVHSHhZcVpZeVg3Y1R4S1ZPRFZnWndTVGRDbnd3SHdZRFZSMGpCQmd3Rm9BVUdIeFlxWll5WDdjVHhLVk9EVmdad1NUZENud3dEQVlEVlIwVEJBVXdBd0VCL3pBTkJna3Foa2lHOXcwQkFRMEZBQU9CZ1FCeUZPbCtoTUZJQ2JkM0RKZm5wMlJnZC9kcXR0c1pHL3R5aElMV3ZFcmJpby9ERWU5OG1YcG93aFRrQzA0RU5wck95WGk3WmJVcWlpY0Y4OXVBR3l0MW9xZ1RVQ0QxVnNMYWhxSWNtcnpndW1OeVR3TEdXbzE3V0RBYTEvdXNEaGV0V0FNaGd6Ri9DbmY1ZWswbkswMG0wWVpHeWM0THpnRDBDUk9NQVNUV05nPT08L2RzOlg1MDlDZXJ0aWZpY2F0ZT48L2RzOlg1MDlEYXRhPjwvZHM6S2V5SW5mbz48L2RzOlNpZ25hdHVyZT4NCiAgICA8c2FtbDpTdWJqZWN0Pg0KICAgICAgPHNhbWw6TmFtZUlEIFNQTmFtZVF1YWxpZmllcj0iaHR0cDovL3NwLmV4YW1wbGUuY29tL2RlbW8xL21ldGFkYXRhLnBocCIgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1hdDp0cmFuc2llbnQiPl9jZTNkMjk0OGI0Y2YyMDE0NmRlZTBhMGIzZGQ2ZjY5YjZjZjg2ZjYyZDc8L3NhbWw6TmFtZUlEPg0KICAgICAgPHNhbWw6U3ViamVjdENvbmZpcm1hdGlvbiBNZXRob2Q9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjbTpiZWFyZXIiPg0KICAgICAgICA8c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBOb3RPbk9yQWZ0ZXI9IjIwMjQtMDEtMThUMDY6MjE6NDhaIiBSZWNpcGllbnQ9Imh0dHA6Ly9zcC5leGFtcGxlLmNvbS9kZW1vMS9pbmRleC5waHA/YWNzIiBJblJlc3BvbnNlVG89Ik9ORUxPR0lOXzRmZWUzYjA0NjM5NWM0ZTc1MTAxMWU5N2Y4OTAwYjUyNzNkNTY2ODUiLz4NCiAgICAgIDwvc2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uPg0KICAgIDwvc2FtbDpTdWJqZWN0Pg0KICAgIDxzYW1sOkNvbmRpdGlvbnMgTm90QmVmb3JlPSIyMDE0LTA3LTE3VDAxOjAxOjE4WiIgTm90T25PckFmdGVyPSIyMDI0LTAxLTE4VDA2OjIxOjQ4WiI+DQogICAgICA8c2FtbDpBdWRpZW5jZVJlc3RyaWN0aW9uPg0KICAgICAgICA8c2FtbDpBdWRpZW5jZT5odHRwOi8vc3AuZXhhbXBsZS5jb20vZGVtbzEvbWV0YWRhdGEucGhwPC9zYW1sOkF1ZGllbmNlPg0KICAgICAgPC9zYW1sOkF1ZGllbmNlUmVzdHJpY3Rpb24+DQogICAgPC9zYW1sOkNvbmRpdGlvbnM+DQogICAgPHNhbWw6QXV0aG5TdGF0ZW1lbnQgQXV0aG5JbnN0YW50PSIyMDE0LTA3LTE3VDAxOjAxOjQ4WiIgU2Vzc2lvbk5vdE9uT3JBZnRlcj0iMjAyNC0wNy0xN1QwOTowMTo0OFoiIFNlc3Npb25JbmRleD0iX2JlOTk2N2FiZDkwNGRkY2FlM2MwZWI0MTg5YWRiZTNmNzFlMzI3Y2Y5MyI+DQogICAgICA8c2FtbDpBdXRobkNvbnRleHQ+DQogICAgICAgIDxzYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkPC9zYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPg0KICAgICAgPC9zYW1sOkF1dGhuQ29udGV4dD4NCiAgICA8L3NhbWw6QXV0aG5TdGF0ZW1lbnQ+DQogICAgPHNhbWw6QXR0cmlidXRlU3RhdGVtZW50Pg0KICAgICAgPHNhbWw6QXR0cmlidXRlIE5hbWU9InVpZCIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDpiYXNpYyI+DQogICAgICAgIDxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPnRlc3Q8L3NhbWw6QXR0cmlidXRlVmFsdWU+DQogICAgICA8L3NhbWw6QXR0cmlidXRlPg0KICAgICAgPHNhbWw6QXR0cmlidXRlIE5hbWU9Im1haWwiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiPg0KICAgICAgICA8c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj50ZXN0QGV4YW1wbGUuY29tPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPg0KICAgICAgPC9zYW1sOkF0dHJpYnV0ZT4NCiAgICAgIDxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJlZHVQZXJzb25BZmZpbGlhdGlvbiIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDpiYXNpYyI+DQogICAgICAgIDxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPnVzZXJzPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPg0KICAgICAgICA8c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5leGFtcGxlcm9sZTE8L3NhbWw6QXR0cmlidXRlVmFsdWU+DQogICAgICA8L3NhbWw6QXR0cmlidXRlPg0KICAgIDwvc2FtbDpBdHRyaWJ1dGVTdGF0ZW1lbnQ+DQogIDwvc2FtbDpBc3NlcnRpb24+DQo8L3NhbWxwOlJlc3BvbnNlPg==
// var signaturePubKey = 'samltool.pem'

var options = initialize(options)

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
    options.signatureAlgorithm = 'sha256'
  }
  if (!options.cert) {
    options.cert = 'othercert.pem'
  }
  return options
}

function generateUniqueID () {
  return crypto.randomBytes(10).toString('hex')
};

function generateInstant () {
  return new Date().toISOString()
};

//  For future use
//  verify assertion against X509 included in Assertion
function certToPEM (cert) {
  cert = cert.match(/.{1,64}/g).join('\n')

  if (cert.indexOf('-BEGIN CERTIFICATE-') === -1) { cert = '-----BEGIN CERTIFICATE-----\n' + cert }
  if (cert.indexOf('-END CERTIFICATE-') === -1) { cert = cert + '\n-----END CERTIFICATE-----\n' }

  return cert
}

//  For future use
//  add multiple public keys to an array for signature validation
function certsToCheck () {
  var self = this
  if (!self.options.cert) {
    return Q()
  }
  if (typeof (self.options.cert) === 'function') {
    return Q.nfcall(self.options.cert)
      .then(function (certs) {
        if (!Array.isArray(certs)) {
          certs = [certs]
        }
        return Q(certs)
      })
  }
  var certs = self.options.cert
  if (!Array.isArray(certs)) {
    certs = [certs]
  }
  return Q(certs)
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
  url = url || ''
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
  var xml = rawAssertion.toString('utf8').trim()

  var doc = new dom().parseFromString(xml)
  
  var assertion = select(doc, "//*[local-name(.)='Assertion']")[0]
  var signature = select(assertion, "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0]

  var sig = new SignedXml()
  sig.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
  sig.keyInfoProvider = new FileKeyInfo(signaturePubKey)
  sig.loadSignature(signature.toString())
  var result = sig.checkSignature(assertion.toString())

  var isvalid
  if (result) {
    isvalid = '0'
  } else {
    console.log(sig.validationErrors)
    isvalid = '1'
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


