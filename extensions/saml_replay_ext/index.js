// Import the f5-nodejs module.
var f5 = require('f5-nodejs');

// Import the XML-Crypto Libraries
// var saml = require('saml20');
var zlib = require('zlib');
var select = require('xml-crypto').xpath
  , dom = require('xmldom').DOMParser
  , SignedXml = require('xml-crypto').SignedXml
  , FileKeyInfo = require('xml-crypto').FileKeyInfo  
  , fs = require('fs');
  
var signaturePubKey = "othercert.pem";

// Create a new rpc server for listening to TCL iRule calls.
var ilx = new f5.ILXServer();

ilx.addMethod('saml-validate', function(req, res) {
    // Function parameters can be found in req.params().
    //console.log('params: ' + req.params());
    
    var parse = req.params()[1];

    var URLDecodedAssertion = decodeURIComponent(req.params()[0]);
    //console.log('URLdecoded: ' + URLDecodedAssertion);
    
    var B64Assertion = new Buffer(URLDecodedAssertion, 'base64');
    
    var rawAssertion = zlib.inflateRawSync(B64Assertion).toString('utf8');

    var doc = new dom().parseFromString(rawAssertion);
    
    var signature = select(doc, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];

    var sig = new SignedXml();
    //IF keep this method, move outside of function, sync/async
    
    sig.keyInfoProvider = new FileKeyInfo(signaturePubKey);
    sig.loadSignature(signature);

    var result = sig.checkSignature(rawAssertion);
    var isvalid;
    if (!result) {
        isvalid = sig.validationErrors;
    } else {
        isvalid = result;
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

function myKeyInfo(x509Certificate){
        this.getKeyInfo = function(key) {
                return '<X509Data><X509Certificate>'+x509Certificate+'</X509Certificate></X509Data>';
        };
        this.getKey = function(keyInfo) {
                // return the public key in pem format
                return getPublicKeyPemFromCertificate(x509Certificate).toString();
       };
}





