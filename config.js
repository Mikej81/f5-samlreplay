const fs = require('fs');
const path = require('path');

const cert = fs.readFileSync(path.join(__dirname, 'bigip.crt'), 'utf8');

module.exports = {
  SAML: {
    passportOptions: { // check full list of available options - https://github.com/bergie/passport-saml
      cert,
      issuer:  'https://f5.f5lab.com', // your okta issuer url (provided by okta duerning SAML setup)
      entryPoint:  'https://f5.f5lab.com/sso/saml', // entryPoint url (provided by okta duerning SAML setup)
      callbackUrl:  'http://f5.f5lab.com:3000/login', // your callback url
    },
    propertiesToExtract: ['Email', 'FirstName', 'LastName'], // these properties will be saved on user session by passport access it by req.user
  },

  passport: {
    options: { //options to be passed to passport.authenticate(). check full list of available options - https://github.com/jaredhanson/passport/blob/master/lib/middleware/authenticate.js
      successRedirect:  '/',
      failureRedirect:  '/login',
      failureFlash:  true,
    },
  },

  appRoutes: { // express-okta-saml will create GET/POST routes on these endpoints to handle auth proccess
    loginPath:  '/login', // make sure this is same as path on SAML.passportOptions.callbackUrl and passport.options.failureRedirect
    logoutPath:  '/logout',
    accessDeniedPath:  '/access-denied',
  },
}
