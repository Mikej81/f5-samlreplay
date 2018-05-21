const http = require('http');
const session = require('express-session');
const oktaAuth = require('okta-auth');
const express = require('express');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser')
const expressOktaSaml = require('./core.js');

const hour = 3600000;
const app = express();
app.use(cookieParser());
app.use(session({
  secret:  'my-secret',
  cookie: { maxAge:  hour  *  24 },
  resave:  true,
  saveUninitialized:  true,
  name:  'my-app',
}));

app.use(bodyParser.json()); // important to have bodyParser as OKTA will make POST redirect with body data
app.use(bodyParser.urlencoded({ extended:  false }));
app.get('/ping', (req, res) => { // unprotected healthcheck
  res.statusCode  =  200;
  res.send('pong');
});

const expressOktaSamlConfig = require('./config.js'); // check bellow for config exmaple and tips
const okta = expressOktaSaml(app, expressOktaSamlConfig); // setups okta routes + passport
app.use('/', okta.secured); // from here all following requests will be checked for auth
app.get('/test', () => { res.send(''); }); // this will be not reachable if user is not logged in via OKTA

const server = http.createServer(app);
server.listen(3000, (err) => {
  if (err) {
    console.log('Failed to start server');
    console.log(err);
  }
  console.log(`Server has started on port: ${server.address().port}`);
});
