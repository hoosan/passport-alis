"use strict";

var express = require('express')
  , passport = require('passport')
  , ALISStrategy = require('../../lib/passport-alis').ALISStrategy;

var methodOverride = require('method-override')
var session = require('express-session')
var bodyParser = require('body-parser')
var flash = require('connect-flash');

var SCOPE = "read";

// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.  However, since this example does not
//   have a database of user records, the complete ALIS profile is serialized
//   and deserialized.

// serialize tht user.id to save in the cookie session
// so the browser will remember the user when login
passport.serializeUser((user, done) => {
  done(null, user);
});

// deserialize the cookieUserId to user in the database
passport.deserializeUser((user, done) => {
  done(null, user);
})


// Use the ALISStrategy within Passport.
//   Strategies in Passport require a `verify` function, which accept
//   credentials (in this case, an accessToken, refreshToken, and ALIS
//   profile), and invoke a callback with a user object.
passport.use(new ALISStrategy({
    clientID:     require('./config').client_id
  , clientSecret: require('./config').client_secret
  , callbackURL:  require('./config').redirect_uri
  },
  function(accessToken, refreshToken, profile, done) {
    return done(null, profile);
  }
));

var app = express();

// configure Express
app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');
app.use(bodyParser());
app.use(methodOverride());
app.use(session({ secret: 'keyboard cat' }));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(__dirname + '/public'));


app.get('/', function(req, res){
  res.render('index', { user: req.user });
});

app.get('/account', ensureAuthenticated, function(req, res){
  res.render('account', { user: req.user });
});

app.get('/login', function(req, res){
  
  // check error message by flash
  const error_message = req.flash('error')
  console.log(error_message);

  res.render('login', { user: req.user });

});

// GET /auth/alis
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  The first step in ALIS authentication will involve
//   redirecting the user to alis.to  After authorization, ALIS will
//   redirect the user back to this application at /auth/alis/callback
app.get('/auth/alis',
  passport.authenticate('alis', {
    scope: SCOPE
  , nonce: parseInt((new Date)/1000)
  }),
  function(req, res){
    // The request will be redirected to ALIS for authentication, so this
    // function will not be called.
  });

// GET /auth/alis/callback
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  If authentication fails, the user will be redirected back to the
//   login page.  Otherwise, the primary route function will be called,
//   which, in this example, will redirect the user to the home page.
app.get('/auth/alis/callback', 
  passport.authenticate('alis', { 
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
  }),
  function(req, res) {
    res.redirect('/account');
  });

app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});

app.listen(3000);


// Simple route middleware to ensure user is authenticated.
//   Use this route middleware on any resource that needs to be protected.  If
//   the request is authenticated (typically via a persistent login session),
//   the request will proceed.  Otherwise, the user will be redirected to the
//   login page.
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { return next(); }
  res.redirect('/login')
}
