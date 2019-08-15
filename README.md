passport-alis - OAuth2.0 package for ALIS
===========

## Introduction

[Passport](http://passportjs.org/) strategy for authenticating with [ALIS](http://alis.to) using the OAuth 2.0 API


## Install

    $ npm install passport-alis

## Usage

### Authorization Endpoint

    const passport = require('passport');
	const ALISStrategy = require('passport-alis');

	passport.use(new ALISStrategy({
		clientID     : <ALIS_APP_ID>,
		clientSecret : <ALIS_APP_SECRET>,
		callbackURL  : <CALL_BACK_URL>,
	}, function(accessToken, refreshtoken, id_token, profile, done){
	    // With this accessToken you can access user profile data.
		// In the case that accessToken is expired, you should
		// regain it with refreshToken. So you have to keep these token
		// safely.
	});


### Token Endpoint

With this module, you don't have to do anything to get accessToken.
As you see above, you have already obtain accessToken and refreshToken.
So this process is not required with this module.

### License

MIT License. Please see the LICENSE file for details.


Developed by hoosan(hoosan16)
