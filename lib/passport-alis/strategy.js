/**
 * Module dependencies.
 */
var util = require('util')
    , querystring= require('querystring')
    , url = require('url')
    , base64url = require('base64url')
    , crypto = require('crypto')
    , utils = require('./utils')
    , jwkToPem = require("jwk-to-pem")
    , jwt = require("jsonwebtoken")
    , fetch = require("node-fetch")
    , OAuth2Strategy = require('passport-oauth').OAuth2Strategy
    , InternalOAuthError = require('passport-oauth').InternalOAuthError;
/**
 * `Strategy` constructor.
 *
 * The ALIS authentication strategy authenticates requests by delegating to
 * ALIS using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your ALIS application's App ID
 *   - `clientSecret`  your ALIS application's App Secret
 *   - `callbackURL`   URL to which ALIS will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new  ALISStrategy({
 *         clientID: 'yourclientid',
 *         clientSecret: 'yourclientsecret',
 *         callbackURL: 'https://yourwebsite.com/auth/alis/callback',
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://alis.to/oauth-authenticate';
  options.tokenURL = options.tokenURL || 'https://alis.to/oauth2/token';
  options.scopeSeparator = options.scopeSeparator || ' ';
  options.state = true;
  options.pkce = true;

  OAuth2Strategy.call(this, options, verify);
  this.name = 'alis';
  this._profileURL = options.profileURL || 'https://alis.to/oauth2api';
  this._profileFields = options.profileFields || null;

}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Return extra ALIS specific parameters to be included in the authorization
 * request.
 *
 * Options:
 *  - `display`  Display mode to render dialog, { `page`, `touch` }.
 *  - `prompt`   @todo
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
Strategy.prototype.authorizationParams = function (options) {
  var params = {};

  if (options.display) {
    params.display = options.display;
  }
  if (options.prompt) {
    params.prompt = options.prompt;
  }
  return params;
};

/**
 * Authenticate request by delegating to a service provider using OAuth 2.0.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = async function(req, options) {
  options = options || {};
  var self = this;

  if (req.query && req.query.error) {
    if (req.query.error == 'access_denied') {
      return this.fail({ message: req.query.error_description });
    } else {
      return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
    }
  }

  var callbackURL = options.callbackURL || this._callbackURL;
  if (callbackURL) {
    var parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(utils.originalURL(req, { proxy: this._trustProxy }), callbackURL);
    }
  }

  var meta = {
    authorizationURL: this._oauth2._authorizeUrl,
    tokenURL: this._oauth2._accessTokenUrl,
    clientId: this._oauth2._clientId,
    clientSecret: this._oauth2._clientSecret,
  }

  if (req.query && req.query.code) {

    function loaded(err, ok, state) {
      if (err) { return self.error(err); }
      // if (!ok) {
      //   return self.fail(state, 403);
      // }

      var code = req.query.code;

      var params = self.tokenParams(options);
      params.grant_type = 'authorization_code';

      if (callbackURL) { params.redirect_uri = callbackURL; }

      if (typeof ok == 'string') { // PKCE
        params.code_verifier = ok;
      }
      const { code_verifier } = req.session;
      params.code_verifier = code_verifier;
      params.client_id = meta.clientId;
      params.client_secret = meta.clientSecret;

      self._getOAuthAccessToken(code, params,
        function(err, accessToken, refreshToken, idToken, params) {

          if (err) { return self.error(self._createOAuthError('Failed to obtain access token', err)); }

          // check ID token
          self._checkIdToken(idToken)
            .catch((err) => {return self.fail(err);});

          self._loadUserProfile(accessToken, function(err, profile) {
            if (err) { return self.error(err); }

            function verified(err, user, info) {
              if (err) { return self.error(err); }
              if (!user) { return self.fail(info); }

              info = info || {};
              if (state) { info.state = state; }
              self.success(user, info);
            }

            try {
              if (self._passReqToCallback) {
                var arity = self._verify.length;
                if (arity == 6) {
                  self._verify(req, accessToken, refreshToken, params, profile, verified);
                } else { // arity == 5
                  self._verify(req, accessToken, refreshToken, profile, verified);
                }
              } else {
                var arity = self._verify.length;
                if (arity == 5) {
                  self._verify(accessToken, refreshToken, params, profile, verified);
                } else { // arity == 4
                  self._verify(accessToken, refreshToken, profile, verified);
                }
              }
            } catch (ex) {
              return self.error(ex);
            }
          });
        }
      );
    }

    var state = req.query.state;
    
    try {
      var arity = this._stateStore.verify.length;
      if (arity == 4) {
        this._stateStore.verify(req, state, meta, loaded);
      } else { // arity == 3
        this._stateStore.verify(req, state, loaded);
      }
    } catch (ex) {
      console.log(`ex: ${JSON.stringify(ex)}`)
      return this.error(ex);
    }
  } else {
    var params = this.authorizationParams(options);
    params.response_type = 'code';
    if (callbackURL) { params.redirect_uri = callbackURL; }
    var scope = options.scope || this._scope;
    if (scope) {
      if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
      params.scope = scope;
    }
    var verifier, challenge;

    if (this._pkceMethod) {
      verifier = base64url(crypto.pseudoRandomBytes(32))
      switch (this._pkceMethod) {
      case 'plain':
        challenge = verifier;
        break;
      case 'S256':
        challenge = base64url(crypto.createHash('sha256').update(verifier).digest());
        break;
      default:
        return this.error(new Error('Unsupported code verifier transformation method: ' + this._pkceMethod));
      }
      
      params.code_challenge = challenge;
      params.code_challenge_method = this._pkceMethod;
      req.session.code_verifier = verifier;

    }

    var state = options.state;

    if (state) {
      params.state = state;
      
      var parsed = url.parse(this._oauth2._authorizeUrl, true);
      utils.merge(parsed.query, params);
      parsed.query['client_id'] = this._oauth2._clientId;
      delete parsed.search;
      var location = url.format(parsed);
      this.redirect(location);
    } else {
      function stored(err, state) {
        if (err) { return self.error(err); }

        if (state) { params.state = state; }
        var parsed = url.parse(self._oauth2._authorizeUrl, true);
        utils.merge(parsed.query, params);
        parsed.query['client_id'] = self._oauth2._clientId;
        delete parsed.search;
        var location = url.format(parsed);
        self.redirect(location);
      }

      try {
        var arity = this._stateStore.store.length;
        if (arity == 5) {
          this._stateStore.store(req, verifier, undefined, meta, stored);
        } else if (arity == 3) {
          this._stateStore.store(req, meta, stored);
        } else { // arity == 2
          this._stateStore.store(req, stored);
        }
      } catch (ex) {
        return this.error(ex);
      }
    }
  }
};

/**
 * Retrieve user profile from alis.to
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `username`         the username
 *
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = async function(accessToken, done) {
  var url = 'https://alis.to/oauth2api/me/info';

  this._getProfile(url, accessToken, function (err, body, res) {

    if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }

    var profile = {};
    try {
      var json = JSON.parse(body);
      console.log(json);

      if (typeof json.user_id !== "undefined") {
        profile.id = json.user_id;
      }

      profile._raw  = body;
      profile._json = json;

      done(null, profile);
    } catch(e) {
      done(e);
    }
  });
};

/**
 * Retrieve access token
 *
 *
 *
 * @param {String} code
 * @param {Object} params
 * @param {Function} callback
 * @api protected
 */
Strategy.prototype._getOAuthAccessToken = function(code, params, callback) {
  var params= params || {};
  const token = Buffer.from(`${params['client_id']}:${params['client_secret']}`).toString("base64");

  var codeParam = (params.grant_type === 'refresh_token') ? 'refresh_token' : 'code';
  params[codeParam]= code;
  var post_data= querystring.stringify( params );
  var post_headers= {
    Authorization: `Basic ${token}`,
    'Content-Type': 'application/x-www-form-urlencoded'
  };

  this._oauth2._request("POST", 'https://alis.to/oauth2/token', post_headers, post_data, null, function(error, data, response) {
    if( error )  callback(error);
    else {
      var results;
      try {
        // As of http://tools.ietf.org/html/draft-ietf-oauth-v2-07
        // responses should be in JSON
        results= JSON.parse( data );
      }
      catch(e) {
        // .... However both Facebook + Github currently use rev05 of the spec
        // and neither seem to specify a content-type correctly in their response headers :(
        // clients of these services will suffer a *minor* performance cost of the exception
        // being thrown
        results= querystring.parse( data );
      }
      var access_token= results["access_token"];
      var refresh_token= results["refresh_token"];
      var id_token= results["id_token"];

      // delete results["refresh_token"];
      callback(null, access_token, refresh_token, id_token, results); // callback results =-=
    }
  });
}

Strategy.prototype._getProfile = function(url, access_token, callback) {
  var post_headers= {
      "Authorization": `${access_token}`,
      "Content-Type": "application/json; charset=utf-8"
  };
  this._oauth2._request("GET", url, post_headers, "", access_token, callback );
}

Strategy.prototype._checkIdToken = async function(token) {
  const iss = "https://alis.to/oauth2";
  try {
    const sig_key = await this._get_sig_key(
      jwt.decode(token, { complete: true }).header.kid
    );
    const decoded = jwt.verify(token, sig_key);
    if (decoded.iss !== iss) {
      throw new Error(`this idtoken's iss is not ${iss}`);
    }
    console.log(decoded);
  } catch (e) {
    console.log(e);
    throw new Error(`this idtoken is not valid`);
  }
}

Strategy.prototype._get_sig_key = async function(kid) {
  const jwk_url = 'https://alis.to/oauth2/jwks'
  const response = await fetch(jwk_url);
  const response_json = await response.json();
  for (const k of response_json.keys) {
    if (k.kid === kid) {
      return jwkToPem(k);
    }
  }
}

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
