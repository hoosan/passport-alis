const vows = require('vows')
  , assert = require('assert')
  , util = require('util')
  , url = require('url');
const ALISStrategy = require('../lib')
  , Config = require('../config');

// dummy data
const CLIENT_ID = Config.client_id;
const CLIENT_SECRET = Config.client_secret;
const REDIRECT_URI = Config.redirect_uri;

const PROFILE_PAGE = 'https://alis.to/oauth2api/me/info';

// test cases
vows.describe('ALISStrategy').addBatch({
  'strategy': {
    topic: function() {
      return new ALISStrategy({
        clientID: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        redirectURL: REDIRECT_URI
      },
      function() {});
    },

    'should be named alis': function(strategy) {
      assert.equal(strategy.name, 'alis');
    },
  },

  'strategy when redirecting for authorization': {
    topic: function () {
      const strategy = new ALISStrategy({
        clientID: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        redirectURL: REDIRECT_URI
      }, function() {});
      return strategy;
    },

    'and display not set': {
      topic: function (strategy) {
        var mockRequest = {},
            url;

        // Stub strategy.redirect()
        var self = this;
        strategy.redirect = function (location) {
          self.callback(null, location)
        };
        strategy.authenticate(mockRequest);
      },

      'does not set authorization param': function(err, location) {
        var params = url.parse(location, true).query;
        assert.isUndefined(params.display);
      }
    },

    'and display set to touch': {
      topic: function (strategy) {
        var mockRequest = {},
            url;

        // Stub strategy.redirect()
        var self = this;
        strategy.redirect = function (location) {
          self.callback(null, location)
        };
        strategy.authenticate(mockRequest, { display: 'touch' });
      },

      'sets authorization param to touch': function(err, location) {
        var params = url.parse(location, true).query;
        assert.equal(params.display, 'touch');
      }
    }
  },

  'strategy when loading user profile': {
    topic: function() {
      var strategy = new ALISStrategy({
          clientID    : CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          redirectURL : REDIRECT_URI
      },
      function() {});

      // mock
      strategy._getProfile = function(url, accessToken, callback) {
        if (url == PROFILE_PAGE) {
          var body = '{"user_id":"fukurou"}';
          callback(null, body, undefined);
        } else {
          callback(new Error('Incorrect user profile URL: ' + url));
        }
      }
      return strategy;
    },
    'when told to load user profile': {
      topic: function(strategy) {
        var self = this;
        function done(err, profile) {
          self.callback(err, profile);
        }

        process.nextTick(function () {
          strategy.userProfile('access_token', done);
        });
      },

      'should not error' : function(err, req) {
        assert.isNull(err);
      },
      'should load profile' : function(err, profile) {
        assert.equal(profile.provider, 'alis');
        assert.equal(profile.id, "fukurou");
      },
      'should set raw property' : function(err, profile) {
        assert.isDefined(profile);
        assert.ok('_raw' in profile);
        assert.isString(profile._raw);
      },
      'should set json property' : function(err, profile) {
        assert.isDefined(profile);
        assert.ok('_json' in profile);
        assert.isObject(profile._json);
      },
    },
  },

  'strategy when loading user profile and encountering an error': {
    topic: function() {
      var strategy = new ALISStrategy({
          clientID    : CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          redirectURL : REDIRECT_URI
      },
      function() {});

      // mock
      strategy._getProfile = function(url, accessToken, callback) {
        callback(new Error('something-went-wrong'));
      }
      return strategy;
    },

    'when told to load user profile': {
      topic: function(strategy) {
        var self = this;
        function done(err, profile) {
          self.callback(err, profile);
        }

        process.nextTick(function () {
          strategy.userProfile('access_token', done);
        });
      },

      'should error' : function(err, req) {
        assert.isNotNull(err);
      },
      'should wrap error in InternalOAuthError' : function(err, req) {
        assert.equal(err.constructor.name, 'InternalOAuthError');
      },
      'should not load profile' : function(err, profile) {
        assert.isUndefined(profile);
      },
    },
  },


}).export(module);
