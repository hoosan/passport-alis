var vow = require('vows');
var assert = require('assert');
var util = require('util');
var passport_alis = require('../lib/passport-alis');

vow.describe('passport-alis').addBatch({
  'module': {
    'should report a version': function () {
      assert.isString(passport_alis.version);
    }
  }
}).export(module);
