var log = require('logger')('auth');
var errors = require('errors');

var Tokens = require('model-tokens');
var Otps = require('model-otps');
require('model-clients');
require('model-users');
require('model-tiers');

module.exports = function (options) {
  options = options || {};
  return function (req, res, next) {
    var otp = req.headers['x-otp'];
    if (otp) {
      Otps.findOne({
        value: otp
      }).populate('user').exec(function (err, otp) {
        if (err) {
          log.error('otps:find-one', err);
          return next(errors.serverError());
        }
        if (!otp || !otp.user) {
          return next(errors.unauthorized());
        }
        Otps.remove({_id: otp.id}, function (err) {
          if (err) {
            return next(err);
          }
          req.otp = otp;
          req.user = otp.user;
          next();
        });
      });
      return;
    }
    var auth = req.headers['authorization'];
    if (auth) {
      var match = /^\s*Bearer\s+(.*)$/g.exec(auth);
      if (!match) {
        return next(errors.unsupportedAuth());
      }
      var token = match[1];
      Tokens.findOne({
        access: token
      }).populate('client user tier')
        .exec(function (err, token) {
          if (err) {
            log.error('tokens:find-one', err);
            return next(errors.serverError());
          }
          if (!token) {
            return next(errors.unauthorized());
          }
          if (token.accessibility() === 0) {
            return next(errors.unauthorized());
          }
          req.token = token;
          req.user = token.user;
          next();
        });
      return;
    }
    var i;
    var length;
    var path = req.path;
    var o = options[req.method];
    if (o) {
      length = o.length;
      for (i = 0; i < length; i++) {
        if (new RegExp(o[i], 'i').test(path)) {
          return next();
        }
      }
    }
    return next(errors.unauthorized());
  };
};