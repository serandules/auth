var log = require('logger')('auth');
var errors = require('errors');

var models = require('models');

var Tokens = models.tokens.model;
var Otps = models.otps.model;

module.exports = function (options) {
  options = options || {};
  return function (req, res, next) {
    var otp = req.headers['x-otp'];
    if (otp) {
      Otps.findOneAndDelete({strong: otp}).populate('user').exec(function (err, otp) {
        if (err) {
          return next(err);
        }
        if (!otp || !otp.user) {
          return next(errors.unauthorized());
        }
        req.otp = otp;
        req.user = otp.user;
        next();
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
    var model = req.ctx.model;
    var o = options[req.method];
    var path = req.path.replace(new RegExp('^/' + model.modelName + '/?'), '/');
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
