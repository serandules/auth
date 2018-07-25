var log = require('logger')('auth');
var errors = require('errors');

var Token = require('model-tokens');
require('model-clients');
require('model-users');
require('model-tiers');

module.exports = function (options) {
    return function (req, res, next) {
        var o;
        var i;
        var length;
        var path = req.path;
        var auth = req.headers['authorization'];
        if (!auth) {
            o = options[req.method];
            if (o) {
                length = o.length;
                for (i = 0; i < length; i++) {
                    if (new RegExp(o[i], 'i').test(path)) {
                        return next();
                    }
                }
            }
            return res.pond(errors.unauthorized())
        }
        var match = /^\s*Bearer\s+(.*)$/g.exec(auth);
        if (!match) {
            return res.pond(errors.unsupportedAuth());
        }
        var token = match[1];
        Token.findOne({
            access: token
        }).populate('client user tier')
            .exec(function (err, token) {
                if (err) {
                    log.error('tokens:find-one', err);
                    return res.pond(errors.serverError());
                }
                if (!token) {
                    return res.pond(errors.unauthorized());
                }
                if (token.accessibility() === 0) {
                    return res.pond(errors.unauthorized());
                }
                req.token = token;
                req.user = token.user;
                next();
            });
    };
};