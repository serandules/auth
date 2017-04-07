var log = require('logger')('auth');
var errors = require('errors');

var Token = require('model-tokens');
require('model-clients');
require('model-users');

module.exports = function (options) {
    return function (req, res, next) {
        var path = req.path;
        var open = options.open;
        var i, length;
        if (open) {
            length = open.length;
            for (i = 0; i < length; i++) {
                if (new RegExp(open[i], 'i').test(path)) {
                    return next();
                }
            }
        }
        var hybrid;
        var auth = req.headers['authorization'];
        if (!auth) {
            hybrid = options.hybrid;
            if (hybrid) {
                length = hybrid.length;
                for (i = 0; i < length; i++) {
                    if (new RegExp(hybrid[i], 'i').test(path)) {
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
        //TODO: validate auth header
        Token.findOne({
            access: token
        }).populate('client')
            .exec(function (err, token) {
                if (err) {
                    log.error(err);
                    return res.pond(errors.serverError());
                }
                if (!token) {
                    return res.pond(errors.unauthorized());
                }
                if (token.accessibility() === 0) {
                    return res.pond(errors.unauthorized());
                }
                req.token = token;
                next();
            });
    };
};