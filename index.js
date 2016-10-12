var log = require('logger')('auth');
var mongoose = require('mongoose');
var Token = require('token');

require('client');
require('user');

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
            res.status(401).send([{
                code: 401,
                message: 'Unauthorized'
            }]);
            return;
        }
        var match = /^\s*Bearer\s+(.*)$/g.exec(auth);
        if (!match) {
            res.status(401).send([{
                code: 401,
                message: 'Unsupported Authorization'
            }]);
            return;
        }
        var token = match[1];
        //TODO: validate auth header
        Token.findOne({
            access: token
        }).populate('client')
            .exec(function (err, token) {
                if (err) {
                    log.error(err);
                    res.status(500).send([{
                        code: 500,
                        message: 'Internal Server Error'
                    }]);
                    return;
                }
                if (!token) {
                    res.status(401).send([{
                        code: 401,
                        message: 'Unauthorized'
                    }]);
                    return;
                }
                log.debug('client token expires in : %s', token.accessibility());
                if (token.accessibility() === 0) {
                    res.status(401).send([{
                        code: 401,
                        message: 'Unauthorized'
                    }]);
                    return;
                }
                req.token = token;
                next();
            });
    };
};