module.exports = function (token, options) {
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
        var auth = req.headers['authorization'];
        if (!auth) {
            res.send(401, {
                error: 'missing authorization header'
            });
            return;
        }
        var match = /^\s*Bearer\s+(.*)$/g.exec(auth);
        if (!match) {
            res.send(401, {
                error: 'invalid authorization header'
            });
            return;
        }
        token(match[1], function (err, token) {
            if (err) {
                res.send(500, {
                    error: err
                });
                return;
            }
            if (!token) {
                res.send(401, {
                    error: 'invalid token'
                });
                return;
            }
            req.token = token;
            next();
        });
    };
};