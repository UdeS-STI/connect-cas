var url = require('url');
var configuration = require('./configure');
var request = require('request');
var _ = require('lodash');
var q = require('q');
var authenticate = require('./authenticate');
var origin = require('./util').origin;

module.exports = function(options){
    options = _.extend({}, options, configuration());
    if (!options.targetService) throw new Error('no target proxy service specified');

    options.pathname = options.paths.proxy;
    options.query = options.query || {};
    options.query.targetService = options.targetService;

    return function(req, res, next){
        if (!req.session.pgt) return redirectToLogin(options, req, res);

        options.query.pgt = req.session.pgt;

        req.session.withProxyTicket = function(withPT){
            options.pathname = options.paths.proxy;
            options.query = options.query || {};
            options.query.targetService = options.targetService;

            request.get({uri: url.format(options), strictSSL: options.strictSSL}, function(err, res, body){
                if (err || res.statusCode !== 200) return redirectToLogin(options, req, res);
                    if (/<cas:proxySuccess/.exec(body)) {
                        if (/<cas:proxyTicket>(.*)<\/cas:proxyTicket>/.exec(body)){
                            req.pt = req.pt || {};
                            var pt= RegExp.$1;
                            withPT(pt);
                        }else{
                            withPT(null);
                        }
                    }else{
                        withPT(null);
                    }
                    
                });
        };
        next();
    };
};
function redirectToLogin(options, req, res){
    options.pathname = options.paths.login;
    options.query = {};
    options.query.service = origin(req);
    //var casRedirectUrl = options.protocol + '://' + options.hostname + options.paths.login + '?service=' + req.headers.referer;
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    //res.send(200, JSON.stringify({ success: 'false', loginUrl: casRedirectUrl}));
    res.redirect(307, url.format(options));
}