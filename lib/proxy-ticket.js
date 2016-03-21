var url = require('url');
var configuration = require('./configure');
var request = require('request');
var _ = require('lodash');
var q = require('q');
var authenticate = require('./authenticate');
var origin = require('./util').origin;

var env = process.env.NODE_ENV || 'development';
var config = require('../../../config/serverConfig')[env];
var utils = require('../../../app/lib/utils');

module.exports = function(options){
    options = _.extend({}, options, configuration());
    if (!options.targetService) throw new Error('no target proxy service specified');

    options.query = options.query || {};
    options.query.targetService = options.targetService;

    return function(req, res, next){
        //S'il n'y a pas de PGT dans la session, on redirige au login CAS
        if (!req.session.pgt) return redirectToLogin(options, req, res);

        //Est-ce que la requête
        //if (req.pt && req.pt[options.targetService]) return next();
        if (req.session.pt) return next();

        options.query.targetService = options.targetService;
        options.query.pgt = req.session.pgt;
        options.pathname = options.paths.proxy;
        request.get(url.format(options), function(err, response, body){
            if (err || res.statusCode !== 200) return redirectToLogin(options, req, res);
            if (/<cas:proxySuccess/.exec(body)) {
                if (/<cas:proxyTicket>(.*)<\/cas:proxyTicket>/.exec(body)){
                    req.pt = req.pt || {};
                    req.pt[options.targetService] = RegExp.$1;
                    req.session.pt = req.pt[options.targetService];
                    if(config.encryption.active){
                        req.session.UEK = utils.generateKey(8);
                    }
                }
            }
            next();
        });
    };
};

function redirectToLogin(options, req, res){
    var senchaUrl = '',
        hostUrl = '',
        casServiceUrl = '',
        casRedirectUrl = '',
        referer;

    options.pathname = options.paths.login;
    options.query = {};
    options.query.service = origin(req);

    // Il y a un header referer et le referer n'est pas CAS
    if (req.headers.referer && req.headers.referer.startsWith(config.appUrl)){
        //Encodage de l'url du service
        if (req.headers['x-route']){
            referer = req.headers['x-route'];
        } else if(req.headers.referer.substr(-1) == '/' && req.headers.referer.length > 1){
            referer = req.headers.referer.slice(0, -1);
        }

        senchaUrl = referer || req.headers.referer;
        hostUrl = (req.headers['x-proxy-request-uri']) ? 'www.usherbrooke.ca' : req.headers['x-forwarded-host'];
        casServiceUrl = encodeURIComponent('https://' + hostUrl + req.headers['x-request-path'] + '/redirection?demandeur=' + senchaUrl);
    
        //Construction de l'url a retourner a l'application pour aller a CAS
        casRedirectUrl = options.protocol + '://' + options.hostname + options.paths.login + '?service=' + casServiceUrl;
        res.header("Access-Control-Allow-Origin", "*");
        res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
        //res.status(307).set('Content-Type', 'application/json').send(JSON.stringify({ success: 'false', loginUrl: casRedirectUrl}));
        res.status(419).set('Content-Type', 'application/json').send(JSON.stringify({ success: false, loginUrl: casRedirectUrl}));
    } else {
        res.redirect(307, url.format(options));
    }
}
