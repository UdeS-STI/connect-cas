var origin = require('./util').origin;
var url = require('url');
var _ = require('lodash');
var env = process.env.NODE_ENV || 'development';
var config = require('../../../config/serverConfig')[env];

module.exports = function(overrides){
    var configuration = require('./configure')();
    var options = _.extend({}, overrides, configuration);
    return function(req, res, next){
        if (req.session && req.session.pt){
            // S'il y a une session et un pt on ajoute la clé de cryptage pour le xor dans un cookie, bête obfuscation
            if(config.encryption.active){
                res.cookie('UEK', req.session.UEK, { expires: config.encryption.keyLifetime });
            }
            // refresh the expiration if ssout
            if (req.ssout) {
                req.sessionStore.set(req.session.pt, req.session.id);
            }
            next();
            return;
        }
        options.pathname = options.paths.login;
        options.query = options.query || {};
        options.query.service = origin(req);

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
       // res.redirect(307, url.format(options));
    };
};
