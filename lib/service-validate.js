var origin = require('./util').origin;
var _ = require('lodash');
var parseUrl = require('url').parse;
var formatUrl = require('url').format;
var request = require('request');
var xml2js = require('xml2js').parseString;
var stripPrefix = require('xml2js/lib/processors').stripPrefix;

var env = process.env.NODE_ENV || 'development';
var config = require('../../../config/serverConfig')[env];

module.exports = function (overrides) {
    var configuration = require('./configure')();
    var options = _.extend({}, overrides, configuration);

    var pgtPathname = '/pgtCallback'; //pgtPath(options); //

    return function(req,res,next){
        if (!options.host && !options.hostname) throw new Error('no CAS host specified');
        if (options.pgtFn && !options.pgtUrl) throw new Error('pgtUrl must be specified for obtaining proxy tickets');

        if (!req.session){
            res.status(503).end();
            return;
        }

        var url = parseUrl(req.url, true);
        var ticket = (url.query && url.query.ticket) ? url.query.ticket : null;

        options.query = options.query || {};
        options.query.service = origin(req);
        options.query.ticket = ticket;
        options.pathname = options.paths.serviceValidate;

        if (options.pgtUrl || options.query.pgtUrl){
           //options.query.pgtUrl = pgtPathname ? 'https://' + req.get('host') + pgtPathname : options.pgtUrl;
           options.query.pgtUrl = options.pgtUrl; //belj1822
        }

        //Write pgtid sur couchbase pour être lu plus tard
        if (pgtPathname && req.path === pgtPathname && req.method === 'GET') {
            if (!req.query.pgtIou || !req.query.pgtId) {
                return res.status(200).end();
            }
            req.sessionStore.set(req.query.pgtIou, _.extend(req.session, {pgtId: req.query.pgtId}));
            return res.status(200).end();
        }

        //S'il n'y a pas de ticket dans l'url on va au prochain middleware, proxyTicket
        if (!ticket){
            next();
            return;
        }

        //Si on utilise les session store, oui
        if (req.sessionStore) {
            //Il y a un ticket dans l'url alors on regarde si nous avons déjà validé ce ticket et il est dans couchbase
            req.sessionStore.get(req.sessionID.toString(), function (err, storedSession) {
                //Déjà validé
                if (storedSession && storedSession.pt && (storedSession.pt === ticket)) {
                    return next();
                } else {                
                //Sinon on valide le ticket au près de CAS 
                    validateService(res, formatUrl(options), function (casBody) {
                        validateCasResponse(req, res, ticket, casBody, options, next);
                    });
                }
            });
        //Cookie session, fallback si pas de session store
        } else {
            validateService(res, formatUrl(options), function (casBody) {
                validateCasResponse(req, res, ticket, casBody, options, next);
            });
        }

    };
};

function validateService(res, url, callback) {
    request.get(url, function(casErr, casRes, casBody){
        if (casErr || casRes.statusCode !== 200){
            res.status(403).end();
            return;
        }
        callback(casBody);
    });
}

function validateCasResponse(req, res, ticket, casBody, options, next) {
    xml2js(casBody, {explicitRoot: false, tagNameProcessors: [stripPrefix]}, function(err, serviceResponse) {
        if (err) {
            console.error('Failed to parse CAS server response. (' + err.message + ')');
            res.status(500).end();
            return;
        }

        var success = serviceResponse && serviceResponse.authenticationSuccess && serviceResponse.authenticationSuccess[0],
            user = success && success.user && success.user[0],
            pgtIou = success && success.proxyGrantingTicket && success.proxyGrantingTicket[0];

        if (!serviceResponse) {
            console.error('Invalid CAS server response.');
            res.status(500).end();
            return;
        }

        if (!success) {
            next();
            return;
        }

        req.session.st = ticket;
        if (req.ssoff) {
            req.sessionStore.set(ticket, {sid: req.sessionID});
        }

        req.session.cas = {};
        for (var casProperty in success){
            req.session.cas[casProperty] = success[casProperty][0];
        }

        if (!pgtIou) {
            next();
            return;
        }

        if (options.pgtFn) {
            options.pgtFn.call(null, pgtIou, function(err, pgt){
                if (err) return res.status(502).end();
                req.session.pgt = pgt;
                next();
            });
            return;
        }
        retrievePGTFromPGTIOU(req, pgtIou, next);
    });
}

function retrievePGTFromPGTIOU(req, pgtIou, cb) {
    req.sessionStore.get(pgtIou, function(err, session){
        if (err){
            console.log(err);
        }else if(session && session.pgtId) {
            req.session.pgt = session.pgtId;
        }
        cb();
    });
}

// returns false or the relative pathname to handle
function pgtPath(options){
    var pgtUrl = parseUrl(options.pgtUrl || (options.query ?  options.query.pgtUrl : ''));
    if (pgtUrl.protocol === 'http:') throw new Error('callback must be secured with https');
    if (pgtUrl.protocol && pgtUrl.host && options.pgtFn) return false;
    return pgtUrl.pathname;
}