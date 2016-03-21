var qs = require('querystring');
var url = require("url");
module.exports.origin = function(req){
    var query = req.query;
    if (query.ticket) delete query.ticket;
    var querystring = qs.stringify(query);
    var hostUrl = (req.headers['x-proxy-request-uri']) ? 'www.usherbrooke.ca' : req.headers['x-forwarded-host'];
    return 'https://' + hostUrl + req.get('x-request-path') + req.path + (querystring ? '?' + querystring : '');
};