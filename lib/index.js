'use strict';

var _ = require('lodash');
var defs = require('./defs');
var sockets = require('./sockets');

var createServer = function (options, connectionListener) {
    return new sockets.Server(options, connectionListener)
};

var listen = function (options, connectListener) {
    var socket = new sockets.Socket(options);
    setTimeout(function () {
        socket.listen(options, connectListener)
    }, 0);
    return socket
};

var connect = function (options, connectListener) {
    var socket = new sockets.Socket(options);
    setTimeout(function () {
        socket.connect(options, connectListener)
    }, 0);
    return socket
};

module.exports.createServer = createServer;
module.exports.listen = listen;
module.exports.connect = connect;
module.exports.Server = sockets.Server;
module.exports.Socket = sockets.Socket;
module.exports.protocol = defs.payload_protocol_identifier;

module.exports.defaults = function (params) {
    _.assign(defs.net_sctp, params);
    if (defs.net_sctp.sack_timeout > 500) defs.net_sctp.sack_timeout = 500;
    if (defs.net_sctp.RWND < 1500) defs.net_sctp.RWND = 1500
};