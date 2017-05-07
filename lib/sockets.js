'use strict';

// https://tools.ietf.org/html/rfc6458

var _ = require('lodash');
var util = require('util');
var net = require('net');
var EventEmitter = require('events').EventEmitter;
var Duplex = require('stream').Duplex;

var sctp = require('./protocol');



class Socket extends Duplex {
    constructor(options) {
        super(options);
        options = options || {};
        this.writeBuffer = [];
        this.protocol = options.protocol
    }

    address() {
        return {
            port: this._localPort,
            address: this._localAddress,
            family: 'IPv4'
        }
    }

    listen(options, connectListener) {
        if (this.p2p) return;
        var socket = this;
        this.p2p = true;
        options = options || {};
        if (options.host) {
            if (net.isIP(options.host)) {
                this.host = options.host
            } else {
                this.emit('error', new Error(util.format('host "%s" must be an ip address', options.host)))
                return
            }
        } else {
            this.host = '127.0.0.1';
        }
        if (_.isNumber(options.port)) {
            this.port = options.port
        } else {
            this.emit('error', new Error(util.format('port "%s" is invalid', options.host)))
            return
        }

        if (_.isFunction(connectListener)) this.on('connect', connectListener)

        var endpoint = sctp.INITIALIZE({
            localPort: options.localPort,
            MIS: options.MIS,
            OS: options.OS
        });
        if (!endpoint) {
            this.emit('error', new Error(util.format('local port in use %d', options.localPort)))
        }

        // associate & reject
        endpoint.on('COMMUNICATION UP', function (association) {
            if (association.remotePort == socket.port && association.remoteAddress == socket.host) {
                socket._construct(endpoint, association);
                socket.emit('connect')
            } else {
                association.ABORT()
            }
        })
    }

    connect(options, connectListener) {
        /*
         port: Port the client should connect to (Required).
         host: Host the client should connect to. Defaults to 'localhost'.
         localAddress: Local interface to bind to for network connections.
         localPort: Local port to bind to for network connections.
         family : Version of IP stack. Defaults to 4.
         hints: dns.lookup() hints. Defaults to 0.
         lookup : Custom lookup function. Defaults to dns.lookup.
         */
        if (this.p2p) return;
        this.p2p = true;
        options = options || {};
        options.host = options.host || '127.0.0.1';
        if (!options.port) {
            this.emit('error', new Error(util.format('connect EADDRNOTAVAIL %s', options.host)))
        }

        if (_.isFunction(connectListener)) {
            this.on('connect', connectListener)
        }

        var endpoint = sctp.INITIALIZE({
            localPort: options.localPort,
            MIS: options.MIS,
            OS: options.OS
        });
        if (!endpoint) {
            this.emit('error', new Error(util.format('local port in use %s', options.localPort)))
        }

        var association = endpoint.ASSOCIATE({
                remotePort: options.port,
                remoteAddress: options.host,
                streams: 1
            }
        );

        this._construct(endpoint, association)
    }

    destroy() {
        this._association.ABORT();
        super.end()
    }

    end() {
        if (this._ending) return;
        this._ending = true;
        var end = super.end;
        this._association.SHUTDOWN(function () {
        })
    }

    setEncoding() {

    }

    setKeepAlive() {

    }

    setNoDelay() {

    }

    setTimeout() {

    }

    /*
     Event: 'close'
     Event: 'connect'
     Event: 'data'
     Event: 'drain'
     Event: 'end'
     Event: 'error'
     Event: 'lookup'
     Event: 'timeout'
     */

    setWriteOptions(options) {
        this._writeOptions = options;
    }

    _construct(endpoint, association) {
        var socket = this;

        this._endpoint = endpoint;
        this._localPort = endpoint.localPort;
        this._localAddress = endpoint.localAddress;

        this._association = association;
        this._remotePort = association.remotePort;
        this._remoteAddress = association.remoteAddress;

        association.on('COMMUNICATION UP', function () {
            socket.emit('connect');
        });

        association.on('DATA ARRIVE', function (stream_id) {
            var buffer = association.RECEIVE(stream_id);
            if (buffer) {
                socket.push(buffer)
            }
        });

        association.on('SHUTDOWN COMPLETE', function () {
            if (socket.p2p) {
                endpoint.DESTROY()
            }
            socket.emit('end')
        });

        association.on('COMMUNICATION LOST', function (event, reason) {
            if (socket.p2p) {
                endpoint.DESTROY()
            }
            socket.emit('close')
        });

        association.on('COMMUNICATION ERROR', function () {
            socket.emit('error')
        })
    }

    // ----------- stream internal methods

    _read(size) {
        // this function means that socket wants to get more data
    }

    _write(chunk, options, callback) {
        var socket = this;
        var association = this._association;
        association.SEND(chunk, this._writeOptions, callback)
    }

}

Object.defineProperty(Socket.prototype, 'bufferSize', {
    enumerable: true,
    get: function () {
        return this.writeBuffer.length
    }
});

Object.defineProperty(Socket.prototype, 'bytesRead', {
    enumerable: true,
    get: function () {
        return 0
    }
});

Object.defineProperty(Socket.prototype, 'bytesWritten', {
    enumerable: true,
    get: function () {
        return 0
    }
});

Object.defineProperty(Socket.prototype, 'connecting', {
    enumerable: true,
    get: function () {
        return false
    }
});

Object.defineProperty(Socket.prototype, 'destroyed', {
    enumerable: true,
    get: function () {
        return false
    }
});

Object.defineProperty(Socket.prototype, 'localAddress', {
    enumerable: true,
    get: function () {
        return this._localAddress
    }
});

Object.defineProperty(Socket.prototype, 'localPort', {
    enumerable: true,
    get: function () {
        return this._localPort
    }
});

Object.defineProperty(Socket.prototype, 'remoteAddress', {
    enumerable: true,
    get: function () {
        return this._remoteAddress
    }
});

Object.defineProperty(Socket.prototype, 'remoteFamily', {
    enumerable: true,
    get: function () {
        return 'IPv4'
    }
});

Object.defineProperty(Socket.prototype, 'remotePort', {
    enumerable: true,
    get: function () {
        return this._remotePort
    }
});


class Server extends EventEmitter {

    constructor(options, connectionListener) {
        super();

        /*
         allowHalfOpen: false,
         pauseOnConnect: false
         */
        if (_.isFunction(connectionListener)) this.on('connection', connectionListener)
        this._listening = false
    }

    /*
     Event: 'close'
     Event: 'connection'
     Event: 'error'
     Event: 'listening'
     */

    address() {
        return {
            port: this._localPort,
            address: this._localAddress,
            family: 'IPv4'
        }
    }

    close(callback) {
        if (!this._listening) return;
        this._listening = false;
        _.each(this._endpoint.associations, function (association) {
            association.SHUTDOWN()
        });
        this.emit('close');
        if (_.isFunction(callback)) {
            callback()
        }
    }

    getConnections(callback) {
        if (_.isFunction(callback)) {
            callback(null, this._endpoint.associations.length)
        }
    }

    listen(options, callback) {
        /*port <number> - Optional.
         host <string> - Optional.
         backlog <number> - Optional.
         path <string> - Optional.
         exclusive <boolean> - Optional.
         */
        options = options || {};
        var server = this;

        var endpoint = new sctp.INITIALIZE({
            localPort: options.port,
            MIS: options.MIS,
            OS: options.OS
        });
        if (!endpoint) {
            server.emit('error');
            return
        }

        this._localPort = endpoint.localPort;
        this._localAddress = endpoint.localAddress;
        this._endpoint = endpoint;

        if (_.isFunction(callback)) {
            this.on('listening', callback)
        }

        endpoint.on('COMMUNICATION UP', function (association) {
            var socket = new Socket({});
            socket._construct(endpoint, association);
            server.emit('connection', socket)
        });

        this._listening = true;
        this.emit('listening')
    }

}

Object.defineProperty(Server.prototype, 'listening', {
    enumerable: true,
    get: function () {
        return (this._listening)
    }
});

Object.defineProperty(Server.prototype, 'maxConnections', {
    enumerable: true,
    set: function (maxConnections) {
        this._maxConnections = maxConnections
    }
});


module.exports.Server = Server;
module.exports.Socket = Socket;
