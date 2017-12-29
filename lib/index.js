/*

 RFC 4960 "Stream Control Transmission Protocol"

*/

const defs = require('./defs')
const Socket = require('./sockets')
const Server = require('./socketserver')

function createServer(options, connectionListener) {
  return new Server(options, connectionListener)
}

function listen(options, connectListener) {
  let socket = new Socket(options)
  options.listen = true
  setTimeout(function () {
    socket.connect(options, connectListener)
  }, 0)
  return socket
}

function connect(options, connectListener) {
  let socket = new Socket(options)
  setTimeout(function () {
    socket.connect(options, connectListener)
  }, 0)
  return socket
}

/*
 module.exports.net_sctp = function (params) {
 Object.assign(defs.net_sctp, params)
 if (defs.net_sctp.sack_timeout > 500) defs.net_sctp.sack_timeout = 500
 if (defs.net_sctp.RWND < 1500) defs.net_sctp.RWND = 1500
 }
 */

function SCTP_RTOINFO(params) {
  defs.net_sctp.rto_initial = params.rto_initial || defs.net_sctp.rto_initial
  defs.net_sctp.rto_min = params.rto_min || defs.net_sctp.rto_min
  defs.net_sctp.rto_max = params.rto_max || defs.net_sctp.rto_max
}


module.exports = {
  createServer,
  listen,
  connect,
  createConnection: connect,
  Socket,
  Server,
  PPID: defs.PPID,
  protocol: defs.PPID,
  SCTP_RTOINFO
}