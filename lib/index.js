/*

 RFC 4960 "Stream Control Transmission Protocol"
 https://tools.ietf.org/html/rfc4960

*/

const defs = require('./defs')
const sockets = require('./sockets')
const Socket = sockets.Socket
const Server = sockets.Server
const transport = require('./transport')

function createServer(options, connectionListener) {
  return new Server(options, connectionListener)
}

function connect(options, connectListener) {
  let socket = new Socket(options)
  socket.connect(options, connectListener)
  return socket
}

function defaults(params) {
  params = params || {}
  for (let param in defs.net_sctp) {
    if (param in params) {
      // todo validate all
      defs.net_sctp[param] = params[param]
    }
  }
  if (defs.net_sctp.sack_timeout > 500) defs.net_sctp.sack_timeout = 500
  if (defs.net_sctp.RWND < 1500) defs.net_sctp.RWND = 1500
  return defs.net_sctp
}

module.exports = {
  createServer,
  connect,
  createConnection: connect,
  Socket,
  Server,
  PPID: defs.PPID,
  protocol: defs.PPID,
  defaults,
  raw: transport.raw,
  setLogger: transport.setLogger,
}
