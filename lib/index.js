/*

 RFC 4960 "Stream Control Transmission Protocol"
 https://tools.ietf.org/html/rfc4960

*/

const defs = require('./defs')
const sockets = require('./sockets')
const Reassembly = require('./reassembly')
const Packet = require('./packet')
const Chunk = require('./chunk')

const Socket = sockets.Socket
const Server = sockets.Server

function createServer(options, connectionListener) {
  return new Server(options, connectionListener)
}

function connect(options, connectListener) {
  const socket = new Socket(options)
  socket.connect(options, connectListener)
  return socket
}

function defaults(params) {
  params = params || {}
  for (const param in defs.NET_SCTP) {
    if (param in params) {
      // Todo validate all
      defs.NET_SCTP[param] = params[param]
    }
  }
  if (defs.NET_SCTP.sack_timeout > 500) {
    defs.NET_SCTP.sack_timeout = 500
  }
  if (defs.NET_SCTP.RWND < 1500) {
    defs.NET_SCTP.RWND = 1500
  }
  return defs.NET_SCTP
}

module.exports = {
  createServer,
  connect,
  createConnection: connect,
  Socket,
  Server,
  Reassembly,
  Packet,
  Chunk,
  PPID: defs.PPID,
  defaults
}
