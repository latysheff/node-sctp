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

function defaults(params) {
  params = params || {}
  for (let param in defs.net_sctp) {
    if (param in params) {
      defs.net_sctp[param] = params[param]
    }
  }
  if (defs.net_sctp.sack_timeout > 500) defs.net_sctp.sack_timeout = 500
  if (defs.net_sctp.RWND < 1500) defs.net_sctp.RWND = 1500
  return defs.net_sctp
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
  defaults
}