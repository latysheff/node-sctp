const EventEmitter = require('events').EventEmitter
const Endpoint = require('./endpoint')
const Socket = require('./sockets')

class Server extends EventEmitter {
  constructor(options, connectionListener) {
    super()
    if (typeof options === 'function') {
      connectionListener = options
      options = {}
    } else {
      options = options || {}
    }

    this.logger = options.logger
    if (this.logger) {
      this.log = (level, ...rest) => {
        this.logger.log(level, 'server -', ...rest)
      }
    } else {
      this.log = () => {
      }
    }
    /*
     allowHalfOpen: false,
     pauseOnConnect: false
     */
    if (typeof connectionListener === 'function') this.on('connection', connectionListener)
    this.listening = false
    // this.maxConnections = 100 // todo
    this.ppid = options.ppid
  }

  address() {
    return {
      port: this.localPort,
      address: this.localAddress,
      family: 'IPv4'
    }
  }

  close(callback) {
    if (!this.listening) return
    this.listening = false
    // todo close connections?
    this.emit('close')
    if (typeof callback === 'function') callback()
  }

  getConnections(callback) {
    // todo
  }

  listen(port, host, backlog, callback) {
    if (typeof port === 'object') {
      let options = port
      callback = host
      this._listen(options, callback)
    } else {
      let options = {port, host, backlog}
      this._listen(options, callback)
    }
  }

  _listen(options, callback) {
    options = options || {}
    let endpoint = Endpoint.INITIALIZE({
      localPort: options.port,
      MIS: options.MIS,
      OS: options.OS
    }, this.logger)
    if (!endpoint) {
      this.emit('error')
      return
    }
    this.localPort = endpoint.localPort
    this.localAddress = endpoint.localAddress
    this._endpoint = endpoint
    if (typeof callback === 'function') this.on('listening', callback)
    endpoint.on('COMMUNICATION UP', (association) => {
      let socket = new Socket({
        ppid: this.ppid
      })
      socket._construct(endpoint, association)
      this.log('debug', 'remote socket connected')
      this.emit('connection', socket)
    })
    this.listening = true
    this.emit('listening')
  }
}


module.exports = Server