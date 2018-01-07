/*

 RFC 6458
 Sockets API Extensions for the Stream Control Transmission Protocol (SCTP)

 */

const Duplex = require('stream').Duplex
const EventEmitter = require('events').EventEmitter
const ip = require('ip')
const Endpoint = require('./endpoint')

class Socket extends Duplex {
  constructor(options) {
    super(options)
    options = options || {}

    this.logger = options.logger
    if (this.logger && (typeof this.logger.log === 'function')) {
      this.log = (level, ...rest) => {
        this.logger.log(level, 'socket -', ...rest)
      }
    } else {
      this.log = () => {
      }
    }

    this.log('debug', 'start SCTP socket')
    this.writeBuffer = []
    this.sctp_sndrcvinfo = {
      stream: 0,
      unordered: false,
      no_bundle: false,
      protocol: options.protocol
    }

  }

  address() {
    return {
      port: this.localPort,
      address: this.localAddress,
      family: 'IPv4'
    }
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

     sctp_paddrparams
     */
    if (this.p2p) return
    this.p2p = true

    if (typeof options !== 'object') {
      throw new Error('options required')
    }
    this.log('debug', 'connect', options)

    let assocOptions = {
      streams: 1 // TODO: ?
    }
    assocOptions.remotePort = ~~options.port
    if (!assocOptions.remotePort) {
      throw new Error('port is required')
    }
    assocOptions.remoteAddress = options.host || '127.0.0.1'

    // todo multi
    let initOptions = {
      MIS: options.MIS,
      OS: options.OS
    }

    initOptions.localAddress = toarray(options.localAddress)

    if (options.localPort && ~~options.localPort) {
      initOptions.localPort = ~~options.localPort
    }

    this.log('debug', 'init & assoc options', initOptions, assocOptions)

    let endpoint = Endpoint.INITIALIZE(initOptions, this.logger)
    if (!endpoint) {
      this.emit('error', new Error('unable to allocate port ' + initOptions.localPort))
    }

    if (typeof connectListener === 'function') {
      this.on('connect', connectListener)
    }

    if (options.listen) {
      // associate & reject
      // TODO: consider abort immediately
      endpoint.on('COMMUNICATION UP', (association) => {
        if (association.remotePort === this.port && association.remoteAddress === this.host) {
          this.log('trace', 'remote peer2peer socket connected')
          this._construct(endpoint, association)
          this.emit('connect')
        } else {
          this.log('warn', 'remote peer2peer socket rejected port', association.remotePort)
          association.ABORT()
        }
      })
    } else {
      let association = endpoint.ASSOCIATE(assocOptions)
      // TODO: error on ASSOCIATE problems
      this._construct(endpoint, association)
    }
  }

  _final(callback) {
    // called by end()
    if (this._association) {
      this._association.SHUTDOWN(callback)
    }
  }


  // https://linux.die.net/man/7/sctp

  /*
   *   This option is used to both examine and set various association and
   *   endpoint parameters.
   struct sctp_assocparams {
   sctp_assoc_t    sasoc_assoc_id;
   __u16           sasoc_asocmaxrxt;
   __u16           sasoc_number_peer_destinations;
   __u32           sasoc_peer_rwnd;
   __u32           sasoc_local_rwnd;
   __u32           sasoc_cookie_life;
   };
   */

  SCTP_ASSOCINFO(options) {
    const params = ['valid_cookie_life']
    let endpoint = this._endpoint
    if (endpoint && typeof options === 'object') {
      params.forEach((key) => {
        if (options.hasOwnProperty(key)) {
          endpoint[key] = options[key]
        }
      })
    }
  }

  SCTP_DEFAULT_SEND_PARAM(params) {
    // should be assoc params
    for (let param in this.sctp_sndrcvinfo) {
      if (param in params) {
        this.sctp_sndrcvinfo[param] = params[param]
      }
    }
  }

  _construct(endpoint, association) {
    // todo
    this.destroyed = false
    this.connecting = false
    this.bufferSize = 0 // this.writeBuffer.length
    this.bytesRead = 0
    this.bytesWritten = 0

    this._endpoint = endpoint
    this.localPort = endpoint.localPort
    this.localAddress = endpoint.localAddress

    this._association = association
    this.remotePort = association.remotePort
    this.remoteAddress = association.remoteAddress
    this.remoteFamily = 'IPv4'

    association.on('COMMUNICATION UP', () => {
      this.emit('connect')
      this.log('info', 'socket connected')
    })

    association.on('DATA ARRIVE', (stream_id) => {
      let buffer = association.RECEIVE(stream_id)
      if (buffer) {
        this.log('debug', '< DATA ARRIVE', buffer.length, buffer)
        this.push(buffer)
      }
    })

    association.on('SHUTDOWN COMPLETE', () => {
      this.log('debug', 'socket ended')
      if (this.p2p) {
        endpoint.DESTROY()
      }
      this.emit('end')
    })

    association.on('COMMUNICATION LOST', (event, reason) => {
      this.log('info', 'COMMUNICATION LOST', event, reason)
      if (this.p2p) {
        endpoint.DESTROY()
      }
      this.emit('close')
    })

    association.on('COMMUNICATION ERROR', () => {
      this.emit('error')
    })
  }

  _read(size) {
    // this function means that socket wants to get more data
  }

  _write(chunk, options, callback) {
    let association = this._association
    this.log('debug', '> write', this.sctp_sndrcvinfo, chunk)
    if (association) {
      association.SEND(chunk, this.sctp_sndrcvinfo, callback)
    } else {
      callback(new Error('no association established'))
    }
  }

  _destroy(err, callback) {
    // todo
    this.log('fatal', 'destroy')
    this._association.ABORT(err)
    callback()
  }

}

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
      localAddress: toarray(options.host),
      MIS: options.MIS,
      OS: options.OS
    }, this.logger)
    if (!endpoint) {
      this.emit('error')
      return
    }
    this.localPort = endpoint.localPort
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

function toarray(address) {
  let addresses = Array.isArray(address) ? address : [address]
  addresses = addresses
    .filter((address) => ip.isV4Format(address))
  return addresses
}


module.exports = {
  Socket,
  Server,
}
