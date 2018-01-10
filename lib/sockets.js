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
    this.allowHalfOpen = options.allowHalfOpen // todo
    this.udpTransport = options.udpTransport

    this.logger = options.logger
    if (this.logger && (typeof this.logger.log === 'function')) {
      this.log = (level, ...rest) => {
        this.logger.log(level, 'socket -', ...rest)
      }
    } else {
      this.log = () => {
      }
    }

    this.log('debug', 'starting socket')
    this.writeBuffer = []
    this.sctp_sndrcvinfo = {
      stream: 0,
      unordered: false,
      no_bundle: false,
      protocol: options.protocol
    }
  }

  _read(size) {
    // this function means that socket wants to get more data
  }

  _write(chunk, options, callback) {
    this.log('debug', '> write', this.sctp_sndrcvinfo, chunk)
    if (this.association) {
      this.association.SEND(chunk, this.sctp_sndrcvinfo, callback)
    } else {
      // todo
      callback(new Error('no association established'))
    }
  }

  // todo
  // _writev(chunks, callback){
  //   // If implemented, the method will be called with all chunks of data currently buffered in the write queue
  //   // Each chunk has following format: { chunk: ..., encoding: ... }
  // }

  _final(callback) {
    // This optional function will be called before the stream closes, delaying the 'finish' event until callback is called.
    // This is useful to close resources or write buffered data before a stream ends.
    // called by end()
    if (this.association) {
      this.association.SHUTDOWN(callback)
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
     */

    if (this.outbound) return
    this.outbound = true

    if (typeof options !== 'object') {
      options = {port: options}
    }

    this.passive = !!options.passive

    options.port = ~~options.port
    if (options.port > 0 && options.port < 0xffff) {
      this.remotePort = options.port
    } else {
      throw new Error('port is required')
    }

    this.remoteAddress = options.host || null
    if (!this.remoteAddress && !this.passive)
      this.remoteAddress = 'localhost' // do not set default host in passive mode, let user decide who may connect

    this.localPort = (~~options.localPort) || null
    this.localAddress = toarray(options.localAddress)

    if (this.udpTransport) {
      this.localAddress = undefined
      this.remoteAddress = undefined
    }

    this.log('info', 'connect()', this.localPort, '->', this.remoteAddress, this.remotePort)

    if (typeof connectListener === 'function') {
      this.once('connect', connectListener)
    }

    let assocOptions = {
      streams: 1, // todo
      remoteAddress: this.remoteAddress,
      remotePort: this.remotePort,
    }

    let initOptions = {
      localAddress: this.localAddress,
      localPort: this.localPort,
      MIS: options.MIS,
      OS: options.OS,
      udpTransport: this.udpTransport,
      logger: this.logger
    }

    Endpoint.INITIALIZE(initOptions, (error, endpoint) => {
      if (error) {
        this.emit('error', new Error('bind EADDRINUSE 0.0.0.0:' + initOptions.localPort))
      } else {
        if (this.passive) {
          endpoint.on('COMMUNICATION UP', (association) => {
            this.log('trace', 'COMMUNICATION UP', association.remotePort, this.remotePort, association.remoteAddress, this.remoteAddress)
            if (association.remotePort === this.remotePort && association.remoteAddress === this.remoteAddress) {
              this.log('trace', 'passive socket connected')
              this._construct(endpoint, association)
              this.emit('connect', this)
            } else {
              // todo abort immediately or even ignore
              this.log('warn', 'remote passive socket rejected port', association.remotePort)
              association.ABORT()
            }
          })
        } else {
          let association = endpoint.ASSOCIATE(assocOptions)
          // TODO: error on ASSOCIATE problems, and better callback mode
          this._construct(endpoint, association)
        }
      }
    })
  }

  _construct(endpoint, association) {
    this.destroyed = false
    this.connecting = false
    this.bufferSize = 0 // todo getter of this.writeBuffer.length
    this.bytesRead = 0 // todo
    this.bytesWritten = 0 // todo

    this.endpoint = endpoint
    this.localPort = endpoint.localPort
    this.localAddress = endpoint.localAddress

    this.association = association
    this.remoteAddress = association.remoteAddress
    this.remoteFamily = 'IPv4' // todo implement ipv6

    association.on('COMMUNICATION UP', () => {
      this.emit('connect')
      this.log('info', 'socket connected')
    })

    association.on('DATA ARRIVE', (stream_id) => {
      let buffer = association.RECEIVE(stream_id)
      if (buffer) {
        this.log('info', '< DATA ARRIVE on stream', stream_id, buffer.length, buffer)
        this.push(buffer)
      }
    })

    association.on('SHUTDOWN COMPLETE', () => {
      this.log('debug', 'socket ended')
      if (this.outbound) {
        endpoint.DESTROY()
      }
      this.emit('end')
    })

    association.on('COMMUNICATION LOST', (event, reason) => {
      this.log('info', 'COMMUNICATION LOST', event, reason)
      if (this.outbound) {
        endpoint.DESTROY()
      }
      this.emit('close')
    })

    association.on('COMMUNICATION ERROR', () => {
      this.emit('error')
    })
  }

  // end(data, encoding) {
  //   // TCP: Half-closes the socket. i.e., it sends a FIN packet. It is possible the server will still send some data.
  //   // SCTP does not support a half-open state (like TCP) wherein one side may continue sending data while the other end is closed.
  //
  //   // If data is specified, it is equivalent to calling socket.write(data, encoding) followed by socket.end().
  //   if (data) {
  //     this.write(data, encoding)
  //   }
  //   // todo
  //   this.association
  //   return this
  // }

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
    let endpoint = this.endpoint
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


  /*
  destroy(exception)

  Streams:
  Destroy the stream, and emit the passed error. After this call, the writable stream has ended.
  Implementors should not override this method, but instead implement writable._destroy.

  Net:
  Ensures that no more I/O activity happens on this socket. Only necessary in case of errors (parse error or so).
  If exception is specified, an 'error' event will be emitted and any listeners for that event will receive exception as an argument.
  */

  _destroy(err, callback) {
    // err <Error> A possible error.
    // callback <Function> A callback function that takes an optional error argument.
    this.log('fatal', 'destroy()')

    // this.destroyed
    // A Boolean value that indicates if the connection is destroyed or not. Once a connection is destroyed no further data can be transferred using it.
    // setTimeout(() => {
    this.association.ABORT() // todo
    if (this.outbound) {
      this.endpoint.DESTROY()
    }
    // }, 100)
    callback(err)
    return this
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

    if (typeof connectionListener === 'function') {
      this.on('connection', connectionListener)
    }

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

    let initOptions = {
      localPort: options.port,
      localAddress: toarray(options.host),
      MIS: options.MIS,
      OS: options.OS,
      logger: this.logger
    }
    Endpoint.INITIALIZE(initOptions, (error, endpoint) => {
      if (error) {
        this.emit('error')
      } else {
        this.localPort = endpoint.localPort
        this.endpoint = endpoint

        if (typeof callback === 'function') {
          this.once('listening', callback)
        }

        endpoint.on('COMMUNICATION UP', (association) => {
          let socket = new Socket({
            ppid: this.ppid,
            logger: this.logger
          })
          socket._construct(endpoint, association)
          this.log('debug', 'remote socket connected')
          this.emit('connection', socket)
        })
        this.listening = true
        this.emit('listening')
      }
    })
  }
}

function toarray(address) {
  if (!address) return
  let addresses = Array.isArray(address) ? address : [address]
  addresses = addresses
    .filter((address) => ip.isV4Format(address))
  return addresses
}


module.exports = {
  Socket,
  Server,
}
