/*

 RFC 6458
 Sockets API Extensions for the Stream Control Transmission Protocol (SCTP)

 */

const Duplex = require('stream').Duplex
const EventEmitter = require('events').EventEmitter
const debug = require('debug')
const ip = require('ip')
const Endpoint = require('./endpoint')

class Socket extends Duplex {
  constructor(options) {
    super(options)
    options = options || {}
    this.allowHalfOpen = options.allowHalfOpen // Todo
    this.udpTransport = options.udpTransport

    this.debugger = {}
    this.debugger.info = debug('sctp:socket:##')
    this.debugger.info('starting socket %o', options)

    this.writeBuffer = []
    this.sctp_sndrcvinfo = {
      stream: 0,
      unordered: false,
      no_bundle: false,
      protocol: options.protocol
    }
  }

  _read() {
    // This function means that socket wants to get more data
    // should exist even if empty
  }

  _write(chunk, options, callback) {
    this.debugger.debug('> write %o', this.sctp_sndrcvinfo, chunk)
    if (this.association) {
      this.association.SEND(chunk, this.sctp_sndrcvinfo, callback)
    } else {
      // Todo
      callback(new Error('no association established'))
    }
  }

  _final(callback) {
    /*
    This optional function will be called before the stream closes,
    delaying the 'finish' event until callback is called.
    This is useful to close resources or write buffered data
    before a stream ends.
    */
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
     Port: Port the client should connect to (Required).
     host: Host the client should connect to. Defaults to 'localhost'.
     localAddress: Local interface to bind to for network connections.
     localPort: Local port to bind to for network connections.
     family : Version of IP stack. Defaults to 4.
     hints: dns.lookup() hints. Defaults to 0.
     lookup : Custom lookup function. Defaults to dns.lookup.
     */

    if (this.outbound) {
      return
    }
    this.outbound = true

    if (typeof options !== 'object') {
      options = {port: options}
    }

    this.passive = Boolean(options.passive)

    options.port = ~~options.port
    if (options.port > 0 && options.port < 0xFFFF) {
      this.remotePort = options.port
    } else {
      throw new Error('port is required')
    }

    this.remoteAddress = options.host || null
    // Do not set default host in passive mode, let user decide who may connect
    if (!this.remoteAddress && !this.passive) {
      this.remoteAddress = 'localhost'
    }

    this.localPort = ~~options.localPort || null
    this.localAddress = toarray(options.localAddress)

    if (this.udpTransport) {
      this.localAddress = undefined
      this.remoteAddress = undefined
    }

    this.debugger.info(
      'connect(%d -> %s:%d)',
      this.localPort,
      this.remoteAddress,
      this.remotePort
    )

    if (typeof connectListener === 'function') {
      this.once('connect', connectListener)
    }

    const assocOptions = {
      streams: 1, // Todo
      remoteAddress: this.remoteAddress,
      remotePort: this.remotePort
    }

    const initOptions = {
      localAddress: this.localAddress,
      localPort: this.localPort,
      MIS: options.MIS,
      OS: options.OS,
      udpTransport: this.udpTransport
    }

    Endpoint.INITIALIZE(initOptions, (error, endpoint) => {
      if (error) {
        this.emit(
          'error',
          new Error('bind EADDRINUSE 0.0.0.0:' + initOptions.localPort)
        )
      } else if (this.passive) {
        endpoint.on('COMMUNICATION UP', association => {
          this.debugger.info(
            'associated with %s:%d',
            association.remoteAddress,
            association.remotePort
          )
          if (
            association.remotePort === this.remotePort &&
            association.remoteAddress === this.remoteAddress
          ) {
            this.debugger.info('passive socket connected')
            this._construct(endpoint, association)
            this.emit('connect', this)
          } else {
            // Todo abort immediately or even ignore
            this.debugger.info(
              'passive socket deny connect from %d',
              association.remotePort
            )
            association.ABORT()
          }
        })
      } else {
        const association = endpoint.ASSOCIATE(assocOptions)
        // TODO: error on ASSOCIATE problems, and better callback mode
        this._construct(endpoint, association)
      }
    })
  }

  _construct(endpoint, association) {
    this.destroyed = false
    this.connecting = false
    this.bufferSize = 0 // Todo getter of this.writeBuffer.length
    this.bytesRead = 0 // Todo
    this.bytesWritten = 0 // Todo

    this.endpoint = endpoint
    this.localPort = endpoint.localPort
    this.localAddress = endpoint.localAddress

    this.association = association
    this.remoteAddress = association.remoteAddress
    this.remotePort = association.remotePort
    this.remoteFamily = 'IPv4'

    const label = `${this.localPort}/${this.remoteAddress}:${this.remotePort}`
    this.debugger.warn = debug(`sctp:socket:### ${label}`)
    this.debugger.info = debug(`sctp:socket:## ${label}`)
    this.debugger.debug = debug(`sctp:socket:# ${label}`)
    this.debugger.trace = debug(`sctp:socket: ${label}`)

    association.on('COMMUNICATION UP', () => {
      this.emit('connect')
      this.debugger.info('socket connected')
    })

    association.on('DATA ARRIVE', stream => {
      const buffer = association.RECEIVE(stream)
      if (buffer) {
        this.debugger.debug(
          '< DATA ARRIVE %d bytes on stream %d',
          buffer.length,
          stream
        )
        this.push(buffer)
      }
    })

    association.on('SHUTDOWN COMPLETE', () => {
      this.debugger.debug('socket ended')
      if (this.outbound) {
        endpoint.DESTROY()
      }
      this.emit('end')
    })

    association.on('COMMUNICATION LOST', (event, reason) => {
      this.debugger.info('COMMUNICATION LOST', event, reason)
      if (this.outbound) {
        endpoint.DESTROY()
      }
      this.emit('close')
    })

    association.on('COMMUNICATION ERROR', () => {
      this.emit('error')
    })
  }

  SCTP_ASSOCINFO(options) {
    const params = ['valid_cookie_life']
    const endpoint = this.endpoint
    if (endpoint && typeof options === 'object') {
      params.forEach(key => {
        if (key in options) {
          endpoint[key] = options[key]
        }
      })
    }
  }

  SCTP_DEFAULT_SEND_PARAM(params) {
    // Should be assoc params
    for (const param in this.sctp_sndrcvinfo) {
      if (param in params) {
        this.sctp_sndrcvinfo[param] = params[param]
      }
    }
  }

  /**
   * Destroy() internal implementation
   * @param {Error} err
   * @param {function} callback
   * @returns {Socket}
   * @private
   */
  _destroy(err, callback) {
    this.debugger.info('destroy()')
    // SetTimeout(() => {
    // todo
    this.association.ABORT()
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

    this.debugger = {}
    const label = ``
    this.debugger.info = debug(`sctp:server:## ${label}`)
    this.debugger.info('server start %o', options)

    if (typeof connectionListener === 'function') {
      this.on('connection', connectionListener)
    }

    this.listening = false
    // This.maxConnections = 100 // todo
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
    if (!this.listening) {
      return
    }
    this.listening = false
    // Todo close connections?
    this.emit('close')
    if (typeof callback === 'function') {
      callback()
    }
  }

  // GetConnections(callback) {
  //   // todo
  // }

  listen(port, host, backlog, callback) {
    if (typeof port === 'object') {
      const options = port
      callback = host
      this._listen(options, callback)
    } else {
      const options = {port, host, backlog}
      this._listen(options, callback)
    }
  }

  _listen(options, callback) {
    options = options || {}

    const initOptions = {
      localPort: options.port,
      localAddress: toarray(options.host),
      MIS: options.MIS,
      OS: options.OS
    }
    Endpoint.INITIALIZE(initOptions, (error, endpoint) => {
      if (error) {
        this.emit('error', error)
      } else {
        this.localPort = endpoint.localPort
        this.endpoint = endpoint

        const label = `[${endpoint.localPort}]`
        this.debugger.warn = debug(`sctp:server:### ${label}`)
        this.debugger.info = debug(`sctp:server:## ${label}`)
        this.debugger.debug = debug(`sctp:server:# ${label}`)
        this.debugger.trace = debug(`sctp:server: ${label}`)
        this.debugger.info('bound')

        if (typeof callback === 'function') {
          this.once('listening', callback)
        }

        endpoint.on('COMMUNICATION UP', association => {
          const socket = new Socket({
            ppid: this.ppid
          })
          socket._construct(endpoint, association)
          this.debugger.debug(
            'remote socket connected %s:%s',
            association.remoteAddress,
            association.remotePort
          )
          this.emit('connection', socket)
        })
        this.listening = true
        this.emit('listening')
      }
    })
  }
}

function toarray(address) {
  if (!address) {
    return
  }
  let addresses = Array.isArray(address) ? address : [address]
  addresses = addresses.filter(address => ip.isV4Format(address))
  return addresses
}

module.exports = {
  Socket,
  Server
}
