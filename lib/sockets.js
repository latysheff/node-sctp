/*

 RFC 6458
 Sockets API Extensions for the Stream Control Transmission Protocol (SCTP)

 */

const assert = require('assert')
const Duplex = require('stream').Duplex
const Readable = require('stream').Readable
const Writable = require('stream').Writable
const EventEmitter = require('events').EventEmitter
const debug = require('debug')
const ip = require('ip')
const Endpoint = require('./endpoint')

class SCTPStreamReadable extends Readable {
  // Constructor is useless
  constructor (socket, streamId) {
    super()
    this.socket = socket
    this.stream_id = streamId
    this.debugger = this.socket.debugger
  }

  _read () {
    this.debugger.debug('_read stream')
  }
}

class SCTPStreamWritable extends Writable {
  constructor (socket, streamId) {
    super()
    this.socket = socket
    this.debugger = this.socket.debugger
    this.stream_id = streamId
    this.bytesWritten = 0
  }

  _write (chunk, encoding, callback) {
    this.debugger.debug('> write stream %d, %d bytes', this.stream_id, chunk.length)
    if (!this.socket.association) {
      return callback(new Error('no association established'))
    }
    const options = {}
    options.stream_id = this.stream_id
    this.bytesWritten += chunk.length
    this.socket.bytesWritten += chunk.length
    return this.socket.association.SEND(chunk, options, callback)
  }
}

class Socket extends Duplex {
  constructor (options) {
    super(options)
    options = options || {}
    this.ootb = options.ootb

    this.debugger = {}
    this.debugger.info = debug('sctp:sockets:##')
    this.debugger.debug = debug('sctp:sockets:##')
    this.debugger.info('starting socket %o', options)

    this.writeCount = 0
    this.bytesRead = 0
    this.bytesWritten = 0

    /*
        Todo?
        this.bufferSize = 0 // getter of this.writeBuffer.length?
        this.destroyed = false
        this.connecting = false
        this._highWaterMark = 8 * 1024
        this.writeBuffer = []
    */

    this.streamsReadable = []
    this.streamsWritable = []

    this.stream_id = options.stream_id || false
    this.unordered = options.unordered || false
    this.no_bundle = options.no_bundle || false
    this.ppid = options.ppid || 0
  }

  _read () {
    this.debugger.debug('_read')
    // This function means that socket wants to get more data
    // should exist even if empty
  }

  createStream (streamId) {
    if (streamId < 0 || streamId >= this.OS) {
      /*
       After the association is initialized, the valid outbound stream
       identifier range for either endpoint shall be 0 to min(local OS, remote MIS)-1.
      */
      this.debugger.warn('wrong stream %d, OS: %d, MIS: %d', streamId, this.OS, this.MIS)
      throw new Error('wrong stream id, check local OS and peer MIS')
    }

    this.debugger.warn('createStream %d, OS: %d, MIS: %d', streamId, this.OS, this.MIS)

    if (this.streamsWritable[streamId]) {
      return this.streamsWritable[streamId]
    }
    const stream = new SCTPStreamWritable(this, streamId)
    this.streamsWritable[streamId] = stream
    return stream
  }

  _write (chunk, encoding, callback) {
    const writeCount = this.writeCount++
    this.debugger.info('> write socket #%d %d bytes', writeCount, chunk.length)
    if (!this.association) {
      return callback(new Error('no association established'))
    }
    const options = {}
    options.stream_id = this.stream_id
    this.bytesWritten += chunk.length
    // While a stream is not draining, calls to write() will buffer chunk, and return false.
    // internal _send
    let drain = this.association.SEND(chunk, options, (error) => {
      setImmediate(callback)
      this.debugger.debug('> write socket #%d complete', writeCount)
      if (error) {
        this.debugger.warn('> write socket error', error)
      }
    })
    this.debugger.trace('draining', drain)
    return drain
  }

  _final (callback) {
    /*
    This optional function will be called before the stream closes,
    delaying the 'finish' event until callback is called.
    This is useful to close resources or write buffered data
    before a stream ends.
    */
    // called by end()
    // todo!
    this.debugger.info('_final')
    if (this.association) {
      this.association.SHUTDOWN(callback)
    }
  }

  address () {
    return {
      port: this.localPort,
      address: this.localAddress,
      family: 'IPv4'
    }
  }

  connect (options, connectListener) {
    /*
     Port: Port the client should connect to (Required).
     host: Host the client should connect to. Defaults to 'localhost'.
     localAddress: Local interface to bind to for network connections.
     localPort: Local port to bind to for network connections.
     family : Version of IP stack. Defaults to 4.
     hints: dns.lookup() hints. Defaults to 0.
     lookup : Custom lookup function. Defaults to dns.lookup.
     */

    if (this.outbound) return

    this.outbound = true

    if (typeof options !== 'object') options = { port: options }

    this.passive = !!options.passive

    options.port = ~~options.port
    assert(Number.isInteger(options.port), 'port should be an number')
    assert(options.port > 0 && options.port < 0xFFFF)
    this.remotePort = options.port

    this.remoteAddress = options.host || null
    // Do not set default host in passive mode, let user decide who may connect
    if (!this.remoteAddress && !this.passive) {
      this.remoteAddress = 'localhost'
    }

    this.localPort = ~~options.localPort || null
    this.localAddress = toarray(options.localAddress)

    // if (this.udpTransport) {
    //   this.localAddress = undefined
    //   this.remoteAddress = undefined
    // }

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
      ootb: this.ootb
    }

    const transportOptions = {
      udpTransport: options.udpTransport,
      udpPeer: options.udpPeer
    }

    Endpoint.INITIALIZE(initOptions, transportOptions, (error, endpoint) => {
      if (error) {
        this.emit('error', error)
      } else if (this.passive) {
        endpoint.on('association', association => {
          this.debugger.info('associated with %s:%d',
            association.remoteAddress, association.remotePort)
          if (
            association.remotePort === this.remotePort &&
            association.remoteAddress === this.remoteAddress
          ) {
            this.establish(endpoint, association)
          } else {
            // Todo abort immediately or even ignore
            this.debugger.info('denied connect from %d', association.remotePort)
            association.ABORT()
          }
        })
      } else {
        const association = endpoint.ASSOCIATE(assocOptions)
        this.establish(endpoint, association)
      }
    })
  }

  establish (endpoint, association) {
    this.endpoint = endpoint
    this.localPort = endpoint.localPort
    this.localAddress = endpoint.localAddress

    this.association = association
    this.remoteAddress = association.remoteAddress
    this.remotePort = association.remotePort

    // Update to min(local OS, remote MIS)
    this.MIS = association.MIS
    this.OS = association.OS
    this.remoteFamily = 'IPv4'

    const label = `${this.localPort}/${this.remoteAddress}:${this.remotePort}`
    this.debugger.warn = debug(`sctp:sockets:### ${label}`)
    this.debugger.info = debug(`sctp:sockets:## ${label}`)
    this.debugger.debug = debug(`sctp:sockets:# ${label}`)
    this.debugger.trace = debug(`sctp:sockets: ${label}`)

    // A)
    association.on('DATA ARRIVE', streamId => {
      const buffer = association.RECEIVE(streamId)
      if (!buffer) {
        return
      }

      this.debugger.debug('< DATA ARRIVE %d bytes on stream %d', buffer.length, streamId)

      if (this.listenerCount('stream') > 0) {
        if (!this.streamsReadable[streamId]) {
          this.streamsReadable[streamId] = new SCTPStreamReadable(this, streamId)
          this.emit('stream', this.streamsReadable[streamId], streamId)
        }
        this.streamsReadable[streamId].push(buffer)
      }

      this.bytesRead += buffer.length
      this.push(buffer)
    })

    // B) todo ?
    association.on('SEND FAILURE', info => {
      this.debugger.warn('send falure', info)
    })

    // C) todo ?
    association.on('NETWORK STATUS CHANGE', info => {
      this.debugger.warn('status change', info)
    })

    association.once('COMMUNICATION UP', () => {
      this.debugger.info('socket connected')
      this.emit('connect')
    })

    association.once('COMMUNICATION LOST', (event, reason) => {
      this.debugger.info('COMMUNICATION LOST', event, reason)
      if (this.outbound) {
        endpoint.DESTROY()
      }
      this.debugger.info('emit end')
      this.emit('end')
    })

    association.on('COMMUNICATION ERROR', () => {
      this.emit('error')
    })

    association.on('RESTART', () => {
      this.emit('restart')
    })

    association.on('SHUTDOWN COMPLETE', () => {
      this.debugger.debug('socket ended')
      if (this.outbound) {
        endpoint.DESTROY()
      }
      this.emit('end')
    })
  }

  SCTP_ASSOCINFO (options) {
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

  /**
   * Destroy() internal implementation
   * @param {Error} err
   * @param {function} callback
   * @returns {Socket}
   * @private
   */
  _destroy (err, callback) {
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
  constructor (options, connectionListener) {
    super()
    if (typeof options === 'function') {
      connectionListener = options
      options = {}
    } else {
      options = options || {}
    }

    this.debugger = {}
    this.debugger.info = debug('sctp:server:##')
    this.debugger.info('server start %o', options)

    if (typeof connectionListener === 'function') {
      this.on('connection', connectionListener)
    }

    this.listening = false
    this.ppid = options.ppid
  }

  address () {
    return {
      port: this.localPort,
      address: this.localAddress,
      family: 'IPv4'
    }
  }

  close (callback) {
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

  listen (port, host, backlog, callback) {
    /*
     The server.listen() method can be called again if and only if there was an error
     during the first server.listen() call or server.close() has been called.
     Otherwise, an ERR_SERVER_ALREADY_LISTEN error will be thrown.
    */

    if (typeof port === 'object') {
      const options = port
      callback = host
      this._listen(options, callback)
    } else {
      const options = { port, host, backlog }
      this._listen(options, callback)
    }
  }

  _listen (options, callback) {
    options = options || {}
    this.debugger.info('server try listen %o', options)

    if (typeof callback === 'function') {
      this.once('listening', callback)
    }

    const initOptions = {
      localPort: options.port,
      localAddress: toarray(options.host),
      MIS: options.MIS || this.maxConnections,
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

        endpoint.on('association', association => {
          // Todo other params
          const socket = new Socket({ ppid: this.ppid })
          socket.establish(endpoint, association)
          this.emit('connection', socket)
          this.debugger.debug('connect <- %s:%s', association.remoteAddress, association.remotePort)
        })
        this.listening = true
        this.emit('listening')
      }
    })
  }
}

function toarray (address) {
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
