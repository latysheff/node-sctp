const assert = require('assert')
const dgram = require('dgram')
const debug = require('debug')
const ip = require('ip')
const Packet = require('./packet')

const IP_TTL = 64
// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
const SCTP_PROTO = 132
const SO_RCVBUF = 1024 * 256
const SO_SNDBUF = SO_RCVBUF
const BUFFER_SIZE = 1024 * 4

const IP_HEADER_TEMPLATE = Buffer.from([
  0x45, // Version and header length
  0x00, // Dfs
  0x00, // Packet length
  0x00,
  0x00, // Id
  0x00,
  0x00, // Flags
  0x00, // Offset
  IP_TTL,
  SCTP_PROTO,
  0x00, // Checksum
  0x00,
  0x00, // Source address
  0x00,
  0x00,
  0x00,
  0x00, // Destination address
  0x00,
  0x00,
  0x00
])

let raw = null
let rawtransport = null

const checkLength =
  process.platform === 'darwin'
    ? (buffer, headerLen, packetLen) => buffer.length === headerLen + packetLen
    : (buffer, headerLen, packetLen) => buffer.length === packetLen

const readLength =
  process.platform === 'darwin'
    ? buffer => buffer.readUInt16LE(2)
    : buffer => buffer.readUInt16BE(2)

const writeLength =
  process.platform === 'darwin'
    ? (buffer, value) => buffer.writeUInt16LE(value, 2)
    : (buffer, value) => buffer.writeUInt16BE(value, 2)

const transports = new WeakMap()

class Transport {
  constructor () {
    /*
    Port numbers are divided into three ranges.  The Well Known Ports are
    those from 0 through 1023, the Registered Ports are those from 1024
    through 49151, and the Dynamic and/or Private Ports are those from
    49152 through 65535.
     */
    this.pool_start = 0xC000
    this.pool_finish = 0xFFFF
    this.pool_size = this.pool_finish - this.pool_start
    this.pool = {}
    this.pointer = this.pool_start
    this.countRcv = 0
  }

  register (endpoint) {
    endpoint.localPort = this.allocate(endpoint.localPort)
    if (endpoint.localPort) {
      this.pool[endpoint.localPort] = endpoint
      this.debug('endpoint registered on port %d', endpoint.localPort)
      return endpoint
    }
  }

  allocate (desired) {
    if (desired > 0 && desired < 0xFFFF) {
      if (desired in this.pool) {
        return null
      }
      return desired
    }
    let attempt = 0
    while (this.pointer in this.pool) {
      this.debug('attempt #%d to allocate port %d', attempt, this.pointer)
      attempt++
      if (attempt > this.pool_size) {
        return null
      }
      this.pointer++
      if (this.pointer > this.pool_finish) {
        this.pointer = this.pool_start
      }
    }
    return this.pointer
  }

  unallocate (port) {
    delete this.pool[port]
    this.debug('unallocate port %d', port)
  }

  receivePacket (packet, src, dst) {
    if (packet && packet.chunks) {
      this.debug(
        '< packet %d chunks %s:%d <- %s:%d',
        packet.chunks.length,
        dst,
        packet.dst_port,
        src,
        packet.src_port
      )
      const endpoint = this.pool[packet.dst_port]
      if (endpoint) {
        endpoint.emit('packet', packet, src, dst)
      } else {
        this.debug('OOTB message', packet)
      }
    } else {
      this.debug('SCTP packet decode error')
    }
  }
}

class RawTransport extends Transport {
  constructor () {
    super()

    this.debug = debug('sctp:transport:raw')
    this.debug('opening raw socket')

    if (!raw) {
      raw = require('raw-socket')
    }

    const rawsocket = raw.createSocket({
      addressFamily: raw.AddressFamily.IPv4,
      protocol: SCTP_PROTO,
      bufferSize: BUFFER_SIZE
    })

    rawsocket.setOption(
      raw.SocketLevel.IPPROTO_IP,
      raw.SocketOption.IP_TTL,
      IP_TTL
    )
    rawsocket.setOption(
      raw.SocketLevel.SOL_SOCKET,
      raw.SocketOption.SO_RCVBUF,
      SO_RCVBUF
    )
    rawsocket.setOption(
      raw.SocketLevel.SOL_SOCKET,
      raw.SocketOption.SO_SNDBUF,
      SO_SNDBUF
    )

    // Workaround to start listening on win32 // todo
    if (process.platform === 'win32') {
      rawsocket.send(Buffer.alloc(20), 0, 0, '127.0.0.1', null, () => {
      })
    }
    this.debug('raw socket opened on %s', process.platform)

    rawsocket.on('message', this.onMessage.bind(this))
    this.rawsocket = rawsocket
  }

  onMessage (buffer, src) {
    this.countRcv++
    this.debug('< message %d bytes from %s', buffer.length, src)
    if (buffer.length < 36) {
      return
    } // Less than ip header + sctp header

    const headerLength = (buffer[0] & 0x0F) << 2
    // Const protocol = buffer[9]
    const dst = ip.toString(buffer, 16, 4)
    const packetLength = readLength(buffer)
    if (!checkLength(buffer, headerLength, packetLength)) {
      return
    }
    this.debug('< ip packet ok %s <- %s', dst, src)
    const payload = buffer.slice(headerLength)

    const packet = Packet.fromBuffer(payload)
    this.receivePacket(packet, src, dst)
  }

  sendPacket (src, dst, packet, callback) {
    const payload = packet.toBuffer()
    this.debug(
      '> send %d bytes %d chunks %s:%d -> %s:%d',
      payload.length,
      packet.chunks.length,
      src,
      packet.src_port,
      dst,
      packet.dst_port
    )
    let buffer
    const cb = (error, bytes) => {
      if (error) {
        this.debug('raw socket send error', error)
      } else {
        this.debug('raw socket sent %d bytes', bytes)
      }
      if (typeof callback === 'function') {
        callback(error)
      }
    }

    let beforeSend
    if (src) {
      beforeSend = () =>
        this.rawsocket.setOption(
          raw.SocketLevel.IPPROTO_IP,
          raw.SocketOption.IP_HDRINCL,
          1
        )
      const headerBuffer = createHeader({ src, dst, payload })
      this.debug('headerBuffer', headerBuffer)
      const checksum = raw.createChecksum(headerBuffer)
      raw.writeChecksum(headerBuffer, 10, checksum)
      buffer = Buffer.concat([headerBuffer, payload])
    } else {
      beforeSend = () =>
        this.rawsocket.setOption(
          raw.SocketLevel.IPPROTO_IP,
          raw.SocketOption.IP_HDRINCL,
          0
        )
      buffer = payload
    }
    this.rawsocket.send(buffer, 0, buffer.length, dst, beforeSend, cb)
    return true
  }

  enableDiscardService () {
    /*
      Discard    9/sctp  Discard  # IETF TSVWG
         # Randall Stewart <rrs@cisco.com>
         # [RFC4960]

      The discard service, which accepts SCTP connections on port
      9, discards all incoming application data and sends no data
      in response.  Thus, SCTP's discard port is analogous to
      TCP's discard port, and might be used to check the health
      of an SCTP stack.
     */
    (new (require('./sockets').Server)({ ppid: 0 })).listen({ OS: 1, MIS: 100, port: 9 })
  }

  enableICMP () {
    /*
     Appendix C.  ICMP Handling
    */
    this.debug('start ICMP RAW socket on %s', process.platform)

    this.icmpsocket = raw.createSocket({
      addressFamily: raw.AddressFamily.IPv4,
      protocol: raw.Protocol.ICMP
    })
    this.icmpsocket.setOption(
      raw.SocketLevel.IPPROTO_IP,
      raw.SocketOption.IP_TTL,
      IP_TTL
    )

    if (process.platform === 'win32') {
      const buffer = Buffer.alloc(24)
      this.icmpsocket.send(
        buffer,
        0,
        buffer.length,
        '127.0.0.1',
        null,
        (error, bytes) => {
          this.debug('> ICMP ping', error, bytes)
        }
      )
    }

    this.debug('ICMP socket opened on %s', process.platform)

    this.icmpsocket.on('message', (buffer, src) => {
      if (src !== '127.0.0.1') {
        this.processICMPPacket(src, buffer)
      }
    })
  }

  processICMPPacket (src, buffer) {
    if (buffer.length < 42) {
      // IP header + ICMP header + part of SCTP header = 20 + 16 + 8 = 42
      return
    }
    const headerLength = (buffer[0] & 0x0F) << 2
    const packetLength = readLength(buffer)
    if (!checkLength(buffer, headerLength, packetLength)) {
      return
    }
    const icmpBuffer = buffer.slice(headerLength)

    /*

     https://tools.ietf.org/html/rfc792
     https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     Type      |     Code      |          Checksum             |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                             unused                            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |      Internet Header + 64 bits of Original Data Datagram      |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    */

    const type = icmpBuffer[0]
    if (type !== 3) {
      // An implementation MAY ignore all ICMPv4 messages
      // where the type field is not set to "Destination Unreachable"
      // this.debug('< type field is not set to "Destination Unreachable", ignore it')
      return
    }

    const code = icmpBuffer[1]
    const payload = icmpBuffer.slice(8)
    // Mute debug
    // this.debug('< ICMP from %s type %d code %d, %d bytes', src, type, code, payload.length)
    this.processICMPPayload(payload, type, code)
  }

  processICMPPayload (buffer, type, code) {
    const headerLength = (buffer[0] & 0x0F) << 2
    const protocol = buffer[9]
    if (protocol !== SCTP_PROTO) {
      return
    }
    const dst = ip.toString(buffer, 16, 4)
    const src = ip.toString(buffer, 12, 4)

    const sctpBuffer = buffer.slice(headerLength)
    const packet = Packet.fromBuffer(sctpBuffer)

    /*
     https://tools.ietf.org/html/rfc792
     https://tools.ietf.org/html/rfc1122
    */
    const ICMP_CODES = [
      'net unreachable',
      'host unreachable',
      'protocol unreachable',
      'port unreachable',
      'fragmentation needed and DF set',
      'source route failed',
      'destination network unknown',
      'destination host unknown',
      'source host isolated',
      'communication with destination network administratively prohibited',
      'communication with destination host administratively prohibited',
      'network unreachable for type of service',
      'host unreachable for type of service'
    ]
    this.debug('< ICMP for %s:%d -> %s:%d %s',
      src, packet.src_port, dst, packet.dst_port, ICMP_CODES[code])

    if (packet) {
      const endpoint = this.pool[packet.src_port]
      if (endpoint) {
        endpoint.emit('icmp', packet, src, dst, code)
      } else {
        // If the association cannot be found,
        // an implementation SHOULD ignore the ICMP message.
      }
    }
  }
}

class UDPTransport extends Transport {
  constructor (socket, peer) {
    super()

    this.debug = debug('sctp:transport:udp')

    this.socket = socket
    this.peer = peer

    if (socket instanceof dgram.Socket) {
      try {
        this.peer = socket.remoteAddress()
        this.connected = true
      } catch (e) {
        assert(peer, 'please provide remote UDP peer (see docs)')
      }
    }

    this.socket.on('error', (err) => {
      if (err.code === 'ECONNREFUSED') {
        this.debug('UDP connection refused')
        this.destroy()
      }
    })

    this.socket.on('close', () => {
      this.destroy()
    })

    this.socket.on('message', (buffer, rinfo) => {
      this.countRcv++
      this.debug('< message %d bytes from %j', buffer.length, rinfo)
      if (buffer.length < 12) {
        return
      } // Less than SCTP header
      const packet = Packet.fromBuffer(buffer)
      this.receivePacket(packet)
    })
  }

  destroy () {
    this.debug('error: transport was closed')
    for (const port in this.pool) {
      const endpoint = this.pool[port]
      endpoint.close()
    }
    delete this.socket
    delete transports[this.socket]
  }

  sendPacket (src, dst, packet, callback) {
    const payload = packet.toBuffer()
    this.debug(
      '> send %d bytes %d chunks %d -> %d over UDP to %s:%d',
      payload.length,
      packet.chunks.length,
      packet.src_port,
      packet.dst_port,
      this.peer.address,
      this.peer.port
    )
    const buffer = payload

    if (this.connected) {
      this.socket.send(buffer, 0, buffer.length, callback)
    } else {
      this.socket.send(buffer, this.peer.port, this.peer.address, callback)
    }
    return true
  }
}

function createHeader (packet) {
  const buffer = Buffer.from(IP_HEADER_TEMPLATE)
  writeLength(buffer, buffer.length + packet.payload.length)
  if (packet.ttl > 0 && packet.ttl < 0xFF) {
    buffer.writeUInt8(packet.ttl, 8)
  }
  ip.toBuffer(packet.src, buffer, 12)
  ip.toBuffer(packet.dst, buffer, 16)
  return buffer
}

function register (endpoint, transportOptions) {
  if (transportOptions.udpTransport) {
    if (transports.has(transportOptions.udpTransport)) {
      endpoint.transport = transports.get(transportOptions.udpTransport)
    } else {
      endpoint.transport = new UDPTransport(transportOptions.udpTransport, transportOptions.udpPeer)
      transports.set(transportOptions.udpTransport, endpoint.transport)
    }
  } else {
    if (!rawtransport) {
      rawtransport = new RawTransport()
      rawtransport.enableICMP()
      rawtransport.enableDiscardService()
    }
    endpoint.transport = rawtransport
  }
  return endpoint.transport.register(endpoint)
}

module.exports = {
  register
}
