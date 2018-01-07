const ip = require('ip')
const raw = require('raw-socket')
const Packet = require('./packet')

const IP_TTL = 0x40 // 64
const SCTP_PROTO = 0x84 // 132 - see https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
const SO_RCVBUF = 1024 * 128
const SO_SNDBUF = SO_RCVBUF
const BUFFER_SIZE = 1024 * 4

let rawsocket

let pool = {}
let pool_start = 0xC000
let pool_finish = 0xFFFF
let pool_size = pool_finish - pool_start
let pointer = pool_start
let countRcv = 0

setTimeout(enableSocket, 0)
setTimeout(enableICMP, 0)

const IP_HEADER = Buffer.from([
  0x45, // version and header length
  0x00, // dfs
  0x00, 0x00, // packet length
  0x00, 0x00, // id
  0x00, // flags
  0x00, // offset
  IP_TTL,
  SCTP_PROTO,
  0x00, 0x00, // checksum
  0x00, 0x00, 0x00, 0x00, // source address
  0x00, 0x00, 0x00, 0x00 // destination address
])

function enableSocket() {
  log('info', 'starting RAW socket on', process.platform)

  rawsocket = raw.createSocket({
    addressFamily: raw.AddressFamily.IPv4,
    protocol: SCTP_PROTO,
    bufferSize: BUFFER_SIZE
  })

  rawsocket.setOption(raw.SocketLevel.IPPROTO_IP, raw.SocketOption.IP_TTL, IP_TTL)
  rawsocket.setOption(raw.SocketLevel.SOL_SOCKET, raw.SocketOption.SO_RCVBUF, SO_RCVBUF)
  rawsocket.setOption(raw.SocketLevel.SOL_SOCKET, raw.SocketOption.SO_SNDBUF, SO_SNDBUF)

  // workaround to start listening on win32
  // todo
  if (process.platform === 'win32') {
    rawsocket.send(Buffer.alloc(20), 0, 0, '127.0.0.1', null, () => {
      log('info', 'RAW socket opened', process.platform)
    })
  } else {
    log('info', 'RAW socket opened', process.platform)
  }

  rawsocket.on('close', function () {
    throw new Error('RAW socket closed')
  })

  rawsocket.on('message', function (buffer, source) {
    countRcv++
    log('debug', '< message', buffer.length, 'bytes from', source, 'total', countRcv)
    if (buffer.length < 36) return // less than ip header + sctp header
    processMessage(buffer, source)
  })

}

let log = () => {
  // dummy logger can be enabled later
}

log = console.log

function setLogger(logger) {
  if (logger && (typeof logger.log === 'function')) {
    log = (level, ...rest) => {
      logger.log(level, 'rawsocket -', ...rest)
    }
  } else {
    log = function () {
    }
  }
}

function processMessage(buffer, source) {
  const headerLength = (buffer[0] & 0x0f) << 2
  // const protocol = buffer[9]
  let destination = ip.toString(buffer, 16, 4)
  let packetLength = readLength(buffer)
  if (!checkLength(buffer, headerLength, packetLength)) return
  log('trace', '< ip packet ok', destination, '<-', source)
  let packet = Packet.fromBuffer(buffer.slice(headerLength))
  if (packet && packet.chunks) {
    log('debug', '< sctp packet', packet.chunks.length, 'chunks', destination, packet.dst_port, '<-', source, packet.src_port)
    let endpoint = pool[packet.dst_port]
    if (endpoint) {
      endpoint.emit('packet', packet, source, destination)
    } else {
      log('trace', 'OOTB sctp packet', packet)
    }
  } else {
    log('warn', 'sctp packet decode error')
  }
}

function register(endpoint) {
  endpoint.localPort = allocate(endpoint.localPort)
  if (endpoint.localPort) {
    pool[endpoint.localPort] = endpoint
    log('debug', 'endpoint registered on port', endpoint.localPort)
    return endpoint
  }
}

function unregister(endpoint) {
  delete pool[endpoint.localPort]
  log('debug', 'destroyed endpoint, freed port', endpoint.localPort)
}

function allocate(desired) {
  if (desired) {
    if (desired in pool) {
      return null
    } else {
      return desired
    }
  } else {
    let attempt = 0
    while (pointer in pool) {
      attempt++
      if (attempt > pool_size) return null
      pointer++
      if (pointer > pool_finish) {
        pointer = pool_start
      }
    }
    return pointer
  }
}

const checkLength = (process.platform === 'darwin') ?
  function (buffer, headerLength, packetLength) {
    return buffer.length === packetLength + headerLength
  } :
  function (buffer, headerLength, packetLength) {
    return buffer.length === packetLength
  }

const readLength = (process.platform === 'darwin') ?
  function (buffer) {
    return buffer.readUInt16LE(2)
  } :
  function (buffer) {
    return buffer.readUInt16BE(2)
  }

const writeLength = (process.platform === 'darwin') ?
  function (buffer, value) {
    buffer.writeUInt16LE(value, 2)
  } : function (buffer, value) {
    buffer.writeUInt16BE(value, 2)
  }


function sendPacket(local, remote, packet, callback) {
  if (!rawsocket) enableSocket()
  let payload = packet.toBuffer()
  log('debug', '> send', packet.chunks.length, 'chunk',
    local, ':', packet.src_port, '->', remote, packet.dst_port, ':', payload.length, 'bytes')
  let buffer
  let beforeSend = null
  if (local) {
    beforeSend = () => rawsocket.setOption(raw.SocketLevel.IPPROTO_IP, raw.SocketOption.IP_HDRINCL, 1)
    let headerBuffer = createHeader({local, remote, payload})
    let checksum = raw.createChecksum(headerBuffer)
    raw.writeChecksum(headerBuffer, 10, checksum)
    buffer = Buffer.concat([headerBuffer, payload])
  } else {
    beforeSend = () => rawsocket.setOption(raw.SocketLevel.IPPROTO_IP, raw.SocketOption.IP_HDRINCL, 0)
    buffer = payload
  }
  rawsocket.send(buffer, 0, buffer.length, remote, beforeSend, (error, bytes) => {
    if (typeof callback === 'function') {
      callback(error, bytes)
    }
  })
  return true
}


function createHeader(packet) {
  let buffer = Buffer.from(IP_HEADER)
  writeLength(buffer, buffer.length + packet.payload.length)
  if (packet.ttl > 0 && packet.ttl < 0xff) buffer.writeUInt8(packet.ttl, 8)
  if (packet.local) {
    ip.toBuffer(packet.local, buffer, 12)
  }
  ip.toBuffer(packet.remote, buffer, 16)
  return buffer
}


function enableICMP() {
  log('info', 'starting ICMP RAW socket on', process.platform)

  let icmp_rawsocket = raw.createSocket({
    addressFamily: raw.AddressFamily.IPv4,
    protocol: 1
  })

  icmp_rawsocket.send(Buffer.alloc(42), 0, 0, '192.168.1.1', null, () => {
    // todo ?
    log('info', 'ICMP socket opened', process.platform)
  })

  icmp_rawsocket.on('message', function (buffer, source) {
    log('trace', '< ICMP from', source)
    if (buffer.length < 42) return  // size < ip header + ICMP header + 8 = 20 + 16 + 8 = 42
    processICMP(buffer)
  })
}


function processICMP(buffer) {

  // Appendix C.  ICMP Handling

  const headerLength = (buffer[0] & 0x0f) << 2
  let packetLength = readLength(buffer)
  if (!checkLength(buffer, headerLength, packetLength)) return
  let icmpbuffer = buffer.slice(headerLength)

  /*

   https://tools.ietf.org/html/rfc792

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

  let type = icmpbuffer[0]
  if (type !== 3) {
    // An implementation MAY ignore all ICMPv4 messages where the type field is not set to "Destination Unreachable"
    return
  }

  let code = icmpbuffer[1]
  /*
   An implementation MAY ignore any ICMPv4 messages where the code does not indicate "Protocol Unreachable" or "Fragmentation Needed".

   Code
      0 = net unreachable;
      1 = host unreachable;
      2 = protocol unreachable;
      3 = port unreachable;
      4 = fragmentation needed and DF set;
      5 = source route failed.
  */
  if (code !== 2 && code !== 4) return
  let payload = icmpbuffer.slice(8)

  processICMPPayload(payload, code)
}

function processICMPPayload(buffer, code) {
  const headerLength = (buffer[0] & 0x0f) << 2
  const protocol = buffer[9]
  if (protocol !== SCTP_PROTO) return
  let destination = ip.toString(buffer, 16, 4)
  let source = ip.toString(buffer, 12, 4)

  let packet = Packet.fromBuffer(buffer.slice(headerLength))
  if (packet) {
    let endpoint = pool[packet.src_port]
    if (endpoint) {
      if (code === 2) {
        log('debug', '< ICMP Protocol Unreachable for SCTP packet', packet.src_port, '->', destination, ':', packet.dst_port)
        endpoint.emit('icmp', packet, source, destination, code)
      }
    } else {
      // If the association cannot be found, an implementation SHOULD ignore the ICMP message.
    }
  }
}


module.exports = {
  sendPacket,
  register,
  unregister,
  setLogger
}
