const _ = require('lodash')
const ip = require('ip')
const raw = require('raw-socket')
const Packet = require('./packet')

let log = () => {
  // to be enabled by endpoint
}

const IP_HEADER = Buffer.from([
  0x45, // version and header length
  0x00, // dfs
  0x00, 0x00, // packet length
  0x00, 0x00, // id
  0x00, // flags
  0x00, // offset
  0x40,  // ttl
  0x84, // sctp = 132 decimal
  0x00, 0x00, // checksum
  0x00, 0x00, 0x00, 0x00, // source address
  0x00, 0x00, 0x00, 0x00 // destination address
])

let rawsocket = raw.createSocket({
  addressFamily: raw.AddressFamily.IPv4,
  protocol: 132, // https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
  bufferSize: 1024 * 80
})

rawsocket.setOption(raw.SocketLevel.IPPROTO_IP, raw.SocketOption.IP_TTL, 64)

// workaround to start listening on win32
if (process.platform === 'win32') {
  rawsocket.send(Buffer.alloc(20), 0, 0, '127.0.0.1', null, () => {
    log('info', 'created raw socket', process.platform)
  })
} else {
  log('info', 'created raw socket', process.platform)
}

rawsocket.on('close', function () {
  throw new Error('raw socket closed')
})

// rawsocket.on('error', function (error) {
//   throw error
// })

rawsocket.on('message', function (buffer, source) {
  if (buffer.length < 36) {
    // packet size less than ip header + sctp header
    log('debug', '< received too small packet', buffer.length)
    return
  }
  let headerLength = (buffer.readUInt8(0) & 0x0f) * 4
  let protocol = buffer.readUInt8(9)
  let destination = ip.toString(buffer, 16, 4)
  let packetLength = readLength(buffer)
  log('debug', '< received packet from', source, ':', packetLength, 'bytes')
  if (process.platform === 'darwin' && ((packetLength + headerLength) !== buffer.length)
    || process.platform !== 'darwin' && packetLength !== buffer.length) {
    log('debug', '< packet length not equal buffer length', packetLength, buffer.length)
    return
  }
  let packet = Packet.fromBuffer(buffer.slice(headerLength))
  if (packet && packet.destination_port) {
    log('debug', '< receive PPID', protocol, 'from', source, packet.source_port, 'to', destination, packet.destination_port,
      packet.chunks ? packet.chunks.length : 0)
    let endpoint = pool[packet.destination_port]
    if (endpoint) {
      // let chunks = packet.chunks
      // delete packet.chunks
      endpoint.emit('packet', packet, source, destination)
    } else {
      // TODO: rfc OOTB
      log('debug', 'OOTB packet', packet)
    }
  } else {
    log('error', 'packet decode error')
  }
})

let pool = {}

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
    if (!(desired in pool)) {
      return desired
    } else {
      return null
    }
  } else {
    // take random cute 4-digit port
    let port = _.random(0xC000, 0xffff) // 49152 - 65535
    // if busy start searching for free from the start
    // todo cyclic search
    if (port in pool) {
      port = 0xC000
      while (port in pool) {
        port++
        if (port > 0xffff) {
          return null
        }
      }
    }
    return port
  }
}


let readLength = (process.platform === 'darwin') ?
  function (buffer) {
    return buffer.readUInt16LE(2)
  } :
  function (buffer) {
    return buffer.readUInt16BE(2)
  }

let writeLength = (process.platform === 'darwin') ?
  function (buffer, value) {
    buffer.writeUInt16LE(value, 2)
  } : function (buffer, value) {
    buffer.writeUInt16BE(value, 2)
  }


function sendPacket(local, remote, packet, callback) {
  let payload = packet.toBuffer()
  log('debug', '> sending', packet.chunks.length, packet.source_port, '->', remote, packet.destination_port, ':', payload.length, 'bytes')
  let buffer
  // local = ip.toBuffer(ip.addr()[1])
  let beforeSend = null
  if (local) {
    beforeSend = () => rawsocket.setOption(raw.SocketLevel.IPPROTO_IP, raw.SocketOption.IP_HDRINCL, 1)
    let headerBuffer = ipHeader({local, remote, payload})
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


function ipHeader(packet) {
  let buffer = Buffer.from(IP_HEADER)
  writeLength(buffer, buffer.length + packet.payload.length)
  if (packet.ttl > 0 && packet.ttl < 0xff) buffer.writeUInt8(packet.ttl, 8)
  if (packet.local) {
    ip.toBuffer(packet.local, buffer, 12)
  }
  ip.toBuffer(packet.remote, buffer, 16)
  log('debug', 'IP_HEADER', buffer)
  return buffer
}


const ACTIVATE_ICMP = false

if (ACTIVATE_ICMP) {
  let icmpSocket = raw.createSocket({
    addressFamily: raw.AddressFamily.IPv4,
    protocol: raw.Protocol.ICMP,
    bufferSize: 1024 * 4
  })

  icmpSocket.on('message', function (buffer, source) {
    if (buffer.length < 42) {
      // packet size less than ip header + ICMP header + 8 = 20 + 16 + 8 = 42
      log('debug', '< received too small packet', buffer.length)
      return
    }
    let headerLength = (buffer.readUInt8(0) & 0x0f) * 4
    let packetLength = readLength(buffer)
    log('debug', '< received ICMP from', source)
    let icmpBuffer = buffer.slice(headerLength)

    // ICMP1) An implementation MAY ignore all ICMPv4 messages where the type field is not set to "Destination Unreachable".
    if (icmpBuffer.readUInt8(0) !== 3) return
    // ICMP3) An implementation MAY ignore any ICMPv4 messages where the code does not indicate "Protocol Unreachable" or "Fragmentation Needed".
    let code = icmpBuffer.readUInt8(1)
    if (code !== 2 && code !== 4) return

    let ipPayload = icmpBuffer.slice(8)

    /*
     ICMP5) An implementation MUST use the payload of the ICMP message (v4
     or v6) to locate the association that sent the message to
     which ICMP is responding.  If the association cannot be found,
     an implementation SHOULD ignore the ICMP message.

     ICMP6) An implementation MUST validate that the Verification Tag
     contained in the ICMP message matches the Verification Tag of
     the peer.  If the Verification Tag is not 0 and does NOT
     match, discard the ICMP message.  If it is 0 and the ICMP
     message contains enough bytes to verify that the chunk type is
     an INIT chunk and that the Initiate Tag matches the tag of the
     peer, continue with ICMP7.  If the ICMP message is too short
     or the chunk type or the Initiate Tag does not match, silently
     discard the packet.

     ICMP7) If the ICMP message is either a v6 "Packet Too Big" or a v4
     "Fragmentation Needed", an implementation MAY process this
     information as defined for PATH MTU discovery.

     ICMP8) If the ICMP code is an "Unrecognized Next Header Type
     Encountered" or a "Protocol Unreachable", an implementation
     MUST treat this message as an abort with the T bit set if it
     does not contain an INIT chunk.  If it does contain an INIT
     chunk and the association is in the COOKIE-WAIT state, handle
     the ICMP message like an ABORT.
     */

    log('debug', '< ICMP')
  })
}

function setLogger(logger) {
  if (logger && (typeof logger.log === 'function')) {
    log = (level, ...rest) => {
      logger.log(level, 'raw -', ...rest)
    }
  }
}


module.exports = {
  sendPacket,
  register,
  unregister,
  setLogger
}

