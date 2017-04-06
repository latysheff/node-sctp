var _ = require('lodash');
var ip = require('ip');
var util = require('util');
var raw = require('raw-socket');

var Packet = require('./packet').Packet;
var Chunk = require('./packet').Chunk;

const IP_HDRINCL = false;
const START_PORT = 1024;
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
]);
var IP_ADDRESS = ip.address();


var sctpSocket = raw.createSocket({
    addressFamily: raw.AddressFamily.IPv4,
    protocol: 132, // https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    bufferSize: 1024 * 4
});

sctpSocket.setOption(raw.SocketLevel.IPPROTO_IP, raw.SocketOption.IP_TTL, 64);
if (IP_HDRINCL) sctpSocket.setOption(raw.SocketLevel.IPPROTO_IP, raw.SocketOption.IP_HDRINCL, 1);

// workaround to start listening
sctpSocket.send(Buffer.alloc(0), 0, 0, '127.0.0.1', null, function () {
});

sctpSocket.on('message', function (buffer, source) {
    if (buffer.length < 36) {
        // packet size less than ip header + sctp header
        return;
    }
    var headerLength = (buffer.readUInt8(0) & 0x0f) * 4;
    var protocol = buffer.readUInt8(9);
    var destination = ip.toString(buffer, 16, 4);
    var packetLength = readLength(buffer);
    var packet = Packet.fromBuffer(buffer.slice(headerLength));
    if (packet) {
        var endpoint = getListener(packet.destination_port);
        if (endpoint) {
            var chunks = packet.chunks;
            delete packet.chunks;
            endpoint.emit('packet', packet, chunks, source, destination)
        } else {
        }
    } else {
    }
});

sctpSocket.on('error', function (e) {
});

sctpSocket.on('close', function () {
});

var ports = {};


function takePort(ep) {
    ep.localPort = allocate(ep.localPort);
    if (ep.localPort) {
        ports[ep.localPort] = ep;
        return ep
    }
}


function allocate(desired) {
    var result;
    if (desired) {
        if (desired in ports) {
            // port already taken
        } else {
            result = desired
        }
    } else {
        var port = START_PORT;
        while (port in ports) {
            port++;
            if (port > 65000) {
                return
            }
        }
        result = port
    }
    return result
}


function releasePort(port) {
    delete ports[port];
}


function getListener(port) {
    return ports[port]
}


function sendPacket(host, header, chunks, callback) {
    var packet = new Packet(header, chunks);
    var payloadBuffer = packet.toBuffer();
    var buffer;
    if (IP_HDRINCL) {
        var headerBuffer = constructIPHeader({
            source: IP_ADDRESS,
            destination: host,
            payload: payloadBuffer
        });
        buffer = Buffer.concat([headerBuffer, payloadBuffer])
    } else {
        buffer = payloadBuffer
    }
    sctpSocket.send(buffer, 0, buffer.length, host, null, function (error, bytes) {
        if (_.isFunction(callback)) {
            callback(error, bytes)
        }
    });
    return true
}


function constructIPHeader(packet) {
    var buffer = Buffer.from(IP_HEADER);
    // buffer.writeUInt8(0x40 | buffer.length >> 2, 0)
    writeLength(buffer, buffer.length + packet.payload.length);
    if (packet.ttl > 0 && packet.ttl < 0xff) {
        buffer.writeUInt8(packet.ttl, 8)
    }
    ip.toBuffer(packet.source, buffer, 12);
    ip.toBuffer(packet.destination, buffer, 16);
    return buffer
}

function readLength(buffer) {
    if (process.platform === 'darwin') {
        return buffer.readUInt16LE(2)
    } else {
        return buffer.readUInt16BE(2)
    }
}

function writeLength(buffer, value) {
    if (process.platform === 'darwin') {
        buffer.writeUInt16LE(value, 2)
    } else {
        buffer.writeUInt16BE(value, 2)
    }
}

const ACTIVATE_ICMP = false

if (ACTIVATE_ICMP) {
    var icmpSocket = raw.createSocket({
        addressFamily: raw.AddressFamily.IPv4,
        protocol: raw.Protocol.ICMP,
        bufferSize: 1024 * 4
    });

    icmpSocket.on('message', function (buffer, source) {
        if (buffer.length < 42) {
            // packet size less than ip header + ICMP header + 8 = 20 + 16 + 8 = 42
            return;
        }
        var headerLength = (buffer.readUInt8(0) & 0x0f) * 4;
        var packetLength = readLength(buffer);
        //todo check length
        var icmpBuffer = buffer.slice(headerLength);

        // ICMP1) An implementation MAY ignore all ICMPv4 messages where the type field is not set to "Destination Unreachable".
        if (icmpBuffer.readUInt8(0) != 3) return;
        // ICMP3) An implementation MAY ignore any ICMPv4 messages where the code does not indicate "Protocol Unreachable" or "Fragmentation Needed".
        var code = icmpBuffer.readUInt8(1);
        if (code != 2 && code != 4) return;

        var ipPayload = icmpBuffer.slice(8);

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

    });
}

module.exports.sendPacket = sendPacket;
module.exports.takePort = takePort;
module.exports.releasePort = releasePort;
