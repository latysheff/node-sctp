# Stream Control Transmission Protocol (SCTP) for Node.js
This is an implementation of SCTP network protocol ([RFC4960]) in plain Javascript.

Module presents the socket interface of [Net] module.
Sockets for SCTP are described in [RFC6458].

## Module status
Implementation of [RFC4960] is currently incomplete. At least it lacks handling silly window syndrome (SWS).
Module is suitable for development purposes and small projects, not for production.

Module is being tested against `sctp_test` 
and [SCTP Conformance Tests according to ETSI TS 102 369][sctptests].

## Demo
Assume local address is 192.168.1.216, remote is 192.168.1.16.

Run test as follows:
```
on local machine:
cd examples
DEBUG=* node server.js

on remote machine:
sctp_test -H 192.168.1.16 -P 3000 -h 192.168.1.216 -p 3000 -s -x 100000 -c 1
```

## Installation
npm install sctp

## Example
```
const sctp = require('sctp')

const server = sctp.createServer()

server.on('connection', socket => {
  console.log('remote socket connected from', socket.remoteAddress, socket.remotePort)
  socket.on('data', data => {
    console.log('server socket received data', data)
    socket.write(Buffer.from('010003040000001000110008000003ea', 'hex'))
  })
})

server.listen({port: 2905}, () => {
  console.log('server listening')
})

const socket = sctp.connect({host: '127.0.0.1', port: 2905}, () => {
    console.log('socket connected')
    socket.write(Buffer.from('010003010000001000110008000003ea', 'hex'))
  }
)

socket.on('data', buffer => {
  console.log('socket received data from server', buffer)
  socket.end()
  server.close()
  process.exit()
})

```

## Different underlying transport
It is possible to run SCTP protocol on top of IP transport layer
or on top of DTLS transport.

### Normal mode (IP transport)
SCTP over IP is widely used in telecommunications in such upper layer protocols
like Sigtran (M3UA, M2PA, M2UA) and Diameter.

For operation in normal mode this module needs [raw-socket] Node.js module as IP network layer.
Raw-socket module requires compilation during installation,
but builds on most popular platforms (Linux, Windows, MacOS).
This makes sctp module multi-platform as Node.js itself.

Sctp will try to dynamically require raw-socket module.
Raw socket mode does not prevent sctp to be used in with UDP/DTLS (see below),
but allows to remove direct dependency on binary module.

You may have to install raw-socket module manually.

#### Prerequisites for building [raw-socket] module
Windows:
```
npm install --global --production windows-build-tools
npm install --global node-gyp
```
CentOS:
```
yum install centos-release-scl-rh
yum install devtoolset-3-gcc devtoolset-3-gcc-c++
scl enable devtoolset-3 bash
```
MacOS:
install Xcode, accept license

#### Need root privileges
Quotation from [raw-socket] README:
> Some operating system versions may restrict the use of raw sockets to privileged users. If this is the case an exception will be thrown on socket creation using a message similar to Operation not permitted (this message is likely to be different depending on operating system version).

#### Disable Linux Kernel SCTP
Linux Kernel SCTP should be disabled, because it conflicts with any other implementation.
To prevent the "sctp" kernel module from being loaded,
add the following line to a file in the directory "/etc/modprobe.d/"

`install sctp /bin/true`

### UDP / WebRTC mode (DTLS transport)
This application of SCTP protocol is described in [RFC8261].

>   The Stream Control Transmission Protocol (SCTP) as defined in
    [RFC4960] is a transport protocol running on top of the network
    protocols IPv4 [RFC0791] or IPv6 [RFC8200].  This document specifies
    how SCTP is used on top of the Datagram Transport Layer Security
    (DTLS) protocol.  DTLS 1.0 is defined in [RFC4347], and the latest
    version when this RFC was published, DTLS 1.2, is defined in
    [RFC6347].  This encapsulation is used, for example, within the
    WebRTC protocol suite (see [RTC-OVERVIEW] for an overview) for
    transporting non-SRTP data between browsers.

Underlying transport layer should implement [UDP] API.

In this mode Node.js application can be a peer in WebRTC [data channel][RTCDataChannel].

#### Usage
You need to provide 'udpTransport' option
when connecting socket or creating server:

```
let socket = sctp.connect({
       passive: true,
       localPort: 5000,
       port: 5000,
       udpTransport: myDTLSSocket,
     }
```

In UDP/DTLS mode host and localAddress will be ignored,
because addressing is provided by underlying transport.

To use normal UDP socket, you should provide 'udpPeer':

```
let socket = sctp.connect({
       passive: true,
       localPort: 5000,
       port: 5000,
       udpTransport: udpSocket,
       udpPeer: {
         host: '192.168.0.123',
         port: 15002
       }
     }
```

See examples/udp.js

Also note that in most cases "passive" connect is a better alternative to creating server.

**passive** option disables active connect to remote peer.
Socket waits for remote connection,
allowing it only from indicated remote port.
This unusual option doesn't exist in TCP API.

## Requirements
Node.js version >=6.0.0

## Debugging
Set environment variable DEBUG=sctp:*

## Performance
Load-testing against `sctp_test` shows that performance of sctp module in real world use cases
is just about 2-3 times slower than native Linux Kernel SCTP implementation.

## Documentation
Refer to Node.js [Net] API.

Several existing differences explained below.

### new net.Socket([options])
* options [Object]

For SCTP socketss, available options are:

* ppid [number] Payload protocol id (see below)
* stream_id [number] SCTP stream id. Default: 0
* unordered [boolean] Indicate unordered mode. Default: false
* no_bundle [boolean] Disable chunk bundling. Default: false

Note: SCTP does not support a half-open state (like TCP)
wherein one side may continue sending data while the other end is closed.

### socket.connect(options[, connectListener])
* options [Object]
* connectListener [Function] Common parameter of socket.connect() methods.
Will be added as a listener for the 'connect' event once.

For SCTP connections, available options are:

* port [number] Required. Port the socket should connect to.
* host [string] Host the socket should connect to.
* localAddress [string] Local address the socket should connect from.
* localPort [number] Local port the socket should connect from.
* MIS [number] Maximum inbound streams. Default: 2
* OS [number] Requested outbound streams. Default: 2
* passive [boolean] Indicates passive mode. Socket will not connect,
but allow connection of remote socket from host:port. Default: false
* udpTransport [Object] UDP transport socket
* ppid [number] default PPID for packets. Default: 0

### socket.createStream(streamId, ppid)
Creates SCTP stream. Those are SCTP socket sub-streams. If stream already exists, returns it.
Stream 0 always exists.

* streamId [number] stream id. Default: 0
* ppid [number] default PPID for packets (if not set, socket setting is used)

> After the association is initialized, the valid outbound stream
  identifier range for either endpoint shall be 0 to min(local OS, remote MIS)-1.

You can check this negotiated value by referring to `socket.OS`
after 'connect' event. id should be less the socket.OS.

Result is stream.Writable.

```
const stream = socket.createStream(1)
stream.write('some data')
```

### socket.write(buffer)
It is possible to change PPID per chunk by setting buffer.ppid to desired value.

`buffer.ppid = sctp.PPID.WEBRTC_STRING`

### Socket events
See [Net] module documentation.

For SCTP additional event 'stream' is defined.
It signals that incoming data chunk were noticed with new SCTP stream id.

```
socket.on('stream', (stream, id) => {
  stream.on('data', data => {
    // Incoming data (data.ppid indicates the SCTP message PPID value)
  })
})
```

### sctp.defaults(options)
Function sets default module parameters. Names follow net.sctp conventions. Returns current default parameters.

See `sysctl -a | grep sctp`

Example:

```
sctp.defaults({
  rto_initial: 500,
  rto_min: 300,
  rto_max: 1000,
  sack_timeout: 150,
  sack_freq: 2,
})
```

### sctp.PPID
sctp.PPID is an object with [SCTP Payload Protocol Identifiers][ppid]

```
{
  SCTP: 0,
  IUA: 1,
  M2UA: 2,
  M3UA: 3,
  SUA: 4,
  M2PA: 5,
  V5UA: 6,
  H248: 7,
  BICC: 8,
  ...
  }
```

## RFC to implement
* [3758 Partial Reliability Extension][RFC3758]
* [4820 Padding Chunk and Parameter][RFC4820]
* [4895 Authenticated Chunks][RFC4895]
* [5061 Dynamic Address Reconfiguration][RFC5061]
* [5062 Security Attacks Found Against SCTP and Current Countermeasures][RFC5062]
* [6525 Stream Reconfiguration][RFC6525]
* [7053 SACK-IMMEDIATELY Extension (I-bit)][RFC7053]
* [7496 Additional Policies for the Partially Reliable Extension][RFC7496]
* [7829 SCTP-PF: A Quick Failover Algorithm][RFC7829]
* [8260 Stream Schedulers and User Message Interleaving (I-DATA Chunk)][RFC8260]

* [Draft: ECN for Stream Control Transmission Protocol][ECN]

## Author
Copyright (c) 2017-2018 Vladimir Latyshev

License: MIT

## Credits
* Inspiration and some ideas are taken from [smpp] module

[raw-socket]: https://www.npmjs.com/package/raw-socket
[Net]: https://nodejs.org/api/net.html
[UDP]: https://nodejs.org/api/dgram.html
[RTCDataChannel]: https://developer.mozilla.org/en-US/docs/Web/API/RTCDataChannel
[RFC4960]: https://tools.ietf.org/html/rfc4960
[RFC6458]: https://tools.ietf.org/html/rfc6458
[RFC8261]: https://tools.ietf.org/html/rfc8261
[smpp]: https://www.npmjs.com/package/smpp
[ppid]: https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-25
[RFC3758]: https://tools.ietf.org/html/rfc3758
[RFC4820]: https://tools.ietf.org/html/rfc4820
[RFC4895]: https://tools.ietf.org/html/rfc4895
[RFC5061]: https://tools.ietf.org/html/rfc5061
[RFC5062]: https://tools.ietf.org/html/rfc5062
[RFC6525]: https://tools.ietf.org/html/rfc6525
[RFC7053]: https://tools.ietf.org/html/rfc7053
[RFC7496]: https://tools.ietf.org/html/rfc7496
[RFC7829]: https://tools.ietf.org/html/rfc7829
[RFC8260]: https://tools.ietf.org/html/rfc8260
[ECN]: https://tools.ietf.org/html/draft-stewart-tsvwg-sctpecn-05
[sctptests]: https://github.com/nplab/sctp-tests
