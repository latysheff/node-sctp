# Stream Control Transmission Protocol (SCTP) for Node.js

This is an implementation of SCTP network protocol ([RFC4960]) in plain Javascript.

Module presents the same socket interface as in Node.js [Net] module. 
Sockets for SCTP are described in [RFC6458].

> Warning!
Implementation  of [RFC4960] is currently incomplete, use at your own risk.

### Installation
npm install sctp

## Normal mode
SCTP over IP is widely used in telecommunications in such upper layer protocols 
like Sigtran (M3UA, M2PA, M2UA) and Diameter.

For operation in normal mode this module needs [raw-socket] Node.js module as IP network layer.
Raw-socket module requires compilation during installation, 
but builds on most popular platforms (Linux, Windows, MacOS).
This makes sctp module multi-platform as Node.js itself.

### Usage
Application should globally provide raw-socket module as a transport.

`sctp.raw(require('raw-socket'))`

By the way, this doesn't prevent sctp to be used in mixed mode with UDP/DTLS, 
but allows to remove direct dependency on binary module.

### Prerequisites for building [raw-socket] module
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

### Need root privileges
Quotation from [raw-socket] README:
> Some operating system versions may restrict the use of raw sockets to privileged users. If this is the case an exception will be thrown on socket creation using a message similar to Operation not permitted (this message is likely to be different depending on operating system version).

### Disable Linux Kernel SCTP
Linux Kernel SCTP should be disabled, because it conflicts with any other implementation.
To prevent the "sctp" kernel module from being loaded,
add the following line to a file in the directory "/etc/modprobe.d/"

`install sctp /bin/true`

## UDP/DTLS mode
It is possible to use UDP/DTLS socket as transport layer for SCTP. Layer should implement [UDP] API.

This application of SCTP is described in [RFC8261]

>   The Stream Control Transmission Protocol (SCTP) as defined in
    [RFC4960] is a transport protocol running on top of the network
    protocols IPv4 [RFC0791] or IPv6 [RFC8200].  This document specifies
    how SCTP is used on top of the Datagram Transport Layer Security
    (DTLS) protocol.  DTLS 1.0 is defined in [RFC4347], and the latest
    version when this RFC was published, DTLS 1.2, is defined in
    [RFC6347].  This encapsulation is used, for example, within the
    WebRTC protocol suite (see [RTC-OVERVIEW] for an overview) for
    transporting non-SRTP data between browsers.

Using DTLS mode, Node.js application can be a peer in WebRTC [data channel][RTCDataChannel].

### Usage
You need to provide **udpTransport** option when connecting socket or creating server:

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

Also note that in most cases "passive" connect is better alternative to creating server. 
**passive** option disables active connect to remote peer. Socket waits for remote connection, 
allowing it only from indicated remote port.
This unusual option doesn't exist in TCP API.

## Requirements
Node.js version >=6

## Module status
Module has alpha status. Please do not send patches and pull requests yet, better ask for bug fixes and feature implementation.

Not implemented yet:

* multi-homing (work in progress)
* IPv6
* minor features
* measures to avoid silly window syndrome (SWS)
* various protocol extensions

Nevertheless, module successfully passes most of `sctp_test` cases (both client and server).
More compatibility testing will follow with use of stcp test tools and frameworks.

## Performance
Load-testing against `sctp_test` shows that performance of sctp module in real world use cases 
is just about 2-3 times slower than native Linux Kernel SCTP implementation.

## Documentation
Refer to Node.js [Net] API.

Several existing differences explained below.

### new net.Socket([options])
RFC 4960: 
> SCTP does not support a half-open state (like TCP)
wherein one side may continue sending data while the other end is closed.

### socket.connect(options[, connectListener])

* options [Object]
* connectListener [Function] Common parameter of socket.connect() methods.
Will be added as a listener for the 'connect' event once.

For SCTP connections, available options are:

* port [number] Required. Port the socket should connect to.
* host [string] Host the socket should connect to. Default: 'localhost'
* localAddress [string] Local address the socket should connect from.
* localPort [number] Local port the socket should connect from.
* MIS [number] Maximum inbound streams. Default: 2
* OS [number] Requested outbound streams. Default: 2
* passive [boolean] Indicates passive mode. Socket will not connect,
but allow connection of remote socket from host:port. Default: false
* logger [Object] Logger object for debugging purposes (e.g. console or log4js logger)
* udpTransport [Object] UDP transport socket

### socket.SCTP_DEFAULT_SEND_PARAM(options)
* options [Object]

Set socket options related to write operations. Argument 'options' is an object with the following keys (all optional):

* ppid [number] Payload protocol id (see below)
* stream [number] SCTP stream id. Default: 0
* unordered [boolean] Indicate unordered mode. Default: false
* no_bundle [boolean] Disable chunk bundling. Default: false

### sctp.raw(module)
* module Should be [raw-socket] module and nothing else.

### sctp.setLogger(logger)
* logger Global logger for transport.

Example: 
`sctp.transport(require('raw-socket'), console)`

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

### sctp.protocol

sctp.protocol is an object with [SCTP Payload Protocol Identifiers][ppid]

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

## Example
```
const sctp = require('sctp')
sctp.raw(require('raw-socket')))
let server = sctp.createServer()
server.on('connection', function (socket) {
    console.log('remote socket connected from', socket.remoteAddress, socket.remotePort)
    socket.on('data', function (data) {
        console.log('server socket received data', data);
        socket.write(Buffer.from('010003040000001000110008000003ea', 'hex'))
    });
})
server.listen({
    port: 2905
})

let socket = sctp.connect({
    host: '127.0.0.1',
    port: 2905
}, function () {
    console.log('socket connected')
    socket.SCTP_DEFAULT_SEND_PARAM({
        protocol: sctp.protocol.M3UA,
    })
    socket.write(Buffer.from('010003010000001000110008000003ea', 'hex'))
})

socket.on('data', function (buffer) {
    console.log('data', buffer)
    socket.end()
    server.close()
})
```

## Credits
* Inspiration and some ideas are taken from [smpp] module
* CRC algorithm ported from https://pycrc.org/

[raw-socket]: https://www.npmjs.com/package/raw-socket
[Net]: https://nodejs.org/api/net.html
[UDP]: https://nodejs.org/api/dgram.html
[RTCDataChannel]: https://developer.mozilla.org/en-US/docs/Web/API/RTCDataChannel
[RFC4960]: https://tools.ietf.org/html/rfc4960
[RFC6458]: https://tools.ietf.org/html/rfc6458
[RFC8261]: https://tools.ietf.org/html/rfc8261
[smpp]: https://www.npmjs.com/package/smpp
[ppid]: https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-25
