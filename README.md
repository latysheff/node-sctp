# Stream Control Transmission Protocol (SCTP) for Node.js

This is a userspace (not kernel), pure Javascript implementation of SCTP protocol ([RFC4960]). It depends on [raw-socket] module as IP network layer. Raw-socket requires compilation, but builds on most popular platforms (Linux, Windows, MacOS). This makes SCTP module multi-platform, as Node.js itself.

Module implements sockets interface ([RFC6458]) in Node.js [Net] API.

> Warning! Warning! Warning!

Implementation  of [RFC4960] is currently incomplete and unstable, don't use in production environment!

## Disable LK-SCTP

On Linux LK-SCTP should be disabled, because it conflicts with any other implementation. To prevent the "sctp" kernel module from being loaded, add the following line to a file in the directory "/etc/modprobe.d":
`install sctp /bin/true`

## Raw socket

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

### Need root priveledges
Quotation from [raw-socket] README:
> Some operating system versions may restrict the use of raw sockets to privileged users. If this is the case an exception will be thrown on socket creation using a message similar to Operation not permitted (this message is likely to be different depending on operating system version).

## Module status
Module has alpha status. Please do not send patches and pull requests yet, better ask for bug fixes and feature implementation.

Not implemented yet:

* multi-homing
* IPv6
* congestion control (incomplete)
* counters
* etc

Nevertheless, module successfully passes most of `sctp_test` cases (both client and server)

## Documentation
Refer to [Net] API


**sctp.protocol**

sctp.protocol is a dictionary object with [SCTP Payload Protocol Identifiers][ppi]

For example, sctp.protocol.M3UA = 3

```
var sctp = require('sctp')
console.log(Object.keys(sctp.protocol).join())
//output: SCTP,IUA,M2UA,M3UA,SUA,M2PA,V5UA,H248,SSH,Diameter,Diameter_DTLS,WebRTC_DCEP,WebRTC_String,WebRTC_Binary,WebRTC_String_Empty,WebRTC_Binary_Empty
```

## Quick example
```
var sctp = require('sctp')
var server = sctp.createServer()
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

var socket = sctp.connect({
    protocol: sctp.protocol.M3UA,
    host: '127.0.0.1',
    port: 2905
}, function () {
    console.log('socket connected')
    socket.write(Buffer.from('010003010000001000110008000003ea', 'hex'))
})

socket.on('data', function (buffer) {
    console.log('data', buffer)
    socket.end()
    server.close()
    process.exit()
})
```

## Credits
Inspiration and some ideas are taken from [smpp] module

[raw-socket]: https://www.npmjs.com/package/raw-socket
[Net]: https://nodejs.org/api/net.html
[rfc4960]: https://tools.ietf.org/html/rfc4960
[rfc6458]: https://tools.ietf.org/html/rfc6458
[smpp]: https://www.npmjs.com/package/smpp
[ppi]: https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-25
