# Stream Control Transmission Protocol (SCTP) for Node.js

This is a userspace (not kernel), pure Javascript implementation of SCTP protocol ([RFC4960]). It depends on [raw-socket] module as IP network layer. Raw-socket requires compilation, but builds on most popular platforms (Linux, Windows, MacOS). This makes SCTP module multi-platform, as Node.js itself.

Module implements sockets interface ([RFC6458]) in Node.js [Net] API.

> Warning!

Implementation  of [RFC4960] is currently incomplete, use at your own risk.

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

### Requirements
Node.js version >=6

### Need root privileges
Quotation from [raw-socket] README:
> Some operating system versions may restrict the use of raw sockets to privileged users. If this is the case an exception will be thrown on socket creation using a message similar to Operation not permitted (this message is likely to be different depending on operating system version).

## Module status
Module has alpha status. Please do not send patches and pull requests yet, better ask for bug fixes and feature implementation.

Not implemented yet:

* multi-homing (work in progress)
* IPv6
* minor features

Nevertheless, module successfully passes most of `sctp_test` cases (both client and server)

## Performance
Load-testing against `sctp_test` shows that performance of sctp module in real world use cases is just about 2-3 times slower than native linux implementation.

## Documentation
Refer to Node.js [Net] API

Some differences with TCP:

**connect(options)**

extra socket options:

* options.MIS - maximum inbound streams (integer, default: 2)
* options.OS - requested outbound streams (integer, default: 2)
* options.logger - logger object for debugging purposes (e.g. console or log4js' logger)

**sctp.defaults(options)**

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

**sctp.protocol**

sctp.protocol is a dictionary object with [SCTP Payload Protocol Identifiers][ppid]

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

See example below.

**socket.SCTP_DEFAULT_SEND_PARAM(options)**

Set socket options related to write operations. Argument 'options' is an object with the following keys (all optional):

* ppid: set payload protocol id (see above)
* stream: sctp stream id (integer)
* unordered: activate unordered mode (boolean)
* no_bundle: disable chunk bundling (boolean)

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
[rfc4960]: https://tools.ietf.org/html/rfc4960
[rfc6458]: https://tools.ietf.org/html/rfc6458
[smpp]: https://www.npmjs.com/package/smpp
[ppid]: https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-25
