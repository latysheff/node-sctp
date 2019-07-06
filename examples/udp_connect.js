const dgram = require('dgram')
process.env.DEBUG = 'sctp:s*'
const sctp = require('../lib/')

const ADDRESS = '192.168.1.217'

const udpSocket = dgram.createSocket({
  type: 'udp4'
})

udpSocket.bind(15001, ADDRESS)

const buffer = Buffer.alloc(20 * 1024 * 1024)
buffer.fill('hello')
buffer.ppid = sctp.PPID.WEBRTC_STRING

if (typeof udpSocket.connect === 'function') {
  udpSocket.connect(15002, ADDRESS, () => {
    let socket = sctp.connect({
      localPort: 5001,
      port: 5002,
      udpTransport: udpSocket
    })

    socket.on('error', error => {
      console.error(error.message)
    })

    socket.on('connect', () => {
      socket.write(buffer)
    })

    const stream = socket.createStream(1)
    stream.write(buffer)
  })
} else {
  let socket = sctp.connect({
    localPort: 5001,
    port: 5002,
    udpTransport: udpSocket,
    udpPeer: {
      address: ADDRESS,
      port: 15002
    },
    OS: 100,
    ppid: sctp.PPID.WEBRTC_DCEP
  })

  socket.on('error', error => {
    console.error(error.message)
  })

  socket.on('connect', () => {
    // socket.write(buffer)

    socket.createStream(1).write(buffer)

    delete buffer.ppid
    socket.createStream(2, 33).write(buffer)
    socket.createStream(3, 44).write(buffer)
  })
}
