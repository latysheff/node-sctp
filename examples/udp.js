const dgram = require('dgram')
process.env.DEBUG = '*'
const sctp = require('../lib/')

const udpSocket = dgram.createSocket({
  type: 'udp4'
})

udpSocket.bind(15001)

let socket = sctp.connect({
  localPort: 5000,
  localAddress: '127.0.0.1',
  host: '127.0.0.2',
  port: 5001,
  udpTransport: udpSocket,
  udpPeer: {
    host: '192.168.0.123',
    port: 15002
  }
})

socket.on('error', error => {
  console.error(error.message)
})
