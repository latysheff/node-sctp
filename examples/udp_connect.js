const dgram = require('dgram')
process.env.DEBUG = '*'
const sctp = require('../lib/')

const ADDRESS = '192.168.1.217'

const udpSocket = dgram.createSocket({
  type: 'udp4'
})

udpSocket.bind(15001, ADDRESS)


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
      socket.write('hello!')
    })
  })
} else {
  let socket = sctp.connect({
    localPort: 5001,
    port: 5002,
    udpTransport: udpSocket,
    udpPeer: {
      address: ADDRESS,
      port: 15002
    }
  })

  socket.on('error', error => {
    console.error(error.message)
  })

  socket.on('connect', () => {
    socket.write('hello!')
  })
}
