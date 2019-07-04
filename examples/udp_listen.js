const dgram = require('dgram')
process.env.DEBUG = 'sctp:sock1*'
const sctp = require('../lib/')

const ADDRESS = '192.168.1.217'

const udpSocket = dgram.createSocket({
  type: 'udp4'
})

udpSocket.bind(15002, ADDRESS)

let socket = sctp.connect({
  localPort: 5002,
  port: 5001,
  passive: true,
  udpTransport: udpSocket,
  udpPeer: {
    address: ADDRESS,
    port: 15001
  }
})

socket.on('error', error => {
  console.error(error.message)
})

socket.on('data', (buffer) => {
  console.log('received buffer', buffer.ppid, buffer.length) // , buffer.toString('hex'))
})
