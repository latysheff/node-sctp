const dgram = require('dgram')
process.env.DEBUG = 'sctp:x*'
const sctp = require('../lib/')

sctp.defaults({ sack_freq: 1 })

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
  },
  MIS: 100
})

socket.on('error', error => {
  console.error(error.message)
})

socket.on('data', (buffer) => {
  console.log('socket received', buffer.ppid, buffer.length)
})

socket.on('stream', (stream, id) => {
  stream.on('data', buffer => {
    console.log('stream %d received', id, buffer.ppid, buffer.length)
  })
})
