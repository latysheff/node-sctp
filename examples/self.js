#!/usr/bin/node

const sctp = require('../lib')

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
})

socket.on('data', buffer => {
  console.log('socket received data from server', buffer)
  socket.end()
  server.close()
  process.exit()
})
