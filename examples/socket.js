#!/usr/bin/node
const fs = require('fs')
const sctp = require('../lib')

const [node, script, host, port] = process.argv
console.log(node, script, host, port)

const socket = sctp.connect({host, port, highWaterMark: 1000}, () => {
  console.log('socket connected')
  socket.on('error', error => {
    console.error(error)
  })
  fs.createReadStream(node).pipe(socket)
}
)

const start = Date.now()
const size = fs.statSync(node).size / 1024
socket.on('end', () => {
  const time = (Date.now() - start) / 1000
  // Console.log(fs.statSync(node))
  console.log('transfer rate', ~~(size / time), 'kB/s')
  // Socket.end()
  process.exit()
})
