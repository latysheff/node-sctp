#!/usr/bin/node
const fs = require('fs')
const util = require('util')

const sctp = require('../lib')

const [node, script, host, port] = process.argv
console.log(node, script, host, port)

let start

const socket = sctp.connect({host, port}, () => {
  console.log('socket connected')
  socket.on('error', error => {
    console.error(error)
  })
  start = Date.now()
  fs.createReadStream(node).pipe(socket)
})

const size = fs.statSync(node).size
socket.on('end', () => {
  const duration = Date.now() - start
  const rateIn = Math.floor(socket.bytesRead / duration / 1024 / 1024 * 100000) / 100
  const rateOut = Math.floor(socket.bytesWritten / duration / 1024 / 1024 * 100000) / 100
  console.log(
    util.format(
      'file size %d, %d bytes read (rate %d MB/s), %d bytes sent (rate %d MB/s)',
      size, socket.bytesRead, rateIn, socket.bytesWritten, rateOut
    )
  )
  // Close
  socket.end()
  process.exit()
})
