const util = require('util')
const fs = require('fs')

const ip = require('ip')
const sctp = require('../lib')

const port = 3000

sctp.defaults({
  rto_initial: 500,
  rto_min: 300,
  rto_max: 1000,
  sack_timeout: 100,
  sack_freq: 2
})
const fileName = './tmp.bin'

let count = 0
const server = sctp.createServer({}, socket => {
  count = 0
  console.log(
    'remote socket connected from',
    socket.remoteAddress,
    socket.remotePort
  )
  socket.pipe(fs.createWriteStream(fileName))

  socket.on('data', data => {
    count++
    console.log('< server received data', data)
    if (!socket.destroyed)
      socket.write(data)
  })
  socket.on('error', err => {
    console.log(err)
  })
  socket.on('end', () => {
    console.log(
      util.format(
        '%d packets, %d bytes read, %d bytes sent',
        count, socket.bytesRead, socket.bytesWritten
      )
    )
    console.log('Contents of piped file (first 100 bytes):')
    console.log(fs.readFileSync(fileName).slice(0, 100).toString())
  })
})

server.listen({
  MIS: 2,
  port
})

console.log('server started on port %d', port)
console.log('now run test, for example:')
console.log(
  'info',
  util.format(
    'sctp_test -H <ip> -h <%s or another local ip> -p %d -s -P <port> -x 10000 -d0 -c 2 -D',
    ip.address(),
    port
  )
)

process.on('SIGINT', () => {
  console.log('SIGINT')
  // Todo close socket
  setTimeout(() => {
    console.log('exiting')
    process.exit()
  }, 100)
})
