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
const fileName = ''

let count = 0
const server = sctp.createServer(socket => {
  const start = Date.now()
  count = 0
  console.log(
    'remote socket connected from',
    socket.remoteAddress,
    socket.remotePort
  )
  if (fileName) {
    socket.pipe(fs.createWriteStream(fileName))
  }

  const streamOut = socket.createStream(110)

  streamOut.on('error', error => {
    console.log(error.message)
  })

  socket.on('stream', (streamIn, id) => {
    console.log('< new sctp stream', id)
    // Uncomment to receive data
    // streamIn.on('data', data => {
    //   // Incoming data
    //   // console.log('< received data on stream', data.length, 'bytes')
    //   // streamOut.write(data)
    // })
  })

  socket.on('data', () => {
    count++
    // Io impacts performance
    // console.log('< server received', data.length, 'bytes')
    // Send data back
    // if (!socket.destroyed) socket.write(data)
  })

  socket.on('error', error => {
    console.log(error.message)
  })

  socket.on('end', () => {
    const duration = Date.now() - start
    const rate = Math.floor(socket.bytesRead / duration / 1024 / 1024 * 100000) / 100
    const ratePackets = ~~(count / duration * 1000)
    console.log(
      util.format(
        '%d packets, %d bytes read, %d bytes sent, rate %d MB/s, %d packets/sec',
        count, socket.bytesRead, socket.bytesWritten, rate, ratePackets
      )
    )
    if (fileName) {
      console.log('Contents of piped file (first 100 bytes):')
      console.log(fs.readFileSync(fileName).slice(0, 100).toString())
    }
  })
})

server.listen({
  OS: 1000,
  MIS: 10,
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
