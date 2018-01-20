let sctp = require('../lib')

let ip = require('ip')
let util = require('util')

let port = 3000

sctp.defaults({
  rto_initial: 500,
  rto_min: 300,
  rto_max: 1000,
  sack_timeout: 100,
  sack_freq: 2,
})

let i = 0
let server = sctp.createServer({}, (socket)=> {
  console.log(
    'remote socket connected from',
    socket.remoteAddress,
    socket.remotePort
  )
  socket.on('data', function(data) {
    // console.log('< server received data', data)
    socket.write('count' + i++)
  })
  socket.on('error', function() {})
  socket.on('end', function() {})
})

server.listen({
  MIS: 2,
  port: port,
})

console.log('server started on port %d', port)
console.log('now run test, for example:')
console.log(
  'info',
  util.format(
    'sctp_test -H <remote ip> -h <%s or another local ip> -p %d -s -P <remote port> -x 10000 -d0 -c 2',
    ip.address(),
    port
  )
)

process.on('SIGINT', () => {
  console.log('SIGINT')
  // todo close socket
  setTimeout(() => {
    console.log('exiting')
    process.exit()
  }, 100)
})
