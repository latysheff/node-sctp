const sctp = require('../lib/')

sctp.defaults({
  sack_timeout: 200,
  rto_initial: 500,
  rto_min: 500,
  rto_max: 1000,
})

const server = sctp.createServer({ logger: null })

server.on('connection', function(socket) {
  console.log(
    'remote socket connected from',
    socket.remoteAddress,
    socket.remotePort
  )
  //socket.end();
  socket.on('data', function(data) {
    console.log('server socket received data', data)
    //socket.write(Buffer.from('010003040000001000110008000003ea', 'hex'))
  })
  socket.on('error', function() {
    // ignore
  })
})

server.listen({
  port: 3000,
})

let count = 1
const maxcount = 1000
const start = new Date()

const interval = setInterval(function() {
  if (count > maxcount) {
    clearInterval(interval)
    console.log(
      'average socket creation time, ms',
      (new Date() - start) / maxcount
    )
    return
  }
  newsocket()
}, 1)

function newsocket() {
  count++
  const sctpSocket = sctp.connect(
    {
      protocol: sctp.M3UA,
      host: '127.0.0.1',
      // host: '10.192.169.102',
      port: 3000,
    },
    function() {
      // console.log('sctp socket connected',i)
    }
  )
  sctpSocket.on('connect', function() {
    // console.log('socket connected', i)
    // sctpSocket.write(Buffer.from('010003010000001000110008000003ea', 'hex'))
    let packet = 0
    const interv = setInterval(function() {
      sctpSocket.write(Buffer.from('010003010000001000110008000003ea', 'hex'))
      if (packet++ === 100) {
        // console.log('finish socket' + count)
        clearInterval(interv)
        sctpSocket.end()
      }
    }, 10)
    // sctpSocket.end()
  })
  sctpSocket.on('error', function() {
    // ignore
  })
}

newsocket()
