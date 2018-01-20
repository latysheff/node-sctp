let sctp = require('../lib')

let server = sctp.createServer()

server.on('connection', function(socket) {
  console.log(
    'remote socket connected from',
    socket.remoteAddress,
    socket.remotePort
  )
  socket.on('data', function(data) {
    console.log('server socket received data', data)
    socket.write(Buffer.from('010003040000001000110008000003ea', 'hex'))
  })
})

server.listen({ port: 2905 }, function() {
  console.log('server listening')
})

let socket = sctp.connect(
  {
    console,
    // localAddress: '127.0.0.2',
    host: '127.0.0.1',
    port: 2905,
  },
  function() {
    console.log('socket connected')
    socket.write(Buffer.from('010003010000001000110008000003ea', 'hex'))
  }
)

socket.on('data', function(buffer) {
  console.log('socket received data from server', buffer)
  socket.end()
  server.close()
  process.exit()
})
