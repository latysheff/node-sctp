const sctp = require('../lib/')

const sock1 = sctp.connect({
  passive: true,
  localPort: 3565,
  host: '127.0.0.1',
  port: 3566
})

sock1.on('connect', () => {
  console.log('remote connected')
})

sock1.on('end', () => {
  console.log('remote end')
})

const sock2 = sctp.connect({
  protocol: sctp.PPID.M2PA,
  host: '127.0.0.1',
  localPort: 3566,
  port: 3565
})

sock2.on('connect', () => {
  console.log('socket connected')
  sock2.write(Buffer.from('01000b020000001400ffffff00ffffff00000009', 'hex'))
  sock2.end()
})
