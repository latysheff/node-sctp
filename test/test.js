const Packet = require('../lib/packet')
const Chunk = require('../lib/chunk')

const lodash = require('lodash')
const tape = require('tape')

const chunk = new Chunk('init', {
  message: 'init',
  initiate_tag: 2925606774,
  a_rwnd: 62464,
  outbound_streams: 10,
  inbound_streams: 65535,
  initial_tsn: 1553697926,
  ipv4_address: ['10.211.55.18', '10.211.55.19', '10.211.55.20'],
  supported_address_type: 5,
  ecn: true,
  forward_tsn_supported: true
})
// delete chunk.flags
// encoding alters chunk parameters in-place, need deep clone before testing decoding back
const originalChunk = lodash.cloneDeep(chunk)
console.log(originalChunk)

const encodedChunk = '01000038ae6137760000f400000affff5c9b8c86000500080ad33712000500080ad33713000500080ad33714000c000600050000c0000004'

const packet = new Packet(
  {
    src_port: 10000,
    dst_port: 10000,
    v_tag: 483748
  },
  [chunk.toBuffer()]
)

const encodedPacket = '27102710000761a42b8e0bb001000038ae6137760000f400000affff5c9b8c86000500080ad33712000500080ad33713000500080ad33714000c000600050000c0000004'

tape('encode chunk', function (t) {
  t.same(chunk.toBuffer().toString('hex'), encodedChunk)
  console.log(chunk)
  t.end()
})

tape('decode chunk', function (t) {
  t.same(Chunk.fromBuffer(Buffer.from(encodedChunk, 'hex')), originalChunk)
  t.end()
})

tape('encode packet', function (t) {
  t.same(packet.toBuffer().toString('hex'), encodedPacket)
  t.end()
})

tape('decode packet', function (t) {
  t.same(Packet.fromBuffer(Buffer.from(encodedPacket, 'hex')), packet)
  t.end()
})
