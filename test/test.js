const expect = require('chai').expect
const Packet = require('../lib/packet')
const Chunk = require('../lib/chunk')

describe('Packet', () => {
  describe('functions', () => {
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
    const packet = new Packet(
      {
        src_port: 10000,
        dst_port: 10000,
        v_tag: 483748
      },
      [chunk.toBuffer()]
    )

    it('chunk creation', () => {
      expect(chunk.toBuffer().toString('hex')).to.equal(
        '0100003cae6137760000f400000affff5c9b8c86000500080ad33712000500080ad33713000500080ad33714000c00060005000080000004c0000004'
      )
    })
    it('packet creation', () => {
      expect(packet.toBuffer().toString('hex')).to.equal(
        '27102710000761a4725ad0b70100003cae6137760000f400000affff5c9b8c86000500080ad33712000500080ad33713000500080ad33714000c00060005000080000004c0000004'
      )
    })
    it('packet roundtrip translation', () => {
      expect(Packet.fromBuffer(packet.toBuffer())).to.deep.equal(packet)
    })
  })
})
