const crc32c = require('./crc').crc32c

class Packet {
  constructor(headers, chunks) {
    if (Buffer.isBuffer(headers)) {
      this.fromBuffer(headers)
      return
    }
    headers = headers || {}
    this.src_port = headers.src_port
    this.dst_port = headers.dst_port
    this.verification_tag = headers.verification_tag
    this.checksum = 0x00000000
    this.chunks = chunks
  }

  fromBuffer(buffer) {
    this.src_port = buffer.readUInt16BE(0)
    this.dst_port = buffer.readUInt16BE(2)
    this.verification_tag = buffer.readUInt32BE(4)
    this.checksum = buffer.readUInt32LE(8)
    buffer.writeUInt32LE(0x00000000, 8)
    if (this.checksum !== crc32c.calculate(buffer)) return
    let offset = 12
    this.chunks = []
    while (offset + 4 <= buffer.length) {
      let length = buffer.readUInt16BE(offset + 2)
      if (offset + length > buffer.length) return
      let chunk = buffer.slice(offset, offset + length)
      this.chunks.push(chunk)
      offset += length
      let padding = length % 4
      if (padding) offset += (4 - padding)
    }
  }

  static fromBuffer(buffer) {
    if (buffer.length < 12) {
      return false
    }
    return new Packet(buffer)
  }

  toBuffer() {
    if (!(Array.isArray(this.chunks))) this.chunks = []
    let headers = Buffer.alloc(12)
    headers.writeUInt16BE(this.src_port, 0)
    headers.writeUInt16BE(this.dst_port, 2)
    headers.writeUInt32BE(this.verification_tag, 4)
    headers.writeUInt32LE(0x00000000, 8)
    let buffer = Buffer.concat([headers, ...this.chunks])
    this.checksum = crc32c.calculate(buffer, 0)
    buffer.writeUInt32LE(this.checksum, 8)
    return buffer
  }

}


module.exports = Packet
