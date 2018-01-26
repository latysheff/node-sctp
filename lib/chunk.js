const debug = require('debug')('sctp:chunk')

const defs = require('./defs')

const chunkdefs = defs.chunkdefs
const tlvs = defs.tlvs

class Chunk {
  constructor(chunkType, options) {
    if (Buffer.isBuffer(chunkType)) {
      this.fromBuffer(chunkType)
      return
    }
    if (!chunkdefs[chunkType]) {
      return
    }
    this.chunkType = chunkType
    options = options || {}
    this.flags = options.flags
    const chunkParams = chunkdefs[chunkType].params || {}
    for (const param in chunkParams) {
      if (param in options) {
        this[param] = options[param]
      } else if ('default' in chunkParams[param]) {
        this[param] = chunkParams[param].default
      } else {
        this[param] = chunkParams[param].type.default
      }
    }
    for (const param in options) {
      if (param in tlvs) {
        this[param] = options[param]
      }
    }
    debug('new chunk %O', this)
  }

  fromBuffer(buffer) {
    let offset = 0
    let chunkParams
    const chunkId = buffer.readUInt8(offset)
    const flags = buffer.readUInt8(offset + 1)
    this.length = buffer.readUInt16BE(offset + 2)
    if (this.length < buffer.length - 3 || this.length > buffer.length) {
      return
    }
    offset += 4
    if (chunkdefs[chunkId]) {
      this.chunkType = chunkdefs[chunkId].chunkType
      chunkParams = chunkdefs[this.chunkType].params || {}
    } else {
      this.chunkType = null
      this.action = chunkId >> 6
      return
    }
    if (chunkdefs[this.chunkType].flags_filter) {
      // Todo memoize, too often to decode
      this.flags = chunkdefs[this.chunkType].flags_filter.decode.call(this, flags)
    }
    for (const key in chunkParams) {
      if (offset >= this.length) {
        break
      }
      this[key] = chunkParams[key].type.read(buffer, offset, this.length - offset)
      offset += chunkParams[key].type.size(this[key])
    }
    let padding
    while (offset + 4 <= this.length) {
      const tlvId = buffer.readUInt16BE(offset)
      const length = buffer.readUInt16BE(offset + 2)
      const tlv = tlvs[tlvId]
      if (!tlv) {
        if (tlvId & 0x4000) {
          if (!this.errors) {
            this.errors = []
          }
          this.errors.push(buffer.slice(offset, offset + length))
        }
        offset += length
        if (tlvId & 0x8000) {
          continue
        } else {
          break
        }
      }
      const tag = tlv.tag
      if (tlv.multiple) {
        if (!this[tag]) {
          this[tag] = []
        }
        this[tag].push(tlv.type.read(buffer, offset + 4, length - 4))
      } else {
        this[tag] = tlv.type.read(buffer, offset + 4, length - 4)
      }
      offset += length
      padding = length % 4
      offset += padding
    }
    this._filter('decode')
  }

  static fromBuffer(buffer) {
    if (buffer.length < 4) {
      return false
    }
    return new Chunk(buffer)
  }

  toBuffer() {
    if (this.buffer) {
      return this.buffer
    }
    const chunkId = chunkdefs[this.chunkType].id
    this.message_length = 4
    let offset = this.message_length
    let flags = 0
    if (chunkdefs[this.chunkType].flags_filter) {
      flags = chunkdefs[this.chunkType].flags_filter.encode.call(this, this.flags)
    }
    this._filter('encode')
    const chunkParams = chunkdefs[this.chunkType].params || {}
    let length
    let padding
    for (const param in this) {
      const value = this[param]
      if (chunkParams[param]) {
        length = chunkParams[param].type.size(value)
        this.message_length += length
      } else if (tlvs[param]) {
        const values = tlvs[param].multiple ? value : [value]
        values.forEach(value => {
          if (value === false) {
            return
          } // Todo comment
          length = tlvs[param].type.size(value) + 4
          this.message_length += length
          // Variable-length parameter padding
          padding = length % 4
          if (padding) {
            this.message_length += 4 - padding
          }
        })
      }
    }

    if (padding) {
      // Padding of the final parameter should be the padding of the chunk
      // discount it from message length
      this.message_length -= 4 - padding
    }
    let bufferLength = this.message_length
    const chunkPadding = this.message_length % 4
    if (chunkPadding > 0) {
      bufferLength += 4 - chunkPadding
    }
    const buffer = Buffer.alloc(bufferLength)
    buffer.writeUInt8(chunkId, 0)
    buffer.writeUInt8(flags, 1)
    buffer.writeUInt16BE(this.message_length, 2)
    // Write mandatory params
    for (const param in chunkParams) {
      chunkParams[param].type.write(this[param], buffer, offset)
      offset += chunkParams[param].type.size(this[param])
    }
    // Write optional variable-length params
    for (const param in this) {
      const value = this[param]
      if (tlvs[param]) {
        const values = tlvs[param].multiple ? value : [value]
        values.forEach(value => {
          if (value === false) {
            return
          }
          buffer.writeUInt16BE(tlvs[param].id, offset)
          const length = tlvs[param].type.size(value)
          buffer.writeUInt16BE(length + 4, offset + 2)
          offset += 4
          tlvs[param].type.write(value, buffer, offset)
          offset += length
          padding = length % 4
          if (padding) {
            offset += 4 - padding
          }
        })
      }
    }
    return buffer
  }

  _filter(func) {
    const chunkParams = chunkdefs[this.chunkType].params || {}
    for (const param in this) {
      if (chunkParams[param] && chunkParams[param].filter) {
        this[param] = chunkParams[param].filter[func].call(this, this[param])
      } else if (tlvs[param] && tlvs[param].filter) {
        if (tlvs[param].multiple) {
          if (!Array.isArray(this[param])) {
            throw new TypeError('parameter can be multiple, but is not an array: ' + param)
          }
          this[param].forEach(
            (value, i) => {
              this[param][i] = tlvs[param].filter[func].call(this, value)
            }
          )
        } else {
          this[param] = tlvs[param].filter[func].call(this, this[param])
        }
      }
    }
  }
}

module.exports = Chunk
