const debug = require('debug')('sctp:chunk')

const defs = require('./defs')

const chunkdefs = defs.chunkdefs
const tlvs = defs.tlvs

class Chunk {
  constructor (chunkType, options) {
    if (Buffer.isBuffer(chunkType)) {
      this.fromBuffer(chunkType)
      return
    }
    if (!chunkdefs[chunkType]) {
      return
    }

    this.chunkType = chunkType
    this.chunkId = chunkdefs[chunkType].id
    options = options || {}
    this.flags = options.flags || {}
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

  fromBuffer (buffer) {
    let offset = 0
    let chunkParams
    const chunkId = buffer.readUInt8(offset)
    this.chunkId = chunkId
    const flags = buffer.readUInt8(offset + 1)
    this.length = buffer.readUInt16BE(offset + 2)
    if (this.length < buffer.length - 3 || this.length > buffer.length) {
      this.error = true
      return
    }
    offset += 4
    if (chunkdefs[chunkId]) {
      this.chunkType = chunkdefs[chunkId].chunkType
      chunkParams = chunkdefs[this.chunkType].params || {}
    } else {
      this.action = chunkId >> 6
      debug('unrecognized chunk', chunkId)
      return
    }
    const minSize = chunkdefs[chunkId].size || 4
    debug('decoding chunk %O', this, buffer)
    if (this.length < minSize) {
      this.error = true
      return
    }
    this.flags = {}
    if (chunkdefs[this.chunkType].flags_filter) {
      // Todo memoize, too often to decode
      this.flags = chunkdefs[this.chunkType].flags_filter.decode.call(this, flags)
    }
    for (const key in chunkParams) {
      // Too verbose
      // debug('key %s offset %d, chunk length %d', key, offset,  this.length, buffer)
      this[key] = chunkParams[key].type.read(buffer, offset, this.length - offset)
      offset += chunkParams[key].type.size(this[key])
    }
    let padding
    while (offset + 4 <= this.length) {
      const tlvId = buffer.readUInt16BE(offset)
      const length = buffer.readUInt16BE(offset + 2)
      padding = length % 4
      if (padding) {
        padding = 4 - padding
      }
      const tlv = tlvs[tlvId]
      if (!tlv) {
        let action = tlvId >> 14
        debug('unrecognized parameter %s, action %s', tlvId, action)
        debug(buffer.slice(offset))
        if (tlvId & 0x4000) {
          if (!this.errors) {
            this.errors = []
          }
          let param = buffer.slice(offset, offset + length + padding)
          if (param.length % 4) {
            // last param can be not padded, let's pad it
            param = Buffer.concat([param, Buffer.alloc(4 - param.length % 4)])
          }
          this.errors.push(param)
        }
        // offset += length
        if (tlvId & 0x8000) {
          // continue
        } else {
          break
        }
      } else {
        const tag = tlv.tag
        if (tlv.multiple) {
          if (!this[tag]) {
            this[tag] = []
          }
          this[tag].push(tlv.type.read(buffer, offset + 4, length - 4))
        } else {
          this[tag] = tlv.type.read(buffer, offset + 4, length - 4)
        }
      }
      offset += length + padding
      debug('length %d, padding %d', length, padding)
    }

    this._filter('decode')
    delete this.length
  }

  static fromBuffer (buffer) {
    if (buffer.length < 4) {
      return false
    }
    const chunk = new Chunk(buffer)
    debug('decoded chunk %O', chunk)
    return chunk
  }

  toBuffer () {
    if (this.buffer) {
      return this.buffer
    }
    const chunkId = chunkdefs[this.chunkType].id
    this.length = 4
    let offset = this.length
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
        this.length += length
      } else if (tlvs[param]) {
        const values = tlvs[param].multiple ? value : [value]
        values.forEach(value => {
          if (value === undefined || value === false) {
            return
          } // Todo comment
          length = tlvs[param].type.size(value) + 4
          this.length += length
          // Variable-length parameter padding
          padding = length % 4
          if (padding) {
            padding = 4 - padding
            this.length += padding
            debug('encode tlv to buff, add padding %d, length %d', padding, length)
          }
        })
      }
    }

    if (padding) {
      // Padding of the final parameter should be the padding of the chunk
      // discount it from message length
      this.length -= padding
    }

    let bufferLength = this.length
    const chunkPadding = this.length % 4
    if (chunkPadding > 0) {
      debug('chunk padding %d, length %d', chunkPadding, length)
      bufferLength += 4 - chunkPadding
    }

    const buffer = Buffer.alloc(bufferLength)
    buffer.writeUInt8(chunkId, 0)
    buffer.writeUInt8(flags, 1)
    buffer.writeUInt16BE(this.length, 2)

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
          if (value === undefined || value === false) {
            return
          }
          buffer.writeUInt16BE(tlvs[param].id, offset)
          const length = tlvs[param].type.size(value)
          padding = length % 4
          if (padding) {
            padding = 4 - padding
          }
          buffer.writeUInt16BE(length + 4, offset + 2)
          // offset += 4
          tlvs[param].type.write(value, buffer, offset + 4)
          offset += 4 + length + padding
        })
      }
    }
    return buffer
  }

  _filter (func) {
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
