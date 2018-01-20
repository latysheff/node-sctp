const defs = require('./defs')
const chunkdefs = defs.chunkdefs
const tlvs = defs.tlvs

class Chunk {
  constructor(chunkType, options) {
    if (Buffer.isBuffer(chunkType)) {
      this.fromBuffer(chunkType)
      return
    }
    if (!chunkdefs[chunkType]) return
    this.chunkType = chunkType
    options = options || {}
    this.flags = options.flags
    let chunkParams = chunkdefs[chunkType].params || {}
    for (let param in chunkParams) {
      if (param in options) {
        this[param] = options[param]
      } else if ('default' in chunkParams[param]) {
        this[param] = chunkParams[param].default
      } else {
        this[param] = chunkParams[param].type.default
      }
    }
    for (let param in options) {
      if (param in tlvs) {
        this[param] = options[param]
      }
    }
  }

  fromBuffer(buffer) {
    let offset = 0
    let chunkParams
    let chunkId = buffer.readUInt8(offset)
    let flags = buffer.readUInt8(offset + 1)
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
      // todo memoize, too often to decode
      this.flags = chunkdefs[this.chunkType].flags_filter.decode.call(
        this,
        flags
      )
    }
    for (let key in chunkParams) {
      if (offset >= this.length) {
        break
      }
      if (chunkParams.hasOwnProperty(key)) {
        this[key] = chunkParams[key].type.read(
          buffer,
          offset,
          this.length - offset
        )
        offset += chunkParams[key].type.size(this[key])
      }
    }
    let padding
    while (offset + 4 <= this.length) {
      let tlvId = buffer.readUInt16BE(offset)
      let length = buffer.readUInt16BE(offset + 2)
      let tlv = tlvs[tlvId]
      if (!tlv) {
        if (tlvId & 0x4000) {
          if (!this.errors) this.errors = []
          this.errors.push(buffer.slice(offset, offset + length))
        }
        offset += length
        if (tlvId & 0x8000) continue
        else break
      }
      let tag = tlv.tag
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
    if (this.buffer) return this.buffer
    let chunkId = chunkdefs[this.chunkType].id
    this.message_length = 4
    let offset = this.message_length
    let flags = 0
    if (chunkdefs[this.chunkType].flags_filter) {
      flags = chunkdefs[this.chunkType].flags_filter.encode.call(
        this,
        this.flags
      )
    }
    this._filter('encode')
    let chunkParams = chunkdefs[this.chunkType].params || {}
    let length
    let padding
    for (let param in this) {
      let value = this[param]
      if (chunkParams[param]) {
        length = chunkParams[param].type.size(value)
        this.message_length += length
      } else if (tlvs[param]) {
        let values = tlvs[param].multiple ? value : [value]
        values.forEach(value => {
          if (value === false) return // todo comment
          length = tlvs[param].type.size(value) + 4
          this.message_length += length
          // variable-length parameter padding
          padding = length % 4
          if (padding) {
            this.message_length += 4 - padding
          }
        })
      }
    }

    if (padding) {
      // padding of the final parameter should be the padding of the chunk
      // discount it from message length
      this.message_length -= 4 - padding
    }
    let buffer_length = this.message_length
    let chunkPadding = this.message_length % 4
    if (chunkPadding > 0) {
      buffer_length += 4 - chunkPadding
    }
    let buffer = Buffer.alloc(buffer_length)
    buffer.writeUInt8(chunkId, 0)
    buffer.writeUInt8(flags, 1)
    buffer.writeUInt16BE(this.message_length, 2)
    // write mandatory params
    for (let param in chunkParams) {
      chunkParams[param].type.write(this[param], buffer, offset)
      offset += chunkParams[param].type.size(this[param])
    }
    // write optional variable-length params
    for (let param in this) {
      let value = this[param]
      if (tlvs[param]) {
        let values = tlvs[param].multiple ? value : [value]
        values.forEach(value => {
          if (value === false) return
          buffer.writeUInt16BE(tlvs[param].id, offset)
          let length = tlvs[param].type.size(value)
          buffer.writeUInt16BE(length + 4, offset + 2)
          offset += 4
          tlvs[param].type.write(value, buffer, offset)
          offset += length
          padding = length % 4
          if (padding) offset += 4 - padding
        })
      }
    }
    return buffer
  }

  _filter(func) {
    let chunkParams = chunkdefs[this.chunkType].params || {}
    for (let param in this) {
      if (chunkParams[param] && chunkParams[param].filter) {
        this[param] = chunkParams[param].filter[func].call(this, this[param])
      } else if (tlvs[param] && tlvs[param].filter) {
        if (tlvs[param].multiple) {
          if (!Array.isArray(this[param]))
            throw new Error(
              'parameter can be multiple, but is not an array: ' + param
            )
          this[param].forEach(
            function(value, i) {
              this[param][i] = tlvs[param].filter[func].call(this, value)
            }.bind(this)
          )
        } else {
          this[param] = tlvs[param].filter[func].call(this, this[param])
        }
      }
    }
  }
}

module.exports = Chunk
