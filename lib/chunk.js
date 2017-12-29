const _ = require('lodash')
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
    let params = chunkdefs[chunkType].params || {}
    let chunk = this
    _.each(params, function (param, key) {
      if (key in options) {
        chunk[key] = options[key]
      } else if ('default' in params[key]) {
        chunk[key] = params[key].default
      } else {
        chunk[key] = params[key].type.default
      }
    })
    _.each(options, function (value, key) {
      if (key in tlvs) {
        chunk[key] = value
      }
    })
  }

  fromBuffer(buffer) {
    let offset = 0
    let params
    let chunkId = buffer.readUInt8(offset)
    this.action = chunkId >> 6
    let flags = buffer.readUInt8(offset + 1)
    this.length = buffer.readUInt16BE(offset + 2)
    if (this.length < buffer.length - 3 || this.length > buffer.length) {
      return
    }
    offset += 4
    if (chunkdefs[chunkId]) {
      this.chunkType = chunkdefs[chunkId].chunkType
      params = chunkdefs[this.chunkType].params || {}
    } else {
      this.chunkType = null
      this.action = chunkId >> 6
      return
    }
    if (chunkdefs[this.chunkType].flags_filter) {
      // todo memoize, too often to decode
      this.flags = chunkdefs[this.chunkType].flags_filter.decode.call(this, flags)
    }
    for (let key in params) {
      if (offset >= this.length) {
        break
      }
      if (params.hasOwnProperty(key)) {
        this[key] = params[key].type.read(buffer, offset, this.length - offset)
        offset += params[key].type.size(this[key])
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
        if (tlvId & 0x8000)
          continue
        else
          break
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
      flags = chunkdefs[this.chunkType].flags_filter.encode.call(this, this.flags)
    }
    this._filter('encode')
    let params = chunkdefs[this.chunkType].params || {}
    let length
    let padding
    let chunk = this
    _.each(chunk, function (value, key) {
      if (params[key]) {
        length = params[key].type.size(value)
        chunk.message_length += length
      } else if (tlvs[key]) {
        // todo rewrite without lodash and creating array
        let values = tlvs[key].multiple ? value : [value]
        _.each(values, function (value) {
          if (value === false) return
          length = tlvs[key].type.size(value) + 4
          chunk.message_length += length
          // variable-length parameter padding
          padding = length % 4
          if (padding) {
            chunk.message_length += (4 - padding)
          }
        })
      }
    })
    /*
     The Chunk Length value does not include terminating padding of the
     chunk.  However, it does include padding of any variable-length
     parameter except the last parameter in the chunk.

     The total length of a chunk (including Type, Length, and Value
     fields) MUST be a multiple of 4 bytes.  If the length of the chunk is
     not a multiple of 4 bytes, the sender MUST pad the chunk with all
     zero bytes, and this padding is not included in the Chunk Length
     field.  The sender MUST NOT pad with more than 3 bytes.  The receiver
     MUST ignore the padding bytes.

     Note: A robust implementation should accept the chunk whether or
     not the final padding has been included in the Chunk Length.
     */
    if (padding) {
      // padding of the final parameter should be the padding of the chunk - discount it from message length
      chunk.message_length -= (4 - padding)
    }
    let buffer_length = chunk.message_length
    let chunkPadding = chunk.message_length % 4
    if (chunkPadding > 0) {
      buffer_length += 4 - chunkPadding
    }
    let buffer = Buffer.alloc(buffer_length)
    buffer.writeUInt8(chunkId, 0)
    buffer.writeUInt8(flags, 1)
    buffer.writeUInt16BE(this.message_length, 2)
    // write mandatory params
    _.each(params, function (param, key) {
      param.type.write(chunk[key], buffer, offset)
      offset += param.type.size(chunk[key])
    })
    // write optional variable-length params
    _.each(chunk, function (value, key) {
      if (tlvs[key]) {
        let values = tlvs[key].multiple ? value : [value]
        _.each(values, function (value) {
          if (value === false) return
          buffer.writeUInt16BE(tlvs[key].id, offset)
          let length = tlvs[key].type.size(value)
          buffer.writeUInt16BE(length + 4, offset + 2)
          offset += 4
          tlvs[key].type.write(value, buffer, offset)
          offset += length
          padding = length % 4
          if (padding) offset += (4 - padding)
        })
      }
    })
    return buffer
  }

  _filter(func) {
    let params = chunkdefs[this.chunkType].params || {}
    for (let key in this) {
      if (params[key] && params[key].filter) {
        this[key] = params[key].filter[func].call(this, this[key])
      } else if (tlvs[key] && tlvs[key].filter) {
        if (tlvs[key].multiple) {
          if (!Array.isArray(this[key])) throw new Error('parameter can be multiple, but is not an array: ' + key)
          this[key].forEach(function (value, i) {
            this[key][i] = tlvs[key].filter[func].call(this, value)
          }.bind(this))
        } else {
          this[key] = tlvs[key].filter[func].call(this, this[key])
        }
      }
    }
  }
}


module.exports = Chunk
