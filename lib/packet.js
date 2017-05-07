'use strict';

var _ = require('lodash');
var util = require('util');
var defs = require('./defs');

var chunkdefs = defs.chunkdefs;
var tlvs = defs.tlvs;

var crc32 = require('fast-crc32c');



function Chunk(chunkType, options) {
    if (Buffer.isBuffer(chunkType)) {
        return this.fromBuffer(chunkType)
    }
    this.chunkType = chunkType;
    this.chunkId = chunkdefs[chunkType].id;
    if (typeof options !== 'object') {
        options = {}
    }
    this.flags = options.flags;
    var params = chunkdefs[chunkType].params || {};
    var chunk = this;
    _.each(params, function (param, key) {
        if (key in options) {
            chunk[key] = options[key]
        } else if ('default' in params[key]) {
            chunk[key] = params[key].default
        } else {
            chunk[key] = params[key].type.default
        }
    });
    _.each(options, function (value, key) {
        if (key in tlvs) {
            chunk[key] = value
        }
    });
}


Chunk.prototype.fromBuffer = function (buffer) {
    var offset = 0;
    var params;
    this.chunkId = buffer.readUInt8(offset);
    this.flags = buffer.readUInt8(offset + 1);
    this.length = buffer.readUInt16BE(offset + 2);
    if (this.length < buffer.length - 3 || this.length > buffer.length) {
        return
    }
    offset += 4;
    if (chunkdefs[this.chunkId]) {
        this.chunkType = chunkdefs[this.chunkId].chunkType;
        params = chunkdefs[this.chunkType].params || {}
    } else {
        this.chunkType = null;
        this.action = this.chunkId >> 6;
        return
    }
    if (chunkdefs[this.chunkType].flags_filter) {
        this.flags = chunkdefs[this.chunkType].flags_filter.decode.call(this, this.flags)
    }
    for (var key in params) {
        if (offset >= this.length) {
            break
        }
        if (params.hasOwnProperty(key)) {
            this[key] = params[key].type.read(buffer, offset, this.length - offset);
            offset += params[key].type.size(this[key])
        }
    }
    var padding;
    while (offset + 4 <= this.length) {
        var tlvId = buffer.readUInt16BE(offset);
        var length = buffer.readUInt16BE(offset + 2);
        var tlv = tlvs[tlvId];
        if (!tlv) {
            if (tlvId & 0x4000) {
                if (!this.errors) this.errors = [];
                this.errors.push(buffer.slice(offset, offset + length))
            }
            offset += length;
            if (tlvId & 0x8000)
                continue;
            else
                break
        }
        var tag = tlv.tag;
        if (tlv.multiple) {
            if (!this[tag]) {
                this[tag] = []
            }
            this[tag].push(tlv.type.read(buffer, offset + 4, length - 4))
        } else {
            this[tag] = tlv.type.read(buffer, offset + 4, length - 4)
        }
        offset += length;
        padding = length % 4;
        offset += padding
    }
    this._filter('decode')
};


Chunk.fromBuffer = function (buffer) {
    if (buffer.length < 4) {
        return false
    }
    return new Chunk(buffer)
};


Chunk.prototype.toBuffer = function () {
    if (this.buffer)
        return this.buffer;
    this.message_length = 4;
    var offset = this.message_length;
    if (chunkdefs[this.chunkType].flags_filter) {
        this.flags = chunkdefs[this.chunkType].flags_filter.encode.call(this, this.flags)
    } else {
        this.flags = 0
    }
    this._filter('encode');
    var params = chunkdefs[this.chunkType].params || {};
    var length;
    var key;
    var padding;
    var chunk = this;
    _.each(chunk, function (value, key) {
        if (params[key]) {
            length = params[key].type.size(value);
            chunk.message_length += length
        } else if (tlvs[key]) {
            var values = tlvs[key].multiple ? value : [value];
            _.each(values, function (value) {
                if (value === false) return;
                length = tlvs[key].type.size(value) + 4;
                chunk.message_length += length;
                // variable-length parameter padding
                padding = length % 4;
                if (padding) {
                    chunk.message_length += (4 - padding);
                }
            });
        }
    });
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
    var buffer_length = chunk.message_length;
    var chunkPadding = chunk.message_length % 4;
    if (chunkPadding > 0) {
        buffer_length += 4 - chunkPadding;
    }
    var buffer = Buffer.alloc(buffer_length);
    buffer.writeUInt8(this.chunkId, 0);
    buffer.writeUInt8(this.flags, 1);
    buffer.writeUInt16BE(this.message_length, 2);
    // write mandatory params
    _.each(params, function (param, key) {
        param.type.write(chunk[key], buffer, offset);
        offset += param.type.size(chunk[key])
    });
    // write optional variable-length params
    _.each(chunk, function (value, key) {
        if (tlvs[key]) {
            var values = tlvs[key].multiple ? value : [value];
            _.each(values, function (value) {
                if (value === false) return;
                buffer.writeUInt16BE(tlvs[key].id, offset);
                var length = tlvs[key].type.size(value);
                buffer.writeUInt16BE(length + 4, offset + 2);
                offset += 4;
                tlvs[key].type.write(value, buffer, offset);
                offset += length;
                padding = length % 4;
                if (padding) offset += (4 - padding)
            });
        }
    });
    return buffer
};


Chunk.prototype._filter = function (func) {
    var params = chunkdefs[this.chunkType].params || {};
    for (var key in this) {
        if (params[key] && params[key].filter) {
            this[key] = params[key].filter[func].call(this, this[key]);
        } else if (tlvs[key] && tlvs[key].filter) {
            if (tlvs[key].multiple) {
                this[key].forEach(function (value, i) {
                    this[key][i] = tlvs[key].filter[func].call(this, value);
                }.bind(this));
            } else {
                this[key] = tlvs[key].filter[func].call(this, this[key]);
            }
        }
    }
};


function Packet(options, chunks) {
    if (Buffer.isBuffer(options)) {
        return this.fromBuffer(options)
    }
    options = options || {};
    this.source_port = options.source_port;
    this.destination_port = options.destination_port;
    this.verification_tag = options.verification_tag;
    this.checksum = 0;
    this.chunks = chunks
}


Packet.fromBuffer = function (buffer) {
    if (buffer.length < 16) {
        return false
    }
    return new Packet(buffer)
};


Packet.prototype.fromBuffer = function (buffer) {
    this.source_port = buffer.readUInt16BE(0);
    this.destination_port = buffer.readUInt16BE(2);
    this.verification_tag = buffer.readUInt32BE(4);
    this.checksum = buffer.readUInt32LE(8);
    buffer.writeUInt32LE(0x000000, 8);
    if (this.checksum === crc32.calculate(buffer, 0)) {
        this.chunks = [];
        var chunk;
        var length = 0;
        var offset = 12;
        var count = 0;
        var padding = 0;
        while (offset + 4 <= buffer.length) {
            count++;
            length = buffer.readUInt16BE(offset + 2);
            if (offset + length > buffer.length) return;
            chunk = buffer.slice(offset, offset + length);
            this.chunks.push(chunk);
            offset += length;
            padding = length % 4;
            if (padding) offset += (4 - padding)
        }
    }
};


Packet.prototype.toBuffer = function () {
    var buffers = [];
    if (!(this.chunks instanceof Array)) return;
    var header = Buffer.alloc(12);
    header.writeUInt16BE(this.source_port, 0);
    header.writeUInt16BE(this.destination_port, 2);
    header.writeUInt32BE(this.verification_tag, 4);
    header.writeUInt32LE(0x000000, 8);
    buffers.push(header);
    this.chunks.forEach(function (chunk) {
        buffers.push(chunk)
    });
    var buffer = Buffer.concat(buffers);
    this.checksum = crc32.calculate(buffer, 0);
    buffer.writeUInt32LE(this.checksum, 8);
    return buffer
};


exports.Packet = Packet;
exports.Chunk = Chunk;
