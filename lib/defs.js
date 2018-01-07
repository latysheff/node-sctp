/*

 https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml

 */

let ip = require('ip')

let net_sctp = {
  G: 50, // granularity
  RWND: 65000,
  rto_initial: 3000,
  rto_min: 1000,
  rto_max: 60000,
  rto_alpha_exp_divisor: 3,
  rto_beta_exp_divisor: 2,
  valid_cookie_life: 60000,
  max_burst: 4,
  association_max_retrans: 10, // todo
  cookie_hmac_alg: 'md5',
  max_init_retransmits: 8,
  hb_interval: 30000,
  sack_timeout: 180,
  sack_freq: 2
}

/*

 todo
 sysctl -a | grep sctp

net.sctp.addip_enable = 0
net.sctp.addip_noauth_enable = 0
net.sctp.addr_scope_policy = 1
net.sctp.association_max_retrans = 10
net.sctp.auth_enable = 0
net.sctp.cookie_hmac_alg = sha1
net.sctp.cookie_preserve_enable = 1
net.sctp.default_auto_asconf = 0
net.sctp.hb_interval = 30000
net.sctp.max_autoclose = 2147483
net.sctp.max_burst = 4
net.sctp.max_init_retransmits = 8
net.sctp.path_max_retrans = 5
net.sctp.pf_retrans = 0
net.sctp.prsctp_enable = 1
net.sctp.rcvbuf_policy = 0
net.sctp.rto_alpha_exp_divisor = 3
net.sctp.rto_beta_exp_divisor = 2
net.sctp.rto_initial = 3000
net.sctp.rto_max = 60000
net.sctp.rto_min = 1000
net.sctp.rwnd_update_shift = 4
net.sctp.sack_timeout = 200
net.sctp.sctp_mem = 42486	56648	84972
net.sctp.sctp_rmem = 4096	865500	1812736
net.sctp.sctp_wmem = 4096	16384	1812736
net.sctp.sndbuf_policy = 0
net.sctp.valid_cookie_life = 60000

*/

function revert(hash, key1, key2) {
  for (let key in hash) {
    let value = hash[key]
    if (key1 && key2) {
      hash[value[key1]] = value
      value[key2] = key
    } else {
      hash[value] = key
    }
  }
}

let types = {
  int8: {
    read: function (buffer, offset) {
      return buffer.readUInt8(offset)
    },
    write: function (value, buffer, offset) {
      value = value || 0
      buffer.writeUInt8(value, offset)
    },
    size: function () {
      return 1
    },
    default: 0
  },
  int16: {
    read: function (buffer, offset) {
      return buffer.readUInt16BE(offset)
    },
    write: function (value, buffer, offset) {
      value = value || 0
      buffer.writeUInt16BE(value, offset)
    },
    size: function () {
      return 2
    },
    default: 0
  },
  int32: {
    read: function (buffer, offset) {
      return buffer.readUInt32BE(offset)
    },
    write: function (value, buffer, offset) {
      value = value || 0
      buffer.writeUInt32BE(value, offset)
    },
    size: function () {
      return 4
    },
    default: 0
  },
  buffer: {
    read: function (buffer, offset, length) {
      return buffer.slice(offset, offset + length)
      // return Buffer.from(buffer.slice(offset, offset + length))
    },
    write: function (value, buffer, offset) {
      if (typeof value === 'string') {
        value = new Buffer(value, 'ascii')
      }
      value.copy(buffer, offset)
    },
    size: function (value) {
      return value.length || 0
    },
    default: null
  },
  empty: {
    read: function () {
      return true
    },
    write: function () {
    },
    size: function () {
      return 0
    },
    default: false
  },
  string: {
    read: function (buffer, offset, length) {
      return buffer.slice(offset, offset + length).toString('ascii')
    },
    write: function (value, buffer, offset) {
      Buffer.from(value, 'ascii').copy(buffer, offset)
    },
    size: function (value) {
      return value.length
    },
    default: ''
  }
}

let filters = {}

filters.data_flags = {
  encode: function (value) {
    let result
    if (typeof value === 'object') {
      result =
        (value.E ? 0x01 : 0x00) |
        (value.B ? 0x02 : 0x00) |
        (value.U ? 0x04 : 0x00) |
        (value.I ? 0x08 : 0x00)
    } else {
      result = value
    }
    return result
  },
  decode: function (value) {
    let result = {
      E: value & 0x01,
      B: (value >> 1) & 0x01,
      U: (value >> 2) & 0x01,
      I: (value >> 3) & 0x01
    }
    return result
  }
}

filters.reflect_flag = {
  encode: function (value) {
    let result
    if (typeof value === 'object') {
      result =
        (value.T ? 0x01 : 0x00)
    } else {
      result = value
    }
    return result
  },
  decode: function (value) {
    let result = {
      T: value & 0x01
    }
    return result
  }
}

filters.ip = {
  encode: function (value) {
    if (Buffer.isBuffer(value)) {
      return value
    }
    return ip.toBuffer(value)
  },
  decode: function (value) {
    if (!Buffer.isBuffer(value)) {
      return value
    }
    return ip.toString(value)
  }
}

filters.sack_info = {
  encode: function (value) {
    let result = Buffer.alloc(0)
    if (typeof value === 'object') {
      let offset = 0
      if (Array.isArray(value.gap_blocks) && value.gap_blocks.length) {
        this.gap_blocks_number = value.gap_blocks.length
        offset = 0
        let gap_blocks_buffer = Buffer.alloc(value.gap_blocks.length * 4)
        value.gap_blocks.forEach((gap_block) => {
          if (offset <= gap_blocks_buffer.length - 4) {
            gap_blocks_buffer.writeUInt16BE(gap_block.start, offset)
            gap_blocks_buffer.writeUInt16BE(gap_block.finish, offset + 2)
            offset += 4
          } else {
            throw new Error('incorrect buffer length for gap blocks') // todo tmp to catch bug if any
          }
        })
        result = gap_blocks_buffer
      }
      if (Array.isArray(value.duplicate_tsn) && value.duplicate_tsn.length) {
        this.duplicate_tsn_number = value.duplicate_tsn.length
        offset = 0
        let duplicate_tsn_buffer = Buffer.alloc(value.duplicate_tsn.length * 4)
        value.duplicate_tsn.forEach((duplicate_tsn) => {
          duplicate_tsn_buffer.writeUInt32BE(duplicate_tsn, offset)
          offset += 4
        })
        result = Buffer.concat([result, duplicate_tsn_buffer])
      }
    }
    return result
  },
  decode: function (buffer) {
    let result = {
      gap_blocks: [],
      duplicate_tsn: []
    }
    let offset = 0
    let gap_block
    for (let n = 1; n <= this.gap_blocks_number; n++) {
      if (offset > buffer.length - 4) break
      gap_block = {
        start: buffer.readUInt16BE(offset),
        finish: buffer.readUInt16BE(offset + 2)
      }
      result.gap_blocks.push(gap_block)
      offset += 4
    }
    for (let x = 1; x <= this.duplicate_tsn_number; x++) {
      if (offset > buffer.length - 4) break
      result.duplicate_tsn.push(buffer.readUInt32BE(offset))
      offset += 4
    }
    return result
  }
}

filters.error_causes = {
  encode: function (value) {
    if (!Array.isArray(value) || value.length === 0) return Buffer.alloc(0)
    let result
    let buffer_arr = []
    let header
    let body
    value.forEach(function (error) {
      header = Buffer.alloc(4)
      if (error.cause) {
        error.cause_code = cause_codes[error.cause]
      }
      header.writeUInt16BE(error.cause_code, 0)
      switch (error.cause_code) {
        case cause_codes.INVALID_STREAM_IDENTIFIER:
          body = Buffer.alloc(4)
          body.writeUInt16BE(error.stream_identifier, 0)
          break
        case cause_codes.UNRECONGNIZED_CHUNK_TYPE:
          body = Buffer.from(error.unrecognized_chunk)
          break
        case cause_codes.UNRECONGNIZED_PARAMETERS:
          body = Buffer.from(error.unrecognized_parameters)
          break
        case cause_codes.PROTOCOL_VIOLATION:
          body = Buffer.from(error.additional_information)
          break
        case cause_codes.USER_INITIATED_ABORT:
          body = Buffer.from(error.abort_reason)
          break
        default:
          body = Buffer.alloc(0)
      }
      header.writeUInt16BE(body.length + 4, 2)
      buffer_arr.push(Buffer.concat([header, body]))
    })
    result = Buffer.concat(buffer_arr)
    return result
  },
  decode: function (buffer) {
    let offset = 0
    let result = []
    let error_length
    let body
    while (offset + 4 <= buffer.length) {
      let error = {}
      error.cause_code = buffer.readUInt16BE(offset)
      error.cause = cause_codes[error.cause_code]
      error_length = buffer.readUInt16BE(offset + 2)
      if (error_length > 4) {
        body = buffer.slice(offset + 4, offset + 4 + error_length)
        switch (error.cause_code) {
          case cause_codes.INVALID_STREAM_IDENTIFIER:
            error.stream_identifier = body.readUInt16BE(0)
            break
          case cause_codes.MISSING_MANDATORY_PARAMETER:
            // TODO:
            break
          case cause_codes.STALE_COOKIE_ERROR:
            error.measure_of_staleness = body.readUInt32BE(0)
            break
          case cause_codes.OUT_OF_RESOURCE:
            break
          case cause_codes.UNRESOLVABLE_ADDRESS:
            // https://sourceforge.net/p/lksctp/mailman/message/26542493/
            let sub_length = body.readUInt16BE(2)
            error.hostname = body.slice(4, 4 + sub_length).toString()
            break
          case cause_codes.UNRECONGNIZED_CHUNK_TYPE:
            error.unrecognized_chunk = body
            break
          case cause_codes.INVALID_MANDATORY_PARAMETER:
            break
          case cause_codes.UNRECONGNIZED_PARAMETERS:
            // TODO: slice
            error.unrecognized_parameters = body
            break
          case cause_codes.NO_USER_DATA:
            error.tsn = body.readUInt32BE(0)
            break
          case cause_codes.COOKIE_RECEIVED_WHILE_SHUTTING_DOWN:
            break
          case cause_codes.RESTART_WITH_NEW_ADDRESSES:
            // TODO:
            break
          case cause_codes.USER_INITIATED_ABORT:
            error.abort_reason = body.toString()
            break
          case cause_codes.PROTOCOL_VIOLATION:
            error.additional_information = body.toString()
            break
          default:
            error.body = body
            return
        }
      }
      offset += error_length
      result.push(error)
    }
    return result
  }
}

let tlvs = {
  heartbeat_info: {
    id: 0x0001,
    type: types.buffer
  },
  ipv4_address: {
    id: 0x0005,
    type: types.buffer,
    multiple: true,
    filter: filters.ip
  },
  ipv6_address: {
    id: 0x0006,
    type: types.buffer,
    multiple: true,
    filter: filters.ip
  },
  state_cookie: {
    id: 0x0007,
    type: types.buffer
  },
  unrecognized_parameter: {
    id: 0x0008,
    type: types.buffer,
    multiple: true
  },
  cookie_preservative: {
    id: 0x0009,
    type: types.int32
  },
  host_name_address: {
    id: 0x000b,
    type: types.string
  },
  supported_address_type: {
    id: 0x000c,
    type: types.int16
  },
  ecn: {
    id: 0x8000,
    type: types.empty
  },
  forward_tsn_supported: {
    id: 0xc000,
    type: types.empty
  }
}

revert(tlvs, 'id', 'tag')

let cause_codes = {
  INVALID_STREAM_IDENTIFIER: 0x0001,
  MISSING_MANDATORY_PARAMETER: 0x0002,
  STALE_COOKIE_ERROR: 0x0003,
  OUT_OF_RESOURCE: 0x0004,
  UNRESOLVABLE_ADDRESS: 0x0005,
  UNRECONGNIZED_CHUNK_TYPE: 0x0006,
  INVALID_MANDATORY_PARAMETER: 0x0007,
  UNRECONGNIZED_PARAMETERS: 0x0008,
  NO_USER_DATA: 0x0009,
  COOKIE_RECEIVED_WHILE_SHUTTING_DOWN: 0x000a,
  RESTART_WITH_NEW_ADDRESSES: 0x000b,
  USER_INITIATED_ABORT: 0x000c,
  PROTOCOL_VIOLATION: 0x000d
}

revert(cause_codes)

let PPID = {
  SCTP: 0,
  IUA: 1,
  M2UA: 2,
  M3UA: 3,
  SUA: 4,
  M2PA: 5,
  V5UA: 6,
  H248: 7,
  BICC: 8,
  TALI: 9,
  DUA: 10,
  ASAP: 11,
  ENRP: 12,
  H323: 13,
  QIPC: 14,
  SIMCO: 15,
  DDP_CHUNK: 16,
  DDP_CONTROL: 17,
  S1AP: 18,
  RUA: 19,
  HNBAP: 20,
  FORCES_HP: 21,
  FORCES_MP: 22,
  FORCES_LP: 23,
  SBCAP: 24,
  NBAP: 25,
  X2AP: 27,
  IRCP: 28,
  LCSAP: 29,
  MPICH2: 30,
  SABP: 31,
  FGP: 32,
  PPP: 33,
  CALCAPP: 34,
  SSP: 35,
  NPMP_CONTROL: 36,
  NPMP_DATA: 37,
  ECHO: 38,
  DISCARD: 39,
  DAYTIME: 40,
  CHARGEN: 41,
  RNA: 42,
  M2AP: 43,
  M3AP: 44,
  SSH: 45,
  DIAMETER: 46,
  DIAMETER_DTLS: 47,
  BER: 48,
  WEBRTC_DCEP: 50,
  WEBRTC_STRING: 51,
  WEBRTC_BINARY: 53,
  PUA: 55,
  WEBRTC_STRING_EMPTY: 56,
  WEBRTC_BINARY_EMPTY: 57,
  XWAP: 58,
  XWCP: 59,
  NGAP: 60,
  XNAP: 61
}

revert(PPID)

let chunkdefs = {
  data: {
    id: 0x00,
    params: {
      tsn: {type: types.int32, default: null},
      stream_identifier: {type: types.int16},
      stream_sequence_number: {type: types.int16},
      payload_protocol_identifier: {type: types.int32},
      user_data: {type: types.buffer}
    },
    flags_filter: filters.data_flags
  },
  init: {
    id: 0x01,
    params: {
      initiate_tag: {type: types.int32},
      a_rwnd: {type: types.int32},
      outbound_streams: {type: types.int16},
      inbound_streams: {type: types.int16},
      initial_tsn: {type: types.int32}
    }
  },
  init_ack: {
    id: 0x02,
    params: {
      initiate_tag: {type: types.int32},
      a_rwnd: {type: types.int32},
      outbound_streams: {type: types.int16},
      inbound_streams: {type: types.int16},
      initial_tsn: {type: types.int32}
    }
  },
  sack: {
    id: 0x03,
    params: {
      cumulative_tsn_ack: {type: types.int32},
      a_rwnd: {type: types.int32},
      gap_blocks_number: {type: types.int16},
      duplicate_tsn_number: {type: types.int16},
      sack_info: {type: types.buffer, filter: filters.sack_info}
    }
  },
  heartbeat: {
    id: 0x04
  },
  heartbeat_ack: {
    id: 0x05
  },
  abort: {
    id: 0x06,
    params: {
      error_causes: {type: types.buffer, filter: filters.error_causes}
    },
    flags_filter: filters.reflect_flag
  },
  shutdown: {
    id: 0x07,
    params: {
      cumulative_tsn_ack: {type: types.int32}
    }
  },
  shutdown_ack: {
    id: 0x08
  },
  error: {
    id: 0x09,
    params: {
      error_causes: {type: types.buffer, filter: filters.error_causes}
    }
  },
  cookie_echo: {
    id: 0x0a,
    params: {
      cookie: {type: types.buffer}
    }
  },
  cookie_ack: {
    id: 0x0b
  },
  shutdown_complete: {
    id: 0x0e,
    flags_filter: filters.reflect_flag
  }
}

revert(chunkdefs, 'id', 'chunkType')


module.exports = {
  net_sctp,
  filters,
  chunkdefs,
  types,
  tlvs,
  cause_codes,
  PPID
}

