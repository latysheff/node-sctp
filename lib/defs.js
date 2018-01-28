/*

 https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml

 */

const ip = require('ip')

const NET_SCTP = {
  G: 50, // Granularity
  RWND: 1024 * 100,
  rto_initial: 3000,
  rto_min: 1000,
  rto_max: 60000,
  rto_alpha_exp_divisor: 3,
  rto_beta_exp_divisor: 2,
  valid_cookie_life: 60000,
  max_burst: 4,
  association_max_retrans: 10, // Todo
  cookie_hmac_alg: 'sha1',
  max_init_retransmits: 8,
  hb_interval: 30000,
  sack_timeout: 180,
  sack_freq: 2
}

const CAUSE_CODES = {
  INVALID_STREAM_IDENTIFIER: 0x0001,
  MISSING_MANDATORY_PARAMETER: 0x0002,
  STALE_COOKIE_ERROR: 0x0003,
  OUT_OF_RESOURCE: 0x0004,
  UNRESOLVABLE_ADDRESS: 0x0005,
  UNRECONGNIZED_CHUNK_TYPE: 0x0006,
  INVALID_MANDATORY_PARAMETER: 0x0007,
  UNRECONGNIZED_PARAMETERS: 0x0008,
  NO_USER_DATA: 0x0009,
  COOKIE_RECEIVED_WHILE_SHUTTING_DOWN: 0x000A,
  RESTART_WITH_NEW_ADDRESSES: 0x000B,
  USER_INITIATED_ABORT: 0x000C,
  PROTOCOL_VIOLATION: 0x000D,
  UNSUPPORTED_HMAC_IDENTIFIER: 0x0105
}

revert(CAUSE_CODES)

/*

 Todo
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
  for (const key in hash) {
    const value = hash[key]
    if (key1 && key2) {
      hash[value[key1]] = value
      value[key2] = key
    } else {
      hash[value] = key
    }
  }
}

const types = {
  int8: {
    read(buffer, offset) {
      return buffer.readUInt8(offset)
    },
    write(value, buffer, offset) {
      value = value || 0
      buffer.writeUInt8(value, offset)
    },
    size() {
      return 1
    },
    default: 0
  },
  int16: {
    read(buffer, offset) {
      return buffer.readUInt16BE(offset)
    },
    write(value, buffer, offset) {
      value = value || 0
      buffer.writeUInt16BE(value, offset)
    },
    size() {
      return 2
    },
    default: 0
  },
  int32: {
    read(buffer, offset) {
      return buffer.readUInt32BE(offset)
    },
    write(value, buffer, offset) {
      value = value || 0
      buffer.writeUInt32BE(value, offset)
    },
    size() {
      return 4
    },
    default: 0
  },
  buffer: {
    read(buffer, offset, length) {
      return buffer.slice(offset, offset + length)
      // Return Buffer.from(buffer.slice(offset, offset + length))
    },
    write(value, buffer, offset) {
      if (typeof value === 'string') {
        value = Buffer.from(value, 'ascii')
      }
      value.copy(buffer, offset)
    },
    size(value) {
      return value.length || 0
    },
    default: Buffer.alloc(0)
  },
  empty: {
    read() {
      return true
    },
    write() {
    },
    size() {
      return 0
    },
    default: false
  },
  string: {
    read(buffer, offset, length) {
      return buffer.slice(offset, offset + length).toString('ascii')
    },
    write(value, buffer, offset) {
      Buffer.from(value, 'ascii').copy(buffer, offset)
    },
    size(value) {
      return value.length
    },
    default: ''
  }
}

const filters = {}

filters.data_flags = {
  encode(value) {
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
  decode(value) {
    const result = {
      B: (value >> 1) & 0x01,
      E: value & 0x01,
      U: (value >> 2) & 0x01,
      I: (value >> 3) & 0x01
    }
    return result
  }
}

filters.reflect_flag = {
  encode(value) {
    let result
    if (typeof value === 'object') {
      result = value.T ? 0x01 : 0x00
    } else {
      result = value
    }
    return result
  },
  decode(value) {
    const result = {
      T: value & 0x01
    }
    return result
  }
}

filters.ip = {
  encode(value) {
    if (Buffer.isBuffer(value)) {
      return value
    }
    return ip.toBuffer(value)
  },
  decode(value) {
    if (!Buffer.isBuffer(value)) {
      return value
    }
    return ip.toString(value)
  }
}

filters.sack_info = {
  encode(value) {
    let result = Buffer.alloc(0)
    if (!value) {
      return result
    }
    // If (typeof value === 'object') {
    let offset = 0
    if (Array.isArray(value.gap_blocks) && value.gap_blocks.length > 0) {
      this.gap_blocks_number = value.gap_blocks.length
      offset = 0
      const gapBlocksBuffer = Buffer.alloc(value.gap_blocks.length * 4)
      value.gap_blocks.forEach(gapBlock => {
        if (offset <= gapBlocksBuffer.length - 4) {
          gapBlocksBuffer.writeUInt16BE(gapBlock.start, offset)
          gapBlocksBuffer.writeUInt16BE(gapBlock.finish, offset + 2)
          offset += 4
        } else {
          // Todo tmp to catch bug if any
          throw new Error('incorrect buffer length for gap blocks')
        }
      })
      result = gapBlocksBuffer
    }
    if (Array.isArray(value.duplicate_tsn) && value.duplicate_tsn.length > 0) {
      this.duplicate_tsn_number = value.duplicate_tsn.length
      offset = 0
      const duplicateTsnBuffer = Buffer.alloc(value.duplicate_tsn.length * 4)
      value.duplicate_tsn.forEach(tsn => {
        duplicateTsnBuffer.writeUInt32BE(tsn, offset)
        offset += 4
      })
      result = Buffer.concat([result, duplicateTsnBuffer])
    }
    // }
    return result
  },
  decode(buffer) {
    const result = {
      gap_blocks: [],
      duplicate_tsn: []
    }
    let offset = 0
    let gapBlock
    for (let n = 1; n <= this.gap_blocks_number; n++) {
      if (offset > buffer.length - 4) {
        break
      }
      gapBlock = {
        start: buffer.readUInt16BE(offset),
        finish: buffer.readUInt16BE(offset + 2)
      }
      result.gap_blocks.push(gapBlock)
      offset += 4
    }
    for (let x = 1; x <= this.duplicate_tsn_number; x++) {
      if (offset > buffer.length - 4) {
        break
      }
      result.duplicate_tsn.push(buffer.readUInt32BE(offset))
      offset += 4
    }
    return result
  }
}

filters.error_causes = {
  encode(value) {
    if (!Array.isArray(value) || value.length === 0) {
      return Buffer.alloc(0)
    }
    const buffers = []
    let header
    let body
    value.forEach(error => {
      header = Buffer.alloc(4)
      if (error.cause) {
        error.cause_code = CAUSE_CODES[error.cause]
      }
      header.writeUInt16BE(error.cause_code, 0)
      switch (error.cause_code) {
        case CAUSE_CODES.INVALID_STREAM_IDENTIFIER:
          body = Buffer.alloc(4)
          body.writeUInt16BE(error.stream_id, 0)
          break
        case CAUSE_CODES.UNRECONGNIZED_CHUNK_TYPE:
          body = Buffer.from(error.unrecognized_chunk)
          break
        case CAUSE_CODES.UNRECONGNIZED_PARAMETERS:
          body = Buffer.from(error.unrecognized_parameters)
          break
        case CAUSE_CODES.PROTOCOL_VIOLATION:
          body = Buffer.from(error.additional_information || '')
          break
        case CAUSE_CODES.USER_INITIATED_ABORT:
          body = Buffer.from(error.abort_reason || '')
          break
        default:
          body = Buffer.alloc(0)
      }
      header.writeUInt16BE(body.length + 4, 2)
      buffers.push(Buffer.concat([header, body]))
    })
    return Buffer.concat(buffers)
  },
  decode(buffer) {
    let offset = 0
    const result = []
    let errorLength
    let body
    while (offset + 4 <= buffer.length) {
      const error = {}
      error.cause_code = buffer.readUInt16BE(offset)
      error.cause = CAUSE_CODES[error.cause_code]
      errorLength = buffer.readUInt16BE(offset + 2)
      if (errorLength > 4) {
        body = buffer.slice(offset + 4, offset + 4 + errorLength)
        switch (error.cause_code) {
          case CAUSE_CODES.INVALID_STREAM_IDENTIFIER:
            error.stream_id = body.readUInt16BE(0)
            break
          case CAUSE_CODES.MISSING_MANDATORY_PARAMETER:
            // TODO:
            break
          case CAUSE_CODES.STALE_COOKIE_ERROR:
            error.measure_of_staleness = body.readUInt32BE(0)
            break
          case CAUSE_CODES.OUT_OF_RESOURCE:
            break
          case CAUSE_CODES.UNRESOLVABLE_ADDRESS:
            // https://sourceforge.net/p/lksctp/mailman/message/26542493/
            error.hostname = body.slice(4, 4 + body.readUInt16BE(2)).toString()
            break
          case CAUSE_CODES.UNRECONGNIZED_CHUNK_TYPE:
            error.unrecognized_chunk = body
            break
          case CAUSE_CODES.INVALID_MANDATORY_PARAMETER:
            break
          case CAUSE_CODES.UNRECONGNIZED_PARAMETERS:
            // TODO: slice
            error.unrecognized_parameters = body
            break
          case CAUSE_CODES.NO_USER_DATA:
            error.tsn = body.readUInt32BE(0)
            break
          case CAUSE_CODES.COOKIE_RECEIVED_WHILE_SHUTTING_DOWN:
            break
          case CAUSE_CODES.RESTART_WITH_NEW_ADDRESSES:
            // TODO:
            break
          case CAUSE_CODES.USER_INITIATED_ABORT:
            error.abort_reason = body.toString()
            break
          case CAUSE_CODES.PROTOCOL_VIOLATION:
            error.additional_information = body.toString()
            break
          default:
            error.body = body
            return
        }
      }
      offset += errorLength
      result.push(error)
    }
    return result
  }
}

filters.reconf = {
  encode: (value) => {
    let buffer = Buffer.alloc(12)
    buffer.writeUInt32BE(value.rsn, 0)
    return buffer
  },
  decode: (buffer) => {
    if (buffer.length < 4) return
    let value = {}
    value.rsn = buffer.readUInt32BE(0)
    return value
  }
}

filters.forward_tsn_stream = {
  encode: (value) => {
    value = value || {}
    let buffer = Buffer.alloc(4)
    buffer.writeUInt16BE(value.stream_id, 0)
    buffer.writeUInt16BE(value.ssn, 0)
    return buffer
  },
  decode: (buffer) => {
    if (buffer.length < 4) return
    let value = {}
    value.stream_id = buffer.readUInt16BE(0)
    value.ssn = buffer.readUInt16BE(2)
    return value
  }
}

filters.chunks = {
  encode: (value) => {
    if (!Array.isArray(value)) return
    if (value.length > 260) return
    let array = value
      .filter(chunkType => typeof chunkType === 'string')
      .map(chunkType => chunkdefs[chunkType].id)
    return Buffer.from(array)
  },
  decode: (buffer) => {
    return [...buffer]
      .map(byte => chunkdefs[byte].chunkType)
  }
}

filters.hmac_algo = {
  encode: (value) => {
    if (!Array.isArray(value)) return
    const HMAC_ALGO = {
      'SHA-1': 1,
      'SHA-256': 3
    }
    let array = value
      .filter(algo => typeof algo === 'string')
      .map(algo => HMAC_ALGO[algo.toUpperCase()])
      .filter(algo => algo)
    let buffer = Buffer.alloc(array.length * 2)
    array.forEach((number, index) => {
      buffer.writeUInt16BE(number, index * 2)
    })
    return buffer
  },
  decode: (buffer) => {
    let result = []
    const HMAC_ALGO = [
      undefined,
      'SHA-1',
      undefined,
      'SHA-256'
    ]
    for (let index = 0; index <= buffer.length - 2; index += 2) {
      let algo = HMAC_ALGO[buffer.readUInt16BE(index)]
      if (algo) {
        result.push(algo)
      }
    }
    return result
  }
}


const tlvs = {
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
    id: 0x000B,
    type: types.string
  },
  supported_address_type: {
    id: 0x000C,
    type: types.int16
  },
  ssn_reset_outgoing: {
    id: 13,
    type: types.buffer,
    filter: filters.reconf
  },
  ssn_reset_incoming: {
    id: 14,
    type: types.buffer,
    filter: filters.reconf
  },
  ssn_tsn_reset: {
    id: 15,
    type: types.buffer,
    filter: filters.reconf
  },
  re_config_response: {
    id: 16,
    type: types.buffer,
    filter: filters.reconf
  },
  add_streams_outgoing: {
    id: 17,
    type: types.buffer,
    filter: filters.reconf
  },
  add_streams_incoming: {
    id: 18,
    type: types.buffer,
    filter: filters.reconf
  },
  ecn_supported: {
    id: 0x8000, // 1000 0000 0000 0000 - '10' - skip and continue
    type: types.empty
  },
  random: {
    id: 0x8002, // 1000 0000 0000 0010
    type: types.buffer
  },
  chunks: {
    id: 0x8003, // 1000 0000 0000 0011
    type: types.buffer,
    filter: filters.chunks
  },
  hmac_algo: {
    id: 0x8004, // 1000 0000 0000 0100
    type: types.buffer,
    filter: filters.hmac_algo
  },
  pad: {
    id: 0x8005, // 1000 0000 0000 0101
    type: types.buffer
  },
  supported_extensions: {
    id: 0x8008, // 1000 0000 0000 1000
    type: types.buffer
  },
  forward_tsn_supported: {
    id: 0xC000, // 1100 0000 0000 0000 - '11' - skip and report 'Unrecognized Chunk Type'
    type: types.empty
  },
  add_ip_address: {
    id: 0xC001, // 1100 0000 0000 0001
    type: types.buffer
  },
  delete_ip_address: {
    id: 0xC002, // 1100 0000 0000 0010
    type: types.buffer
  },
  error_cause_indication: {
    id: 0xC003, // 1100 0000 0000 0011
    type: types.buffer
  },
  set_primary_address: {
    id: 0xC004, // 1100 0000 0000 0100
    type: types.buffer
  },
  success_indication: {
    id: 0xC005, // 1100 0000 0000 0101
    type: types.buffer
  },
  adaptation_layer_indication: {
    id: 0xC006, // 1100 0000 0000 0110
    type: types.buffer
  },
}

revert(tlvs, 'id', 'tag')

const PPID = {
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

const chunkdefs = {
  data: {
    id: 0x00,
    params: {
      tsn: {type: types.int32, default: null},
      stream_id: {type: types.int16},
      ssn: {type: types.int16},
      ppid: {type: types.int32},
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
      c_tsn_ack: {type: types.int32},
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
      c_tsn_ack: {type: types.int32}
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
    id: 0x0A,
    params: {
      cookie: {type: types.buffer}
    }
  },
  cookie_ack: {
    id: 0x0B
  },
  ecn_echo: {
    id: 0x0C
  },
  cwr: {
    id: 0x0D
  },
  shutdown_complete: {
    id: 0x0E,
    flags_filter: filters.reflect_flag
  },
  auth: {
    id: 0x0F,
    params: {
      shared_key_id: {type: types.int16},
      hmac_id: {type: types.int16},
      hmac: {type: types.buffer}
    }
  },
  i_data: {
    id: 0x40, // 64, 0100 0010
    params: {
      tsn: {type: types.int32, default: null},
      stream_id: {type: types.int16},
      ssn: {type: types.int16},
      message_id: {type: types.int16},
      ppid: {type: types.int32},
      user_data: {type: types.buffer}
    },
    flags_filter: filters.data_flags
  },
  asconf_ack: {
    id: 0x80, // 128, 1000 0000,
    seq: {type: types.int32}
  },
  re_config: {
    id: 0x82, // 130, 1000 0010
  },
  pad: {
    id: 0x84, // 132, 1000 0100
    params: {
      padding_data: {type: types.buffer}
    },
  },
  forward_tsn: {
    id: 0xC0, // 192, 1100 0000
    params: {
      new_c_tsn: {type: types.int32},
      streams: {type: types.buffer, multiple: true, filter: filters.forward_tsn_stream}
    }
  },
  asconf: {
    id: 0xC1, // 193, 1100 0001
    params: {
      seq: {type: types.int32},
      address: {type: types.buffer}
    }
  },
  i_forward_tsn: {
    id: 0xC2, // 194, 1100 0010
    params: {
      new_c_tsn: {type: types.int32},
      streams: {type: types.buffer, multiple: true}
    }
  },
}

revert(chunkdefs, 'id', 'chunkType')

module.exports = {
  NET_SCTP,
  filters,
  chunkdefs,
  types,
  tlvs,
  CAUSE_CODES,
  PPID
}
