// https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml

var _ = require('lodash');
var ip = require('ip');


var net_sctp = {
    RWND: 256000,
    rto_initial: 3000,
    rto_min: 1000,
    rto_max: 60000,
    rto_alpha_exp_divisor: 3,
    rto_beta_exp_divisor: 2,
    valid_cookie_life: 60000,
    cookie_hmac_alg: 'md5',
    hb_interval: 30000,
    sack_timeout: 180,
    sack_freq: 2
};

/*
 recommended values
 rto_initial=500
 rto_max=500
 rto_min=250
 sack_timeout=50
 */

var types = {
    int8: {
        read: function (buffer, offset) {
            return buffer.readUInt8(offset)
        },
        write: function (value, buffer, offset) {
            value = value || 0;
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
            value = value || 0;
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
            value = value || 0;
            buffer.writeUInt32BE(value, offset)
        },
        size: function () {
            return 4
        },
        default: 0
    },
    buffer: {
        read: function (buffer, offset, length) {
            return buffer.slice(offset, offset + length);
            // return Buffer.from(buffer.slice(offset, offset + length))
        },
        write: function (value, buffer, offset) {
            if (typeof value == 'string') {
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
        read: function (buffer, offset) {
            return true
        },
        write: function (value, buffer, offset) {

        },
        size: function () {
            return 0
        },
        default: false
    },
    string: {
        read: function (buffer, offset, length) {
            return buffer.toString('ascii', offset, offset + length);
        },
        write: function (value, buffer, offset) {
            if (typeof value == 'string') {
                value = new Buffer(value, 'ascii');
            }
            value.copy(buffer, offset);
        },
        size: function (value) {
            return value.length;
        },
        default: ''
    }
};


var filters = {};

filters.data_flags = {
    encode: function (value) {
        if (typeof value == 'object') {
            var result =
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
        var result = {
            E: value & 0x01,
            B: (value >> 1) & 0x01,
            U: (value >> 2) & 0x01,
            I: (value >> 3) & 0x01
        };
        return result
    }
};

filters.reflect_flag = {
    encode: function (value) {
        if (typeof value == 'object') {
            var result =
                (value.T ? 0x01 : 0x00)
        } else {
            result = value
        }
        return result
    },
    decode: function (value) {
        var result = {
            T: value & 0x01
        };
        return result
    }
};

filters.ip = {
    encode: function (value) {
        if (Buffer.isBuffer(value)) {
            return value;
        }
        return ip.toBuffer(value)
    },
    decode: function (value) {
        if (!Buffer.isBuffer(value)) {
            return value;
        }
        return ip.toString(value)
    }
};

filters.sack_info = {
    encode: function (value) {
        var result = Buffer.alloc(0);
        if (_.isObject(value)) {
            var offset = 0;
            if (_.isArray(value.gap_blocks) && value.gap_blocks.length) {
                offset = 0;
                var gap_blocks_buffer = Buffer.alloc(value.gap_blocks.length * 4);
                _.each(value.gap_blocks, function (gap_block) {
                    gap_blocks_buffer.writeUInt16BE(gap_block.start, offset);
                    gap_blocks_buffer.writeUInt16BE(gap_block.finish, offset + 2);
                    offset += 4
                });
                result = gap_blocks_buffer
            }
            if (_.isArray(value.duplicate_tsn) && value.duplicate_tsn.length) {
                this.duplicate_tsn_number = value.duplicate_tsn.length
                offset = 0;
                var duplicate_tsn_buffer = Buffer.alloc(value.duplicate_tsn.length * 4);
                _.each(value.duplicate_tsn, function (duplicate_tsn) {
                    duplicate_tsn_buffer.writeUInt32BE(duplicate_tsn, offset);
                    offset += 4
                });
                result = Buffer.concat([result, duplicate_tsn_buffer])
            }
        }
        return result
    },
    decode: function (buffer) {
        var result = {
            gap_blocks: [],
            duplicate_tsn: []
        };
        var offset = 0;
        var gap_block;
        for (var n = 1; n <= this.gap_blocks_number; n++) {
            if (offset > buffer.length - 4) break;
            gap_block = {
                start: buffer.readUInt16BE(offset),
                finish: buffer.readUInt16BE(offset + 2)
            };
            result.gap_blocks.push(gap_block);
            offset += 4
        }
        for (var x = 1; x <= this.duplicate_tsn_number; x++) {
            if (offset > buffer.length - 4) break;
            result.duplicate_tsn.push(buffer.readUInt32BE(offset));
            offset += 4
        }
        return result
    }
};


filters.error_causes = {
    encode: function (value) {
        if (!(value instanceof Array) || value.length == 0) return Buffer.alloc(0);
        var result;
        var buffer_arr = [];
        var header;
        var body;
        value.forEach(function (error) {
            header = Buffer.alloc(4);
            if (error.cause) {
                error.cause_code = cause_codes[error.cause]
            }
            header.writeUInt16BE(error.cause_code, 0);
            switch (error.cause_code) {
                case cause_codes.INVALID_STREAM_IDENTIFIER:
                    body = Buffer.alloc(4);
                    body.writeUInt16BE(error.stream_identifier, 0);
                    break;
                case cause_codes.UNRECONGNIZED_PARAMETERS:
                    body = Buffer.from(error.unrecognized_parameters);
                    break;
                case cause_codes.PROTOCOL_VIOLATION:
                    body = Buffer.from(error.additional_information);
                    break;
                default:
                    return;
            }
            header.writeUInt16BE(body.length + 4, 2);
            buffer_arr.push(Buffer.concat([header, body]))
        });
        result = Buffer.concat(buffer_arr);
        return result
    },
    decode: function (buffer) {
        var offset = 0;
        var result = [];
        var error_length;
        var body;
        while (offset + 4 <= buffer.length) {
            var error = {};
            error.cause_code = buffer.readUInt16BE(offset);
            error.cause = cause_codes[error.cause_code];
            error_length = buffer.readUInt16BE(offset + 2);
            if (error_length > 4) {
                body = buffer.slice(offset + 4, offset + 4 + error_length);
                switch (error.cause_code) {
                    case cause_codes.INVALID_STREAM_IDENTIFIER:
                        error.stream_identifier = body.readUInt16BE(0);
                        break;
                    case cause_codes.MISSING_MANDATORY_PARAMETER:
                        break;
                    case cause_codes.STALE_COOKIE_ERROR:
                        error.measure_of_staleness = body.readUInt32BE(0);
                        break;
                    case cause_codes.OUT_OF_RESOURCE:
                        break;
                    case cause_codes.UNRESOLVABLE_ADDRESS:
                        // https://sourceforge.net/p/lksctp/mailman/message/26542493/
                        var sub_length = body.readUInt16BE(2);
                        error.hostname = body.slice(4, 4 + sub_length).toString();
                        break;
                    case cause_codes.UNRECONGNIZED_CHUNK_TYPE:
                        error.unrecognized_chunk = body;
                        break;
                    case cause_codes.INVALID_MANDATORY_PARAMETER:
                        break;
                    case cause_codes.UNRECONGNIZED_PARAMETERS:
                        error.unrecognized_parameters = body;
                        break;
                    case cause_codes.NO_USER_DATA:
                        error.tsn = body.readUInt32BE(0);
                        break;
                    case cause_codes.COOKIE_RECEIVED_WHILE_SHUTTING_DOWN:
                        break;
                    case cause_codes.RESTART_WITH_NEW_ADDRESSES:
                        break;
                    case cause_codes.USER_INITIATED_ABORT:
                        error.abort_reason = body.toString();
                        break;
                    case cause_codes.PROTOCOL_VIOLATION:
                        error.additional_information = body.toString();
                        break;
                    default:
                        error.body = body;
                        return;
                }
            }
            offset += error_length;
            result.push(error)
        }
        return result
    }
};


var tlvs = {
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
};

_.each(tlvs, function (tlv, tag) {
    tlv.tag = tag;
    tlvs[tlv.id] = tlv
});


var cause_codes = {
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
};

_.assign(cause_codes, _.invert(cause_codes));


// http://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-25
var payload_protocol_identifier = {
    SCTP: 0,
    IUA: 1,
    M2UA: 2,
    M3UA: 3,
    SUA: 4,
    M2PA: 5,
    V5UA: 6,
    H248: 7,
    SSH: 45,
    Diameter: 46,
    Diameter_DTLS: 47,
    WebRTC_DCEP: 50,
    WebRTC_String: 51,
    WebRTC_Binary: 53,
    WebRTC_String_Empty: 56,
    WebRTC_Binary_Empty: 57
};

var chunks = {
    data: {
        id: 0x00,
        params: {
            tsn: {type: types.int32, default: 1},
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
            initiate_tag: {type: types.int32, default: 1},
            a_rwnd: {type: types.int32, default: 62464},
            outbound_streams: {type: types.int16, default: 2},
            inbound_streams: {type: types.int16, default: 2},
            initial_tsn: {type: types.int32, default: 0}
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
};


_.each(chunks, function (chunk, chunkType) {
    chunk.chunkType = chunkType;
    chunks[chunk.id] = chunk
});

/*
 http            80/sctp                         # HyperText Transfer Protocol
 bgp             179/sctp
 https           443/sctp                        # http protocol over TLS/SSL
 nfs             2049/sctp       nfsd shilp      # Network File System
 discard         9/sctp                  # Discard
 ftp-data        20/sctp                 # FTP
 ftp             21/sctp                 # FTP
 ssh             22/sctp                 # SSH
 cisco-ipsla     1167/sctp               # Cisco IP SLAs Control Protocol
 rcip-itu        2225/sctp               # Resource Connection Initiation Protocol
 m2ua            2904/sctp               # M2UA
 m3ua            2905/sctp               # M3UA
 megaco-h248     2944/sctp               # Megaco-H.248 text
 h248-binary     2945/sctp               # Megaco/H.248 binary
 itu-bicc-stc    3097/sctp               # ITU-T Q.1902.1/Q.2150.3
 m2pa            3565/sctp               # M2PA
 asap-sctp       3863/sctp               # asap sctp
 asap-sctp-tls   3864/sctp               # asap-sctp/tls
 diameter        3868/sctp               # DIAMETER
 ipfix           4739/sctp               # IP Flow Info Export
 ipfixs          4740/sctp               # ipfix protocol over DTLS
 car             5090/sctp               # Candidate AR
 cxtp            5091/sctp               # Context Transfer Protocol
 amqp            5672/sctp               # AMQP
 v5ua            5675/sctp               # V5UA application port
 frc-hp          6700/sctp               # ForCES HP (High Priority) channel
 frc-mp          6701/sctp               # ForCES MP (Medium Priority) channel
 frc-lp          6702/sctp               # ForCES LP (Low priority) channel
 simco           7626/sctp               # SImple Middlebox COnfiguration (SIMCO)
 pim-port        8471/sctp               # PIM over Reliable Transport
 aurora          9084/sctp               # IBM AURORA Performance Visualizer
 sctp-tunneling  9899/tcp                # SCTP TUNNELING
 sctp-tunneling  9899/udp                # SCTP TUNNELING
 iua             9900/sctp               # IUA
 enrp-sctp       9901/sctp               # enrp server channel
 enrp-sctp-tls   9902/sctp               # enrp/tls server channel
 wmereceiving    11997/sctp              # WorldMailExpress
 wmedistribution 11998/sctp              # WorldMailExpress
 wmereporting    11999/sctp              # WorldMailExpress
 sua             14001/sctp              # SUA
 nfsrdma         20049/sctp              # Network File System (NFS) over RDMA
 sgsap           29118/sctp              # SGsAP in 3GPP
 sbcap           29168/sctp              # SBcAP in 3GPP
 iuhsctpassoc    29169/sctp              # HNBAP and RUA Common Association
 s1-control      36412/sctp              # S1-Control Plane (3GPP)
 x2-control      36422/sctp              # X2-Control Plane (3GPP)

 */


exports.net_sctp = net_sctp;
exports.filters = filters;
exports.chunks = chunks;
exports.types = types;
exports.tlvs = tlvs;
exports.cause_codes = cause_codes;
exports.payload_protocol_identifier = payload_protocol_identifier;

