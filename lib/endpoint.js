const crypto = require('crypto')
const EventEmitter = require('events').EventEmitter
const debug = require('debug')

const transport = require('./transport')
const Packet = require('./packet')
const Chunk = require('./chunk')
const Association = require('./association')
const defs = require('./defs')

debug.formatters.h = v => {
  return v.toString('hex')
}

class Endpoint extends EventEmitter {
  constructor (options) {
    super()
    options = options || {}
    this.ootb = options.ootb
    this.localPort = options.localPort
    if (options.localAddress && options.localAddress.length > 0) {
      this.localAddress = options.localAddress
      this.localActiveAddress = options.localAddress[0]
    }

    this.udpTransport = options.udpTransport

    this.debugger = {}
    const label = `[${this.localPort}]`
    this.debugger.warn = debug(`sctp:endpoint:### ${label}`)
    this.debugger.info = debug(`sctp:endpoint:## ${label}`)
    this.debugger.debug = debug(`sctp:endpoint:# ${label}`)
    this.debugger.trace = debug(`sctp:endpoint: ${label}`)

    this.debugger.info('creating endpoint %o', options)

    this.MIS = options.MIS || 2
    this.OS = options.OS || 2
    this.cookieSecretKey = crypto.randomBytes(32)
    this.valid_cookie_life = defs.NET_SCTP.valid_cookie_life
    this.cookie_hmac_alg = defs.NET_SCTP.cookie_hmac_alg === 'md5' ? 'md5' : 'sha1'
    this.cookie_hmac_len = defs.NET_SCTP.cookie_hmac_alg === 'md5' ? 16 : 20

    setInterval(() => {
      // TODO change interval when valid_cookie_life changes
      this.cookieSecretKey = crypto.randomBytes(32)
    }, this.valid_cookie_life * 5)

    this.associations_lookup = {}
    this.associations = []

    this.on('icmp', this.onICMP.bind(this))
    this.on('packet', this.onPacket.bind(this))
  }

  onICMP (packet, src, dst, code) {
    const association = this._getAssociation(dst, packet.dst_port)
    if (association) {
      association.emit('icmp', packet, code)
    }
  }

  onPacket (packet, src, dst) {
    if (!Array.isArray(packet.chunks)) {
      this.debugger.warn('< received empty packet from %s:%d', src, packet.src_port)
      return
    }
    this.debugger.debug('< received packet from %s:%d', src, packet.src_port)
    let emulateLoss
    if (emulateLoss) {
      this.debugger.warn('emulate loss of remote packet')
      return
    }
    let lastDataChunk = -1
    let decodedChunks = []
    const errors = []
    const chunkTypes = {}
    let discardPacket = false

    // Check if packet should be discarded because of unrecognized chunks
    // Also collect errors, chunk types present, decoded chunks
    packet.chunks.every((buffer, index) => {
      const chunk = Chunk.fromBuffer(buffer)

      if (!chunk || chunk.error) {
        /*
        If the receiver detects a partial chunk, it MUST drop the chunk.
         */
        return true
      }

      if (chunk.chunkType) {
        chunkTypes[chunk.chunkType] = chunk

        decodedChunks.push(chunk)
        chunk.buffer = buffer

        if (chunk.chunkType === 'data') {
          lastDataChunk = index
        } else if (chunk.chunkType === 'init') {
          // Ok
        } else if (chunk.chunkType === 'abort') {
          // Remaining chunks should be ignored
          return false
        }
      } else {
        this.debugger.warn('unrecognized chunk %s, action %s', chunk.chunkId, chunk.action)
        switch (chunk.action || 0) {
          case 0:
            /* 00 -  Stop processing this SCTP packet and discard it, do not
             process any further chunks within it. */
            discardPacket = true
            return false
          case 1:
            /* 01 -  Stop processing this SCTP packet and discard it, do not
             process any further chunks within it, and report the
             unrecognized chunk in an 'Unrecognized Chunk Type'. */
            discardPacket = true
            errors.push({
              cause: 'UNRECONGNIZED_CHUNK_TYPE',
              unrecognized_chunk: buffer
            })
            return false
          case 2:
            /* 10 -  Skip this chunk and continue processing. */
            break
          case 3:
            /* 11 -  Skip this chunk and continue processing, but report in an
             ERROR chunk using the 'Unrecognized Chunk Type' cause of
             error. */
            errors.push({
              cause: 'UNRECONGNIZED_CHUNK_TYPE',
              unrecognized_chunk: buffer
            })
            break
          default:
        }
      }
      return true
    })

    let association = this._getAssociation(src, packet.src_port)

    if (association) {
      if (errors.length > 0 && !chunkTypes.abort) {
        this.debugger.warn('informing unrecognized chunks in packet', errors)
        association.ERROR(errors, packet.src)
      }
    }

    if (discardPacket) {
      return
    }

    if (decodedChunks.length === 0) {
      return
    }

    if (!association) {
      // 8.4.  Handle "Out of the Blue" Packets
      this.debugger.debug('Handle "Out of the Blue" Packets')
      if (chunkTypes.abort) {
        // If the OOTB packet contains an ABORT chunk, the receiver MUST
        // silently discard the OOTB packet and take no further action.
        this.debugger.debug('OOTB ABORT, discard')
        return
      }
      if (chunkTypes.init) {
        /*
        If the packet contains an INIT chunk with a Verification Tag set
        to '0', process it as described in Section 5.1.  If, for whatever
        reason, the INIT cannot be processed normally and an ABORT has to
        be sent in response, the Verification Tag of the packet
        containing the ABORT chunk MUST be the Initiate Tag of the
        received INIT chunk, and the T bit of the ABORT chunk has to be
        set to 0, indicating that the Verification Tag is NOT reflected.

         When an endpoint receives an SCTP packet with the Verification
         Tag set to 0, it should verify that the packet contains only an
         INIT chunk.  Otherwise, the receiver MUST silently discard the
         packet.

         Furthermore, we require
         that the receiver of an INIT chunk MUST enforce these rules by
         silently discarding an arriving packet  with an INIT chunk that is
         bundled with other chunks or has a non-zero verification tag and
         contains an INIT-chunk.
        */
        if (packet.v_tag === 0 && packet.chunks.length === 1) {
          this.onInit(decodedChunks[0], src, dst, packet)
        } else {
          // all chunks count, including bogus
          this.debugger.warn('INIT rules violation, discard')
        }
        return
      } else if (chunkTypes.cookie_echo && decodedChunks[0].chunkType === 'cookie_echo') {
        association = this.onCookieEcho(decodedChunks[0], src, dst, packet)
        decodedChunks.shift()
        if (!association) {
          this.debugger.warn('Cookie Echo failed to establish association')
          return
        }
      } else if (chunkTypes.shutdown_ack) {
        /*
         If the packet contains a SHUTDOWN ACK chunk, the receiver should
         respond to the sender of the OOTB packet with a SHUTDOWN
         COMPLETE.  When sending the SHUTDOWN COMPLETE, the receiver of
         the OOTB packet must fill in the Verification Tag field of the
         outbound packet with the Verification Tag received in the
         SHUTDOWN ACK and set the T bit in the Chunk Flags to indicate
         that the Verification Tag is reflected.
        */
        const chunk = new Chunk('shutdown_complete', { flags: { T: 1 } })
        this._sendPacket(src, packet.src_port, packet.v_tag, [chunk.toBuffer()])
        return
      } else if (chunkTypes.shutdown_complete) {
        /*
        If the packet contains a SHUTDOWN COMPLETE chunk, the receiver
        should silently discard the packet and take no further action.
        */
        this.debugger.debug('OOTB SHUTDOWN COMPLETE, discard')
        return
      } else if (chunkTypes.error) {
        /*
        If the packet contains a "Stale Cookie" ERROR or a COOKIE ACK,
        the SCTP packet should be silently discarded.
        */
        // TODO
        this.debugger.debug('OOTB ERROR, discard')
        return
      } else if (chunkTypes.cookie_ack) {
        this.debugger.debug('OOTB COOKIE ACK, discard')
        return
      } else {
        /*
         The receiver should respond to the sender of the OOTB packet with
         an ABORT.  When sending the ABORT, the receiver of the OOTB
         packet MUST fill in the Verification Tag field of the outbound
         packet with the value found in the Verification Tag field of the
         OOTB packet and set the T bit in the Chunk Flags to indicate that
         the Verification Tag is reflected.  After sending this ABORT, the
         receiver of the OOTB packet shall discard the OOTB packet and
         take no further action.
        */
        if (this.ootb) {
          this.debugger.debug('OOTB packet, tolerate')
        } else {
          this.debugger.debug('OOTB packet, abort')
          const chunk = new Chunk('abort', { flags: { T: 1 } })
          this._sendPacket(src, packet.src_port, packet.v_tag, [chunk.toBuffer()])
        }
        return
      }
    }

    if (!association) {
      // To be sure
      return
    }

    // all chunks count, including bogus
    if (packet.chunks.length > 1 &&
      (chunkTypes.init || chunkTypes.init_ack || chunkTypes.shutdown_complete)) {
      this.debugger.warn('MUST NOT bundle INIT, INIT ACK, or SHUTDOWN COMPLETE.')
      return
    }

    // 8.5.1.  Exceptions in Verification Tag Rules

    if (chunkTypes.abort) {
      if (
        (packet.v_tag === association.my_tag && !chunkTypes.abort.flags.T) ||
        (packet.v_tag === association.peer_tag && chunkTypes.abort.flags.T)
      ) {
        /*
        An endpoint MUST NOT respond to any received packet
        that contains an ABORT chunk (also see Section 8.4)
         */
        association.mute = true
        // DATA chunks MUST NOT be bundled with ABORT
        // TODO. For now we just keep some types
        // init_ack will be ignored, cause it needs reply
        // all other control chunks are useful
        decodedChunks = decodedChunks.filter(chunk =>
          chunk.chunkType === 'sack' ||
          chunk.chunkType === 'cookie_ack' ||
          chunk.chunkType === 'abort'
        )
      } else {
        this.debugger.warn('discard according to Rules for packet carrying ABORT %O', packet)
        this.debugger.debug(
          'v_tag %d, T-bit %s, my_tag %d, peer_tag %d',
          packet.v_tag,
          chunkTypes.abort.flags.T,
          association.my_tag,
          association.peer_tag
        )
        return
      }
    } else if (chunkTypes.init) {
      if (packet.v_tag !== 0) {
        return
      }
    } else if (chunkTypes.shutdown_complete) {
      /*
      -   The receiver of a SHUTDOWN COMPLETE shall accept the packet if
       the Verification Tag field of the packet matches its own tag and
       the T bit is not set OR if it is set to its peer's tag and the T
       bit is set in the Chunk Flags.  Otherwise, the receiver MUST
       silently discard the packet and take no further action.  An
       endpoint MUST ignore the SHUTDOWN COMPLETE if it is not in the
       SHUTDOWN-ACK-SENT state.
       */

      if (!((packet.v_tag === association.my_tag && !chunkTypes.shutdown_complete.flags.T) ||
        (packet.v_tag === association.peer_tag && chunkTypes.shutdown_complete.flags.T))) {
        return
      }
    } else {
      // 8.5.  Verification Tag
      if (packet.v_tag !== association.my_tag) {
        this.debugger.warn('discarding packet, v_tag %d != my_tag %d',
          packet.v_tag,
          association.my_tag
        )
        return
      }
    }

    // TODO shutdown_ack and shutdown_complete

    decodedChunks.forEach((chunk, index) => {
      chunk.last_in_packet = index === lastDataChunk
      this.debugger.debug('processing chunk %s from %s:%d', chunk.chunkType, src, packet.src_port)
      this.debugger.debug('emit chunk %s for association', chunk.chunkType)
      association.emit(chunk.chunkType, chunk, src, packet)
    })
  }

  onInit (chunk, src, dst, header) {
    this.debugger.info('< CHUNK init', chunk.initiate_tag)

    // Check for errors in parameters. Note that chunk can already have parse errors.
    const errors = []
    if (
      chunk.initiate_tag === 0 ||
      chunk.a_rwnd < 1500 ||
      chunk.inbound_streams === 0 ||
      chunk.outbound_streams === 0
    ) {
      /*
       If the value of the Initiate Tag in a received INIT chunk is found
       to be 0, the receiver MUST treat it as an error and close the
       association by transmitting an ABORT.
       An SCTP receiver MUST be able to receive a minimum of 1500 bytes in
       one SCTP packet.  This means that an SCTP endpoint MUST NOT indicate
       less than 1500 bytes in its initial a_rwnd sent in the INIT or INIT
       ACK.
       A receiver of an INIT with the MIS value of 0 SHOULD abort
       the association.
       Note: A receiver of an INIT with the OS value set to 0 SHOULD
       abort the association.

       Invalid Mandatory Parameter: This error cause is returned to the
       originator of an INIT or INIT ACK chunk when one of the mandatory
       parameters is set to an invalid value.
       */
      errors.push({ cause: 'INVALID_MANDATORY_PARAMETER' })
    }
    if (errors.length > 0) {
      const abort = new Chunk('abort', { error_causes: errors })
      this._sendPacket(src, header.src_port, chunk.initiate_tag, [abort.toBuffer()])
      return
    }
    const myTag = crypto.randomBytes(4).readUInt32BE(0)
    const cookie = this.createCookie(chunk, header, myTag)
    const initAck = new Chunk('init_ack', {
      initiate_tag: myTag,
      initial_tsn: myTag,
      a_rwnd: defs.NET_SCTP.RWND,
      state_cookie: cookie,
      outbound_streams: chunk.inbound_streams,
      inbound_streams: this.MIS
    })
    if (this.localAddress) {
      initAck.ipv4_address = this.localAddress
    }
    if (chunk.errors) {
      this.debugger.warn('< CHUNK has errors (unrecognized parameters)', chunk.errors)
      initAck.unrecognized_parameter = chunk.errors
    }
    this.debugger.trace('> sending cookie', cookie)
    this._sendPacket(src, header.src_port, chunk.initiate_tag, [initAck.toBuffer()])
    /*
     After sending the INIT ACK with the State Cookie parameter, the
     sender SHOULD delete the TCB and any other local resource related to
     the new association, so as to prevent resource attacks.
     */
  }

  onCookieEcho (chunk, src, dst, header) {
    this.debugger.info('< CHUNK cookie_echo ', chunk.cookie)
    /*
    If the State Cookie is valid, create an association to the sender
    of the COOKIE ECHO chunk with the information in the TCB data
    carried in the COOKIE ECHO and enter the ESTABLISHED state.
    */
    const cookieData = this.validateCookie(chunk.cookie, header)
    if (cookieData) {
      this.debugger.trace('cookie is valid')
      const initChunk = Chunk.fromBuffer(cookieData.initChunk)
      if (initChunk.chunkType !== 'init') {
        this.debugger.warn('--> this should be init chunk', initChunk)
        throw new Error('bug in chunk validation function')
      }
      const options = {
        remoteAddress: src,
        my_tag: cookieData.my_tag,
        remotePort: cookieData.src_port,
        MIS: this.MIS,
        OS: this.OS
      }
      const association = new Association(this, options)
      this.emit('association', association)
      association.acceptRemote(initChunk)
      return association
    }
  }

  _sendPacket (host, port, vTag, chunks, callback) {
    this.debugger.debug('> send packet %d chunks %s -> %s:%d vTag %d',
      chunks.length,
      this.localActiveAddress,
      host,
      port,
      vTag
    )
    const packet = new Packet(
      {
        src_port: this.localPort,
        dst_port: port,
        v_tag: vTag
      },
      chunks
    )
    // TODO multi-homing select active address
    this.transport.sendPacket(this.localActiveAddress, host, packet, callback)
  }

  createCookie (chunk, header, myTag) {
    const created = Math.floor(new Date() / 1000)
    const information = Buffer.alloc(16)
    information.writeUInt32BE(created, 0)
    information.writeUInt32BE(this.valid_cookie_life, 4)
    information.writeUInt16BE(header.src_port, 8)
    information.writeUInt16BE(header.dst_port, 10)
    information.writeUInt32BE(myTag, 12)
    const hash = crypto.createHash(this.cookie_hmac_alg)
    hash.update(information)
    /*
     The receiver of the PAD
     parameter MUST silently discard this parameter and continue
     processing the rest of the INIT chunk.  This means that the size of
     the generated COOKIE parameter in the INIT-ACK MUST NOT depend on the
     existence of the PAD parameter in the INIT chunk.  A receiver of a
     PAD parameter MUST NOT include the PAD parameter within any State
     Cookie parameter it generates.

     Note: sctp_test doesn't follow this rule.
     */
    delete chunk.pad
    const strippedInit = new Chunk('init', chunk)
    const initBuffer = strippedInit.toBuffer()
    hash.update(initBuffer)
    hash.update(this.cookieSecretKey)
    const mac = hash.digest()
    this.debugger.debug('created cookie mac %h %d bytes', mac, mac.length)
    /*
      0                   1                   2                   3                   4
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |               MAC             |           Information           |    INIT chunk ...
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |               MAC             | time  | life  |spt|dpt|  my tag |    INIT chunk ...
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   */
    return Buffer.concat([mac, information, initBuffer])
  }

  validateCookie (cookie, header) {
    let result
    // MAC 16 + Info 16 + Init chunk 20 = 52
    if (cookie.length < 52) {
      return
    }
    const receivedMAC = cookie.slice(0, this.cookie_hmac_len)
    const information = cookie.slice(this.cookie_hmac_len, this.cookie_hmac_len + 16)
    const initChunk = cookie.slice(this.cookie_hmac_len + 16)
    /*
     Compute a MAC using the TCB data carried in the State Cookie and
     the secret key (note the timestamp in the State Cookie MAY be
     used to determine which secret key to use).
     */
    const hash = crypto.createHash(defs.NET_SCTP.cookie_hmac_alg)
    hash.update(information)
    hash.update(initChunk)
    hash.update(this.cookieSecretKey)
    const mac = hash.digest()
    /*
     Authenticate the State Cookie as one that it previously generated
     by comparing the computed MAC against the one carried in the
     State Cookie.  If this comparison fails, the SCTP header,
     including the COOKIE ECHO and any DATA chunks, should be silently
     discarded
     */
    if (mac.equals(receivedMAC)) {
      result = {
        created: new Date(information.readUInt32BE(0) * 1000),
        cookie_lifespan: information.readUInt32BE(4),
        src_port: information.readUInt16BE(8),
        dst_port: information.readUInt16BE(10),
        my_tag: information.readUInt32BE(12)
      }
      /*
       Compare the port numbers and the Verification Tag contained
       within the COOKIE ECHO chunk to the actual port numbers and the
       Verification Tag within the SCTP common header of the received
       header.  If these values do not match, the packet MUST be
       silently discarded.
       */
      if (
        header.src_port === result.src_port &&
        header.dst_port === result.dst_port &&
        header.v_tag === result.my_tag
      ) {
        /*
         Compare the creation timestamp in the State Cookie to the current
         local time.  If the elapsed time is longer than the lifespan
         carried in the State Cookie, then the packet, including the
         COOKIE ECHO and any attached DATA chunks, SHOULD be discarded,
         and the endpoint MUST transmit an ERROR chunk with a "Stale
         Cookie" error cause to the peer endpoint.
         */
        if (new Date() - result.created < result.cookie_lifespan) {
          result.initChunk = initChunk
          return result
        }
      } else {
        this.debugger.warn('port verification error', header, result)
      }
    } else {
      this.debugger.warn('mac verification error %h != %h', receivedMAC, mac)
    }
  }

  close () {
    this.emit('close')
    this.associations.forEach(association => {
      association.emit('COMMUNICATION LOST')
      association._destroy()
    })
    this._destroy()
  }

  _destroy () {
    this.transport.unallocate(this.localPort)
  }

  _getAssociation (host, port) {
    const key = host + ':' + port
    this.debugger.trace('trying to find association for %s', key)
    return this.associations_lookup[key]
  }

  ASSOCIATE (options) {
    /*
     Format: ASSOCIATE(local SCTP instance name,
     destination transport addr, outbound stream count)
     -> association id [,destination transport addr list]
     [,outbound stream count]
     */

    this.debugger.info('API ASSOCIATE', options)
    options = options || {}
    if (!options.remotePort) {
      throw new Error('port is required')
    }
    options.OS = options.OS || this.OS
    options.MIS = options.MIS || this.MIS

    const association = new Association(this, options)
    association.init()

    return association
  }

  DESTROY () {
    /*
     Format: DESTROY(local SCTP instance name)
     */
    this.debugger.trace('API DESTROY')
    this._destroy()
  }

  static INITIALIZE (options, transportOptions, callback) {
    const endpoint = new Endpoint(options)
    // TODO register is synchronous for now, but could be async
    const port = transport.register(endpoint, transportOptions)
    if (port) {
      callback(null, endpoint)
    } else {
      callback(new Error('bind EADDRINUSE 0.0.0.0:' + options.localPort))
    }
  }
}

module.exports = Endpoint
