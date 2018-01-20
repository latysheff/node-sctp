const debug = require('debug')
const crypto = require('crypto')
const EventEmitter = require('events').EventEmitter

const transport = require('./transport')
const Packet = require('./packet')
const Chunk = require('./chunk')
const Association = require('./association')
const defs = require('./defs')

class Endpoint extends EventEmitter {
  constructor(options) {
    super()
    options = options || {}
    this.localPort = options.localPort
    if (options.localAddress && options.localAddress.length) {
      this.localAddress = options.localAddress
      this.localActiveAddress = options.localAddress[0]
    }

    this.udpTransport = options.udpTransport

    this.debugger = {}
    let label = `[${this.localPort}]`
    this.debugger.warn = debug(`sctp:endpoint:### ${label}`)
    this.debugger.info = debug(`sctp:endpoint:## ${label}`)
    this.debugger.debug = debug(`sctp:endpoint:# ${label}`)
    this.debugger.trace = debug(`sctp:endpoint: ${label}`)

    this.debugger.info(
      'creating endpoint %s:%s',
      this.localPort,
      this.localAddress
    )

    this.MIS = options.MIS || 2
    this.OS = options.OS || 2
    this.cookieSecretKey = crypto.randomBytes(32)
    this.valid_cookie_life = defs.net_sctp.valid_cookie_life
    setInterval(() => {
      // todo change interval when valid_cookie_life changes
      this.cookieSecretKey = crypto.randomBytes(32)
    }, this.valid_cookie_life * 5)

    this.associations_lookup = {}
    this.associations = []

    this.on('icmp', (packet, src, dst, code) => {
      let association = this._getAssociation(dst, packet.dst_port)
      if (association) {
        association.emit('icmp', packet, code)
      }
    })

    this.on('packet', (packet, src, dst) => {
      if (!Array.isArray(packet.chunks)) {
        this.debugger.warn(
          '< received empty packet from %s:%d',
          src,
          packet.src_port
        )
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
      let discardPacket = false
      let errors = []
      let chunkTypes = {}
      let abortPacket = false

      packet.chunks.every((buffer, index) => {
        let chunk = Chunk.fromBuffer(buffer)
        if (chunk.chunkType) {
          chunkTypes[chunk.chunkType] = true
        } else {
          switch (chunk.action) {
            case 0:
              /*00 -  Stop processing this SCTP packet and discard it, do not
               process any further chunks within it.*/
              discardPacket = true
              return false
            case 1:
              /*01 -  Stop processing this SCTP packet and discard it, do not
               process any further chunks within it, and report the
               unrecognized chunk in an 'Unrecognized Chunk Type'.*/
              errors.push({
                cause: 'UNRECONGNIZED_CHUNK_TYPE',
                unrecognized_chunk: buffer,
              })
              discardPacket = true
              return false
            case 2:
              /*10 -  Skip this chunk and continue processing.*/
              break
            case 3:
              /*11 -  Skip this chunk and continue processing, but report in an
               ERROR chunk using the 'Unrecognized Chunk Type' cause of
               error.*/
              errors.push({
                cause: 'UNRECONGNIZED_CHUNK_TYPE',
                unrecognized_chunk: buffer,
              })
              break
          }
        }

        if (chunk.chunkType === 'abort') {
          /*
           An endpoint MUST NOT respond to any received packet
            that contains an ABORT chunk (also see Section 8.4)
           ...
           DATA chunks MUST NOT be bundled with ABORT.
           Control chunks (except for INIT, INIT ACK, and SHUTDOWN COMPLETE)
           MAY be bundled with an ABORT, but they MUST be
           placed before the ABORT in the SCTP packet
           or they will be ignored by the receiver.
          */
          abortPacket = true
          let association = this._getAssociation(src, packet.src_port)
          if (association) {
            /*
              The receiver of an ABORT MUST accept the packet
               if the Verification Tag field of the packet
                 matches its own tag and the T bit is not set
               OR if it is set to its peer's tag
                 and the T bit is set in the Chunk Flags.
              Otherwise, the receiver MUST silently discard
               the packet and take no further action.
             */
            if (
              (packet.v_tag === association.my_tag && !chunk.flags.T) ||
              (packet.v_tag === association.peer_tag && chunk.flags.T)
            ) {
              this.debugger.warn('emit ONLY abort for association')
              association.emit(chunk.chunkType, chunk, src, packet)
            } else {
              this.debugger.warn(
                'discard according to B) Rules for packet carrying ABORT',
                packet
              )
              this.debugger.debug(
                'v_tag %d, T-bit %s, my_tag %d, peer_tag %d',
                packet.v_tag,
                chunk.flags.T,
                association.my_tag,
                association.peer_tag
              )
            }
          } else {
            /*
              8.4.  Handle "Out of the Blue" Packets
              2)  If the OOTB packet contains an ABORT chunk,
              the receiver MUST silently discard the OOTB packet
              and take no further action.
             */
            this.debugger.trace('OOTB abort', packet)
          }
          // and obviously no need to process further chunks
          return false
        }

        decodedChunks.push(chunk)
        chunk.buffer = buffer

        if (chunk.chunkType === 'data') {
          lastDataChunk = index
        } else if (chunk.chunkType === 'init') {
          // for creating cookie
          // todo check if fits size (rfc says smth about)
        }

        return true
      })

      if (abortPacket) return

      // 8.5.  Verification Tag
      // 8.5.1.  Exceptions in Verification Tag Rules
      let association = this._getAssociation(src, packet.src_port)
      switch (true) {
        case chunkTypes['init']:
          if (packet.v_tag === 0 && decodedChunks.length === 1) {
            /*
             When an endpoint receives an SCTP packet with the Verification
             Tag set to 0, it should verify that the packet contains only an
             INIT chunk.  Otherwise, the receiver MUST silently discard the
             packet.
            */
          } else {
            this.debugger.warn(
              'silently discard according to A) Rules for packet carrying INIT'
            )
            return
          }
          break
        case chunkTypes['cookie_echo']:
          // after processing (check for tags will happen there)
          // this chunk association can be established
          // and for the rest of this packet we will have it
          break
        case chunkTypes['shutdown_ack']:
        case chunkTypes['shutdown_complete']:
        default:
          if (association) {
            if (packet.v_tag === association.my_tag) {
            } else {
              this.debugger.warn(
                'silently discard according to 8.5.  Verification Tag',
                association.my_tag,
                packet.v_tag
              )
              return
            }
          } else {
            // we don't have chunks in the packet
            // that can establish or close association - nothing to do
            this.debugger.warn('OOTB packet')
            return
          }
      }

      if (discardPacket) {
        this.debugger.warn('unrecognized chunks in packet', errors)
        if (errors.length > 0) {
          if (association) {
            association.error({ error_causes: errors })
          } else {
            // TODO: implement same in mirrored situation
            let abort = new Chunk('abort', {
              flags: { T: true },
              error_causes: errors,
            })
            this._sendPacket(src, packet.src_port, packet.v_tag, [
              abort.toBuffer(),
            ])
          }
        }
        return
      }

      // todo create header from packet?
      let header = packet

      decodedChunks.forEach((chunk, index) => {
        chunk.packet = index === lastDataChunk
        this.debugger.debug(
          `processing chunk ${chunk.chunkType} from ${src}:${header.src_port}`
        )
        if (!association)
          association = this._getAssociation(src, header.src_port)
        if (association) {
          if (chunk.chunkType === 'init' || chunk.chunkType === 'cookie_echo') {
            this.emit(chunk.chunkType, chunk, src, dst, header, association)
          } else {
            this.debugger.debug(
              'emit chunk',
              chunk.chunkType,
              'for association'
            )
            association.emit(chunk.chunkType, chunk, src, header, true)
          }
        } else {
          this.emit(chunk.chunkType, chunk, src, dst, header)
        }
      })
    })

    // todo tmp
    this.on('data', (chunk, src, dst, header) => {
      this.debugger.warn(`received data ${chunk}, ${src}, ${dst}, ${header}`)
    })

    this.on('init', (chunk, src, dst, header, association) => {
      this.debugger.info('< CHUNK init', chunk.initiate_tag)
      if (association) {
        this.debugger.warn(
          'rfc4960 "5.2.2.  Unexpected INIT ..."',
          association.state,
          chunk
        )
        // return
      }
      let errors = []
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
        let abort = new Chunk('abort', { error_causes: errors })
        this._sendPacket(src, header.src_port, chunk.initiate_tag, [
          abort.toBuffer(),
        ])
        return
      }
      let my_tag = ~~(Math.random() * 0x7fffffff)
      let cookie = this.createCookie(chunk.buffer, header, my_tag)
      let initAck = new Chunk('init_ack', {
        initiate_tag: my_tag,
        initial_tsn: my_tag,
        a_rwnd: defs.net_sctp.RWND,
        state_cookie: cookie,
        outbound_streams: chunk.inbound_streams,
        inbound_streams: this.MIS,
      })
      if (this.localAddress) {
        initAck.ipv4_address = this.localAddress
      }
      if (chunk.errors) {
        this.debugger.warn('< CHUNK has errors', chunk.errors)
        initAck.unrecognized_parameter = chunk.errors
      }
      this.debugger.trace('> sending cookie', cookie)
      this._sendPacket(src, header.src_port, chunk.initiate_tag, [
        initAck.toBuffer(),
      ])
      /*
       After sending the INIT ACK with the State Cookie parameter, the
       sender SHOULD delete the TCB and any other local resource related to
       the new association, so as to prevent resource attacks.
       */
    })

    this.on('cookie_echo', (chunk, src, dst, header, association) => {
      this.debugger.info('< CHUNK cookie_echo ', chunk.cookie)
      /*
      If the State Cookie is valid, create an association to the sender
      of the COOKIE ECHO chunk with the information in the TCB data
      carried in the COOKIE ECHO and enter the ESTABLISHED state.
      */

      let cookieData = this.validateCookie(chunk.cookie, header)
      if (cookieData) {
        this.debugger.trace('cookie is valid')
        let initChunk = Chunk.fromBuffer(cookieData.init)
        let my_tag = cookieData.my_tag
        let peer_tag = initChunk.initiate_tag
        let options = {
          remoteAddress: src,
          my_tag: cookieData.my_tag,
          remotePort: cookieData.src_port,
          MIS: this.MIS,
        }
        if (association) {
          this.debugger.warn(
            'Handle a COOKIE ECHO when a TCB Exists',
            association.state,
            chunk
          )
          this.debugger.debug(
            association.my_tag,
            association.peer_tag,
            my_tag,
            peer_tag
          )
          let action = ''
          if (association.my_tag === my_tag) {
            // B or D
            if (association.peer_tag === peer_tag) {
              action = 'D'
            } else {
              action = 'B'
            }
          } else {
            // A or C
            if (association.peer_tag === peer_tag) {
              let tieTagsUnknown = true // todo tmp, implement tie-tags
              if (tieTagsUnknown) {
                action = 'C'
              }
            } else {
              let tieTagsMatch = true // todo tmp, implement tie-tags
              if (tieTagsMatch) {
                action = 'A'
              }
            }
          }
          this.debugger.warn('action', action)
          switch (action) {
            case 'A':
              /*
              todo tie-tags
              todo SHUTDOWN-ACK-SENT state
              A) In this case, the peer may have restarted.  When the endpoint
              recognizes this potential 'restart', the existing session is
              treated the same as if it received an ABORT followed by a new
              COOKIE ECHO with the following exceptions:

              -  Any SCTP DATA chunks MAY be retained (this is an
                 implementation-specific option).

              -  A notification of RESTART SHOULD be sent to the ULP instead of
                 a "COMMUNICATION LOST" notification.

              All the congestion control parameters (e.g., cwnd, ssthresh)
              related to this peer MUST be reset to their initial values (see
              Section 6.2.1).

              After this, the endpoint shall enter the ESTABLISHED state.

              If the endpoint is in the SHUTDOWN-ACK-SENT state and recognizes
              that the peer has restarted (Action A), it MUST NOT set up a new
              association but instead resend the SHUTDOWN ACK and send an ERROR
              chunk with a "Cookie Received While Shutting Down" error cause to
              its peer.
              */
              if (association.state === 'SHUTDOWN-ACK-SENT') {
                association._sendChunk('shutdown_ack', {}, src, () => {
                  this.debugger.info('sent shutdown_ack')
                })
                return
              } else {
                association.emit('RESTART')
                association._destroy()
              }
              break
            case 'B':
              /*
              todo init collision
          B) In this case, both sides may be attempting to start an association
          at about the same time, but the peer endpoint started its INIT
          after responding to the local endpoint's INIT.  Thus, it may have
          picked a new Verification Tag, not being aware of the previous tag
          it had sent this endpoint.  The endpoint should stay in or enter
          the ESTABLISHED state, but it MUST update its peer's Verification
          Tag from the State Cookie, stop any init or cookie timers that may
          be running, and send a COOKIE ACK.
              */
              association.peer_tag = peer_tag
              // todo stop init & cookie timers
              association._sendChunk('cookie_ack')
              return
            case 'C':
              /*
              C) In this case, the local endpoint's cookie has arrived late.
              Before it arrived, the local endpoint sent an INIT and received an
              INIT ACK and finally sent a COOKIE ECHO with the peer's same tag
              but a new tag of its own.  The cookie should be silently
              discarded.  The endpoint SHOULD NOT change states and should leave
              any timers running.
              */
              return
            case 'D':
              /*
        D) When both local and remote tags match, the endpoint should enter
        the ESTABLISHED state, if it is in the COOKIE-ECHOED state.  It
        should stop any cookie timer that may be running and send a COOKIE ACK.
              */
              if (association.state === 'COOKIE-ECHOED')
                association.state = 'ESTABLISHED'
              // todo should be already running, state also be ESTABLISHED
              // association._enableHeartbeat()
              // todo stop cookie timer
              association._sendChunk('cookie_ack')
              return
            default:
              /*
              Note: For any case not shown in Table 2,
               the cookie should be silently discarded
              */
              return
          }
        }
        let newAssociation = new Association(this, options, initChunk)
        this.emit('COMMUNICATION UP', newAssociation)
      }
    })
  }

  _sendPacket(host, port, tag, chunks, callback) {
    this.debugger.debug(
      '> send packet',
      this.localActiveAddress,
      '->',
      host,
      port,
      tag,
      chunks.length
    )
    let packet = new Packet(
      {
        src_port: this.localPort,
        dst_port: port,
        v_tag: tag,
      },
      chunks
    )
    // todo multi-homing select active address
    this.transport.sendPacket(this.localActiveAddress, host, packet, callback)
  }

  createCookie(chunk, header, my_tag) {
    let created = Math.floor(new Date() / 1000)
    let information = Buffer.alloc(16)
    information.writeUInt32BE(created, 0)
    information.writeUInt32BE(this.valid_cookie_life, 4)
    information.writeUInt16BE(header.src_port, 8)
    information.writeUInt16BE(header.dst_port, 10)
    information.writeUInt32BE(my_tag, 12)
    let hash = crypto.createHash(defs.net_sctp.cookie_hmac_alg)
    hash.update(information)
    hash.update(chunk)
    hash.update(this.cookieSecretKey)
    let mac = hash.digest() // length 16
    return Buffer.concat([mac, information, chunk])
  }

  validateCookie(cookie, header) {
    let result
    if (cookie.length < 32) {
      return
    }
    let information = cookie.slice(16, 32)
    let init = cookie.slice(32)
    /*
     Compute a MAC using the TCB data carried in the State Cookie and
     the secret key (note the timestamp in the State Cookie MAY be
     used to determine which secret key to use).
     */
    let hash = crypto.createHash(defs.net_sctp.cookie_hmac_alg)
    hash.update(information)
    hash.update(init)
    hash.update(this.cookieSecretKey)
    let mac = hash.digest()
    /*
     Authenticate the State Cookie as one that it previously generated
     by comparing the computed MAC against the one carried in the
     State Cookie.  If this comparison fails, the SCTP header,
     including the COOKIE ECHO and any DATA chunks, should be silently
     discarded
     */
    if (mac.equals(cookie.slice(0, 16))) {
      result = {
        created: new Date(information.readUInt32BE(0) * 1000),
        cookie_lifespan: information.readUInt32BE(4),
        src_port: information.readUInt16BE(8),
        dst_port: information.readUInt16BE(10),
        my_tag: information.readUInt32BE(12),
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
          result.init = init
          return result
        }
      } else {
        this.debugger.warn('port verification error', header, result)
      }
    } else {
      this.debugger.warn('mac verification error', cookie.slice(0, 16), mac)
    }
  }

  close() {
    this.emit('close')
    this.associations.forEach(association => {
      association.emit('COMMUNICATION LOST')
      association._destroy()
    })
    this._destroy()
  }

  _destroy() {
    this.transport.unallocate(this.localPort)
  }

  _getAssociation(host, port) {
    this.debugger.trace('trying to find association for', host, port)
    return this.associations_lookup[host + ':' + port]
  }

  ASSOCIATE(options) {
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
    let association = new Association(this, {
      remoteAddress: options.remoteAddress,
      remotePort: options.remotePort,
      OS: options.OS || this.OS, // we suggest only if we initiate
      MIS: options.MIS || this.MIS,
    })
    association.init()
    // todo callback?
    return association
  }

  DESTROY() {
    /*
     Format: DESTROY(local SCTP instance name)
     */
    this.debugger.trace('API DESTROY')
    this._destroy()
  }

  static INITIALIZE(options, callback) {
    let endpoint = new Endpoint(options)
    // todo register is synchronous for now, but could be async
    let port = transport.register(endpoint)
    if (port) {
      callback(null, endpoint)
    } else {
      process.nextTick(() => {
        callback(new Error('bind EADDRINUSE 0.0.0.0:' + options.localPort))
      })
    }
  }
}

module.exports = Endpoint
