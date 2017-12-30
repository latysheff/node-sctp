const crypto = require('crypto')
const EventEmitter = require('events').EventEmitter
const _ = require('lodash')

const rawsocket = require('./rawsocket')
const Packet = require('./packet')
const Chunk = require('./chunk')
const Association = require('./association')
const defs = require('./defs')

class Endpoint extends EventEmitter {
  constructor(options, logger) {
    super()
    options = options || {}
    this.localPort = options.localPort
    if (options.localAddress) {
      this.localAddress = options.localAddress[0]
      this.localAddresses = options.localAddress
    }

    this.logger = logger
    if (this.logger && (typeof this.logger.log === 'function')) {
      this.log = (level, ...rest) => {
        this.logger.log(level, 'endpoint - [', this.localPort, ']', ...rest)
      }
    } else {
      this.log = () => {
      }
    }
    rawsocket.setLogger(this.logger)

    this.MIS = options.MIS || 2
    this.OS = options.OS || 2
    this.cookieSecretKey = crypto.randomBytes(32)
    this.valid_cookie_life = defs.net_sctp.valid_cookie_life
    setInterval(() => {
      // todo change interval when valid_cookie_life changes
      this.cookieSecretKey = crypto.randomBytes(32)
    }, this.valid_cookie_life * 5)
    this.associations = {}

    this.on('packet', (packet, source, destination) => {
      if (!Array.isArray(packet.chunks)) {
        this.log('warn', '< received empty packet from', source, ':', packet.source_port)
        return
      }
      this.log('debug', '< received packet from', source, ':', packet.source_port)
      let emulateLoss
      //emulateLoss = (_.random(1, 10) == 10)
      if (emulateLoss) {
        this.log('error', 'emulate loss of remote packet')
        return
      }
      let lastDataChunk = -1
      let decodedChunks = []
      let discard = false
      let errors = []
      let tBit
      let chunkTypes = {}
      _.forEach(packet.chunks, (buffer, index) => {
        let chunk = Chunk.fromBuffer(buffer)
        if (chunk.chunkType) {
          chunkTypes[chunk.chunkType] = true
        } else {
          switch (chunk.action) {
            case 0:
              /*00 -  Stop processing this SCTP packet and discard it, do not
               process any further chunks within it.*/
              discard = true
              return
            case 1:
              /*01 -  Stop processing this SCTP packet and discard it, do not
               process any further chunks within it, and report the
               unrecognized chunk in an 'Unrecognized Chunk Type'.*/
              errors.push({cause: 'UNRECONGNIZED_CHUNK_TYPE', unrecognized_chunk: buffer})
              discard = true
              return
            case 2:
              /*10 -  Skip this chunk and continue processing.*/
              break
            case 3:
              /*11 -  Skip this chunk and continue processing, but report in an
               ERROR chunk using the 'Unrecognized Chunk Type' cause of
               error.*/
              errors.push({cause: 'UNRECONGNIZED_CHUNK_TYPE', unrecognized_chunk: buffer})
              break
          }
        }
        chunk.buffer = buffer
        decodedChunks.push(chunk)
        if (chunk.chunkType === 'data') {
          lastDataChunk = index
        } else if (chunk.chunkType === 'abort') {
          // this.log('error', chunk)
          tBit = chunk.flags.T
        }
      })

      // 8.5.  Verification Tag
      // 8.5.1.  Exceptions in Verification Tag Rules
      let association = this._getAssociation(source, packet.source_port)
      switch (true) {
        case chunkTypes['init']:
          if (packet.verification_tag === 0 && decodedChunks.length === 1) {
            /*
             When an endpoint receives an SCTP packet with the Verification
             Tag set to 0, it should verify that the packet contains only an
             INIT chunk.  Otherwise, the receiver MUST silently discard the
             packet.
            */
          } else {
            this.log('warn', 'silently discard according to A) Rules for packet carrying INIT')
            return
          }
          break
        case chunkTypes['abort']:
          if (association &&
            (
              (!tBit && packet.verification_tag === association.myTag)
              || (tBit && packet.verification_tag === association.peerTag)
            )
          ) {
            /*
            The receiver of an ABORT MUST accept the packet if the
            Verification Tag field of the packet matches its own tag and the
            T bit is not set OR if it is set to its peer's tag and the T bit
            is set in the Chunk Flags.  Otherwise, the receiver MUST silently
            discard the packet and take no further action.
           */
          } else {
            this.log('warn', 'silently discard according to B) Rules for packet carrying ABORT', packet)
            return
          }
          break
        // case chunkTypes['shutdown_complete']:
        //   break
        case chunkTypes['cookie_echo']:
          // 5.2.4. Handle a COOKIE ECHO when a TCB Exists
          break
        // case chunkTypes['shutdown_ack']:
        //   break
        default:
          if (association) {
            if (packet.verification_tag === association.myTag) {
            } else {
              this.log('warn', 'silently discard according to 8.5.  Verification Tag', association.myTag, packet.verification_tag)
              return
            }
          } else {
            this.log('warn', 'no association')
          }
      }

      if (discard) {
        this.log('warn', 'unrecognized chunks in packet', errors)
        if (errors.length > 0) {
          if (association) {
            association.error({error_causes: errors})
          } else {
            // TODO: implement same in mirrored situation
            let abort = new Chunk('abort', {
              flags: {T: true},
              error_causes: errors
            })
            this._sendPacket(source, packet.source_port, packet.verification_tag, [abort.toBuffer()])
          }
        }
        return
      }

      delete packet.chunks
      let header = packet

      _.each(decodedChunks, (chunk, index) => {
        chunk.packet = index === lastDataChunk
        this.log('debug', 'processing chunk', chunk.chunkType, 'from', source, ':', header.source_port)
        if (!association) association = this._getAssociation(source, header.source_port)
        if (association) {
          if (chunk.chunkType === 'init' || chunk.chunkType === 'cookie_echo') {
            this.emit(chunk.chunkType, chunk, source, destination, header, association)
          } else {
            association.emit(chunk.chunkType, chunk, source, header)
          }
        } else {
          this.emit(chunk.chunkType, chunk, source, destination, header)
        }
      })

    })

    // todo tmp
    this.on('data', (chunk, source, destination, header) => {
      this.log('warn', 'received data', chunk)
    })

    this.on('abort', (chunk, source, destination, header) => {
      this.log('warn', 'received abort', chunk)
    })

    this.on('init', (chunk, source, destination, header, association) => {
      this.log('info', '< CHUNK init', chunk.initiate_tag)
      if (association) {
        this.log('error', 'rfc4960 "5.2.2.  Unexpected INIT ..."', association.state, chunk)
        // return
      }
      let errors = []
      if (chunk.initiate_tag === 0
        || chunk.a_rwnd < 1500
        || chunk.inbound_streams === 0
        || chunk.outbound_streams === 0) {
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
        errors.push({cause: 'INVALID_MANDATORY_PARAMETER'})
      }
      if (errors.length > 0) {
        let abort = new Chunk('abort', {error_causes: errors})
        this._sendPacket(source, header.source_port, chunk.initiate_tag, [abort.toBuffer()])
        return
      }
      let myTag = _.random(0, 0xffffffff)
      let cookie = this.createCookie(chunk.buffer, header, myTag)
      let initAck = new Chunk('init_ack', {
        initiate_tag: myTag,
        initial_tsn: myTag,
        a_rwnd: defs.net_sctp.RWND,
        state_cookie: cookie,
        outbound_streams: chunk.inbound_streams,
        inbound_streams: this.MIS
      })
      if (chunk.errors) {
        this.log('warn', '< CHUNK has errors', chunk.errors)
        initAck.unrecognized_parameter = chunk.errors
      }
      this.log('trace', '> sending cookie', cookie)
      this._sendPacket(source, header.source_port, chunk.initiate_tag, [initAck.toBuffer()])
      /*
       After sending the INIT ACK with the State Cookie parameter, the
       sender SHOULD delete the TCB and any other local resource related to
       the new association, so as to prevent resource attacks.
       */
    })

    this.on('cookie_echo', (chunk, source, destination, header, existingAssoc) => {
      this.log('info', '< CHUNK cookie_echo ', chunk.cookie)
      /*
      If the State Cookie is valid, create an association to the sender
      of the COOKIE ECHO chunk with the information in the TCB data
      carried in the COOKIE ECHO and enter the ESTABLISHED state.
      */

      let cookieData = this.validateCookie(chunk.cookie, header)
      if (cookieData) {
        this.log('trace', 'cookie is valid')
        let initChunk = Chunk.fromBuffer(cookieData.init)
        let myTag = cookieData.myTag
        let peerTag = initChunk.initiate_tag
        let options = {
          remoteAddress: source,
          myTag: cookieData.myTag,
          remotePort: cookieData.source_port,
          MIS: this.MIS
        }
        if (existingAssoc) {
          this.log('warn', 'Handle a COOKIE ECHO when a TCB Exists', existingAssoc.state, chunk)
          this.log('debug', existingAssoc.myTag, existingAssoc.peerTag, myTag, peerTag)
          let action = ''
          if (existingAssoc.myTag === myTag) {
            // B or D
            if (existingAssoc.peerTag === peerTag) {
              action = 'D'
            } else {
              action = 'B'
            }
          } else {
            // A or C
            if (existingAssoc.peerTag === peerTag) {
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
          this.log('error', 'action', action)
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
              if (existingAssoc.state === 'SHUTDOWN-ACK-SENT') {
                existingAssoc._sendChunk('shutdown_ack', {}, source, () => {
                  this.log('info', 'sent shutdown_ack')
                })
                return
              } else {
                existingAssoc.emit('RESTART')
                existingAssoc._destroy()
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
              existingAssoc.peerTag = peerTag
              // todo stop init & cookie timers
              existingAssoc._sendChunk('cookie_ack')
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
              if (existingAssoc.state === 'COOKIE-ECHOED') existingAssoc.state = 'ESTABLISHED'
              // todo should be already running, but state also should be 'ESTABLISHED'
              // existingAssoc._enableHeartbeat()
              // todo stop cookie timer
              existingAssoc._sendChunk('cookie_ack')
              return
            default:
              /*
              Note: For any case not shown in Table 2, the cookie should be silently discarded
              */
              return
          }
        }
        let association = new Association(this, options, initChunk, () => {
          this.emit('COMMUNICATION UP', association)
        })
      }
    })
  }

  _sendPacket(host, port, tag, chunks, callback) {
    this.log('debug', '> send packet', host, port, tag, chunks)
    let packet = new Packet({
      source_port: this.localPort,
      destination_port: port,
      verification_tag: tag
    }, chunks)
    // todo multi-homing select active address
    rawsocket.sendPacket(this.localAddress, host, packet, callback)
  }

  createCookie(chunk, header, myTag) {
    let created = Math.floor(new Date() / 1000)
    let information = Buffer.alloc(16)
    information.writeUInt32BE(created, 0)
    information.writeUInt32BE(this.valid_cookie_life, 4)
    information.writeUInt16BE(header.source_port, 8)
    information.writeUInt16BE(header.destination_port, 10)
    information.writeUInt32BE(myTag, 12)
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
        source_port: information.readUInt16BE(8),
        destination_port: information.readUInt16BE(10),
        myTag: information.readUInt32BE(12)
      }
      /*
       Compare the port numbers and the Verification Tag contained
       within the COOKIE ECHO chunk to the actual port numbers and the
       Verification Tag within the SCTP common header of the received
       header.  If these values do not match, the packet MUST be
       silently discarded.
       */
      if (header.source_port === result.source_port &&
        header.destination_port === result.destination_port &&
        header.verification_tag === result.myTag) {
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
        this.log('warn', 'port verification error', header, result)
      }
    } else {
      this.log('warn', 'mac verification error', cookie.slice(0, 16), mac)
    }
  }

  _destroy() {
    rawsocket.unregister(this)
  }

  _getAssociation(host, port) {
    this.log('trace', 'select association', host, port)
    return this.associations[host + ':' + port]
  }

  ASSOCIATE(options) {
    /*
     Format: ASSOCIATE(local SCTP instance name,
     destination transport addr, outbound stream count)
     -> association id [,destination transport addr list]
     [,outbound stream count]
     */

    this.log('info', 'API ASSOCIATE', options)
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
    return association
  }

  DESTROY() {
    /*
     Format: DESTROY(local SCTP instance name)
     */
    this.log('trace', 'API DESTROY')
    this._destroy()
  }

  static INITIALIZE(options, logger) {
    let endpoint = new Endpoint(options, logger)
    return rawsocket.register(endpoint)
  }

}


module.exports = Endpoint