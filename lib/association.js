const crypto = require('crypto')
const EventEmitter = require('events').EventEmitter
const _ = require('lodash')
const ip = require('ip')
const Chunk = require('./chunk')
const defs = require('./defs')
const SerialNumber = require('./serial')

const MAX_DUPLICATES_LENGTH = 50

class Association extends EventEmitter {
  constructor(endpoint, options, initChunk, callback) {
    super()

    this.state = 'CLOSED'
    this.endpoint = endpoint
    this.localPort = endpoint.localPort

    this.remoteAddress = options.remoteAddress
    this.remotePort = options.remotePort
    this.MIS = options.MIS

    this.logger = endpoint.logger
    if (this.logger && (typeof this.logger.log === 'function')) {
      this.log = (level, ...rest) => {
        this.logger.log(level, 'association - [', this.localPort, '<->', this.remoteAddress, ']', ...rest)
      }
    } else {
      this.log = () => {
      }
    }

    this.log('trace', 'create association', options)

    // todo provide also way to iterate
    endpoint.associations[this.remoteAddress + ':' + this.remotePort] = this

    this.rto_initial = defs.net_sctp.rto_initial
    this.rto_min = defs.net_sctp.rto_min
    this.rto_max = defs.net_sctp.rto_max

    let PMTU = 1500 // todo
    if (!this.myRwnd) this.myRwnd = defs.net_sctp.RWND

    // TODO: for each remote address if multi-homing
    this.sack_timeout = defs.net_sctp.sack_timeout
    this.sack_freq = defs.net_sctp.sack_freq
    this.hb_interval = defs.net_sctp.hb_interval
    this.flightsize = 0

    //  13.3.  Per Transport Address Data
    this.default_address_data = {
      active: false,
      errors: 0,
      error_threshold: 10,
      cwnd: Math.min(4 * PMTU, Math.max(2 * PMTU, 4380)), //  7.2.1.  Slow-Start
      // ssthresh: this.myRwnd, // todo ?
      RTO: this.rto_initial,
      SRTT: 0,
      RTTVAR: 0,
      PMTU: PMTU,
      rtoPending: false // RTO-Pending
    }
    Object.assign(this, this.default_address_data) // todo tmp

    this.destinations = {}
    this.destinations[this.remoteAddress] = this.default_address_data

    // 13.2.  Parameters Necessary per Association (i.e., the TCB) todo review
    if (initChunk) {
      this.myTag = options.myTag
      this._updatePeer(initChunk)
      /*
        todo
       A COOKIE ACK MAY be sent to an UNCONFIRMED address, but it MUST be bundled with a HEARTBEAT including a nonce.
       An implementation that does NOT support bundling MUST NOT send a COOKIE ACK to an UNCONFIRMED address.
       2)  For the receiver of the COOKIE ECHO, the only CONFIRMED address is the one to which the INIT-ACK was sent.
      */
      this._up()
      this._sendChunk('cookie_ack', {}, null, () => {
        callback()
      })
    } else {
      this.OS = options.OS
      // todo ssthresh?
      this.peerTag = null
      this.myTag = crypto.randomBytes(4).readUInt32BE(0)
      // COOKIE-WAIT, COOKIE-ECHOED, ESTABLISHED, SHUTDOWN-PENDING, SHUTDOWN-SENT, SHUTDOWN-RECEIVED, SHUTDOWN-ACK-SENT

      this.peerRwnd = null // TCB
      this.lastRcvdTSN = null
      this.peerMaxTSN = null
      this.peerMinTrackTSN = null
    }

    this.nextTSN = SerialNumber(this.myTag)
    this.mapping_array = []
    this.HTNA = this.nextTSN.copy()

    this.peerSSN = []
    for (let sid = 0; sid < this.MIS; sid++) {
      this.peerSSN.push(SerialNumber(0, 16))
    }

    this.bundling = 0
    this.sacks = 0
    this.SSN = {}

    this.fastRecovery = false
    this.readBuffer = []
    this.duplicates = []
    this.everSentSack = false
    this.packetsSinceLastSack = 0
    this.bundleQueue = []
    this.sentChunks = {}
    this.countRcv = 0

    this.nonces = {}

    this.log('trace', 'association sack_timeout', this.sack_timeout)

    this.on('data', (chunk, source) => {
        this.countRcv++
        this.log('debug', '< received data chunk', chunk.tsn, ', total:', this.countRcv)
        if (!(this.state === 'ESTABLISHED' || this.state === 'SHUTDOWN-PENDING' || this.state === 'SHUTDOWN-SENT')) return
        if (!chunk.user_data || !chunk.user_data.length) {
          this.log('warn', '< received empty data chunk', chunk)
          this._abort({
            error_causes: [{cause: 'NO_USER_DATA', tsn: chunk.tsn}]
          }, source)
          return
        }
        this.log('trace', '< CHUNK data: TSN/lastTSN/flags/length', chunk.tsn, this.lastRcvdTSN.number, chunk.flags, chunk.user_data.length, chunk.user_data)
        let tsn = SerialNumber(chunk.tsn)
        let isDuplicate = false
        let zeroRwndDrop = false
        if (this.myRwnd <= 0 && tsn.gt(this.peerMaxTSN)) {
          /*
           When the receiver's advertised window is 0, the receiver MUST drop
           any new incoming DATA chunk with a TSN larger than the largest TSN
           received so far.

           If the new incoming DATA chunk holds a TSN value
           less than the largest TSN received so far, then the receiver SHOULD
           drop the largest TSN held for reordering and accept the new incoming
           DATA chunk.
           */
          this.log('warn', 'rwnd is 0 - drop tsn', tsn)
          zeroRwndDrop = true
        } else {
          let isLast = tsn.gt(this.peerMaxTSN)
          if (isLast) {
            this.peerMaxTSN = tsn
          }
          let offset = tsn.delta(this.peerMinTrackTSN)
          if (offset <= 0 || this.mapping_array[offset - 1]) {
            this.log('trace', 'duplicate TSN offset from peerMinTrackTSN', this.peerMinTrackTSN.number, offset)
            isDuplicate = true
            if (this.duplicates.length < MAX_DUPLICATES_LENGTH) {
              this.duplicates.push(chunk.tsn)
            }
          } else {
            this.log('trace', 'TSN offset from peerMinTrackTSN', this.peerMinTrackTSN.number, '=', offset, 'for', chunk.tsn)
            this.mapping_array[offset - 1] = chunk
            this.myRwnd -= chunk.user_data.length
            this.log('trace', 'reduce myRwnd to', this.myRwnd)
            if (isLast && !chunk.flags.E) {
              // don't scan yet
            } else {
              this._scan(offset)
            }
            if (tsn.gt(this.lastRcvdTSN)) this._updateCumulative()
            if (chunk.packet) this.packetsSinceLastSack++
          }
        }
        let haveGaps = this.lastRcvdTSN.lt(this.peerMaxTSN)
        if (this.state === 'SHUTDOWN-SENT') {
          /*
           While in the SHUTDOWN-SENT state, the SHUTDOWN sender MUST
           immediately respond to each received packet containing one or more
           DATA chunks with a SHUTDOWN chunk and restart the T2-shutdown timer.
           If a SHUTDOWN chunk by itself cannot acknowledge all of the received
           DATA chunks (i.e., there are TSNs that can be acknowledged that are
           larger than the cumulative TSN, and thus gaps exist in the TSN
           sequence), or if duplicate TSNs have been received, then a SACK chunk
           MUST also be sent.
           */
          this.log('trace', 'we are in the SHUTDOWN-SENT state - repeat SHUTDOWN')
          this._sendChunk('shutdown', {cumulative_tsn_ack: this.lastRcvdTSN.getNumber()})
          if (!(haveGaps || isDuplicate)) {
            this.log('trace', 'no gaps and not a duplicate')
            return
          }
        }
        let timeout = 0
        if (this.packetsSinceLastSack >= this.sack_freq || !this.everSentSack || haveGaps || isDuplicate || zeroRwndDrop) {
          // for all such we do sack immediately
          this.log('trace', 'SACK immediately')

          this.sacks++
          setTimeout(() => {
            this._sack()
          }, 0)
        } else {
          // normally set timeout 200 ms
          timeout = this.sack_timeout
        }
        if (timeout) {
          if (this._sackTimeout) {
            this.log('trace', 'SACK timeout already set')
          } else {
            this.log('trace', 'SACK timeout set', timeout, this.sack_timeout)
            this._sackTimeout = setTimeout(
              () => {
                this.log('trace', 'SACK timeout expired', timeout)
                this._sack()
              }, timeout)
          }
        }
      }
    )

    this.on('sack', (chunk) => {
      /*
       A SACK MUST be processed in ESTABLISHED, SHUTDOWN-PENDING, and
       SHUTDOWN-RECEIVED.  An incoming SACK MAY be processed in COOKIE-
       ECHOED.  A SACK in the CLOSED state is out of the blue and SHOULD be
       processed according to the rules in Section 8.4.  A SACK chunk
       received in any other state SHOULD be discarded.
       */
      if (!(this.state === 'ESTABLISHED'
          || this.state === 'SHUTDOWN-PENDING'
          || this.state === 'SHUTDOWN-RECEIVED'
          || this.state === 'COOKIE-ECHOED')) return

      this.log('trace', '< CHUNK sack', chunk.cumulative_tsn_ack, chunk.sack_info)
      this.log('trace', 'updating peer rwnd to', chunk.a_rwnd)
      this.peerRwnd = chunk.a_rwnd

      let cumulativeTsnAck = SerialNumber(chunk.cumulative_tsn_ack)
      let ackAdvanced = this.cumulativeTsnAck ? cumulativeTsnAck.gt(this.cumulativeTsnAck) : true
      this.cumulativeTsnAck = cumulativeTsnAck.copy()

      if (this.fastRecovery && cumulativeTsnAck.ge(this.fastRecoveryExitPoint)) {
        this.fastRecovery = false
        this.fastRecoveryExitPoint = null
      }
      let flightsize = this.flightsize
      _.each(this.sentChunks, (item, key) => {
        let t = SerialNumber(key)
        if (t.le(this.cumulativeTsnAck)) {
          this.log('trace', '_acknowledge', key)
          this._acknowledge(t)
        }
      })
      if (chunk.sack_info && chunk.sack_info.gap_blocks && chunk.sack_info.gap_blocks.length) {
        this.log('trace', '< CHUNK gap_blocks ', chunk.cumulative_tsn_ack, chunk.sack_info.gap_blocks)
        /*
         Whenever an endpoint receives a SACK that indicates that some TSNs
         are missing, it SHOULD wait for two further miss indications (via
         subsequent SACKs for a total of three missing reports) on the same
         TSNs before taking action with regard to Fast Retransmit.
         */

        let absent = []
        let tmp = []
        chunk.sack_info.gap_blocks.forEach((block, index) => {
          absent.push({
            start: SerialNumber(index ? chunk.cumulative_tsn_ack + chunk.sack_info.gap_blocks[index - 1].finish + 1 : chunk.cumulative_tsn_ack + 1),
            finish: SerialNumber(chunk.cumulative_tsn_ack + block.start - 1)
          })
          tmp.push({
            start: index ? chunk.cumulative_tsn_ack + chunk.sack_info.gap_blocks[index - 1].finish + 1 : chunk.cumulative_tsn_ack + 1,
            finish: chunk.cumulative_tsn_ack + block.start - 1
          })
          for (let t = this.cumulativeTsnAck.copy().inc(block.start); t.le(this.cumulativeTsnAck.copy().inc(block.finish)); t.inc(1)) {
            if (this.sentChunks[t.getNumber()]) {
              this._acknowledge(t)
            }
          }
        })
        // 7.2.4.  Fast Retransmit on Gap Reports
        this.log('trace', '< sack indicates absent blocks', tmp)
        /*
         Whenever an endpoint receives a SACK that indicates that some TSNs
         are missing, it SHOULD wait for two further miss indications (via
         subsequent SACKs for a total of three missing reports) on the same
         TSNs before taking action with regard to Fast Retransmit.
         */
        let doFastRetransmit = false
        absent.forEach((block) => {
          for (let tsn = block.start.copy(); tsn.le(block.finish); tsn.inc(1)) {
            let tsnNum = tsn.getNumber()
            if (this.sentChunks[tsnNum]) {
              /*
               Miss indications SHOULD follow the HTNA (Highest TSN Newly
               Acknowledged) algorithm.  For each incoming SACK, miss indications
               are incremented only for missing TSNs prior to the highest TSN newly
               acknowledged in the SACK.  A newly acknowledged DATA chunk is one not
               previously acknowledged in a SACK.  If an endpoint is in Fast
               Recovery and a SACK arrives that advances the Cumulative TSN Ack
               Point, the miss indications are incremented for all TSNs reported
               missing in the SACK.
               */
              this.log('trace', 'checks for fast retransmit of TSN (HTNA / fastRecovery / ackAdvanced)', tsnNum, this.HTNA.number, this.fastRecovery, ackAdvanced)
              if (tsn.lt(this.HTNA) || this.fastRecovery && ackAdvanced) {
                this.sentChunks[tsnNum].losses++
                this.log('trace', 'increment miss indications for TSN', tsnNum, this.sentChunks[tsnNum].losses)
                if (this.sentChunks[tsnNum].losses >= 3) {
                  /*
                   Mark the DATA chunk(s) with three miss indications for
                   retransmission.

                   A straightforward implementation of the above keeps a counter for
                   each TSN hole reported by a SACK.  The counter increments for each
                   consecutive SACK reporting the TSN hole.  After reaching 3 and
                   starting the Fast-Retransmit procedure, the counter resets to 0.
                   */
                  this.sentChunks[tsnNum].losses = 0
                  this.sentChunks[tsnNum].fastRetransmit = true
                  doFastRetransmit = true
                }
              }
            }
          }
        })
        if (doFastRetransmit) this._fastRetransmit()

        /*
         Whenever a SACK is received missing a TSN that was previously
         acknowledged via a Gap Ack Block, start the T3-rtx for the
         destination address to which the DATA chunk was originally
         transmitted if it is not already running.
         */
      } else {
        if (this.nextTSN.eq(this.cumulativeTsnAck.copy().inc(1))) {
          /*
           Whenever all outstanding data sent to an address have been
           acknowledged, turn off the T3-rtx timer of that address.
           */
          this.flightsize = 0
          this.log('trace', 'all outstanding data has been acknowledged')
          this._stopT3()
          if (this.state === 'SHUTDOWN-PENDING') {
            this._shutdown()
            return
          }
        }
      }
      if (chunk.sack_info && chunk.sack_info.duplicate_tsn && chunk.sack_info.duplicate_tsn.length) {
        this.log('trace', 'peer indicates duplicates', chunk.sack_info.duplicate_tsn)
      }
      if (ackAdvanced && this.flightsize) {
        /*
         When cwnd is less than or equal to ssthresh, an SCTP endpoint MUST
         use the slow-start algorithm to increase cwnd only if the current
         congestion window is being fully utilized, an incoming SACK
         advances the Cumulative TSN Ack Point, and the data sender is not
         in Fast Recovery.  Only when these three conditions are met can
         the cwnd be increased; otherwise, the cwnd MUST not be increased.
         If these conditions are met, then cwnd MUST be increased by, at
         most, the lesser of 1) the total size of the previously
         outstanding DATA chunk(s) acknowledged, and 2) the destination's
         path MTU.  This upper bound protects against the ACK-Splitting
         attack outlined in [SAVAGE99].
         */
        // TODO: rule to increase cwnd is unclear to me
        if (this.cwnd <= this.ssthresh && this.cwnd <= this.flightsize && !this.fastRecovery) {
          let totalAcknowledgedSize = flightsize - this.flightsize
          let cwndIncrease = Math.min(totalAcknowledgedSize, this.PMTU)
          this.cwnd += cwndIncrease
          this.log('trace', 'increase cwnd by %d (CWND / ssthresh)', cwndIncrease, this.cwnd, this.ssthresh)
        }

        /*
         Whenever a SACK is received that acknowledges the DATA chunk
         with the earliest outstanding TSN for that address, restart the
         T3-rtx timer for that address with its current RTO (if there is
         still outstanding data on that address).
         */
        this.log('trace', 'cumulative acknowledgement advanced to', this.cumulativeTsnAck.number)
        this._restartT3()
      }
      if (this.flightsize && this.flightsize < this.cwnd) {
        this.log('trace', 'flightsize < cwnd', this.flightsize, this.cwnd)
        this._retransmit()
      }
    })

    this.on('init_ack', (chunk, source) => {
      if (this.state === 'COOKIE-WAIT') {
        this.log('info', '< init_ack cookie', chunk.state_cookie)
        clearTimeout(this.T1)
        if (chunk.inbound_streams === 0) {
          // receiver of an INIT ACK with the MIS value set to 0 SHOULD destroy the association discarding its TCB
          this._abort({
            error_causes: [{cause: 'INVALID_MANDATORY_PARAMETER'}]
          }, source)
          return
        }
        this._updatePeer(chunk)
        this._sendChunk('cookie_echo', {cookie: chunk.state_cookie}, source, () => {
          this.log('info', 'sent cookie_echo', chunk.state_cookie)
        })
        /*
         If the receiver of an INIT ACK chunk detects unrecognized parameters
         and has to report them according to Section 3.2.1, it SHOULD bundle
         the ERROR chunk containing the 'Unrecognized Parameters' error cause
         with the COOKIE ECHO chunk sent in response to the INIT ACK chunk.
         If the receiver of the INIT ACK cannot bundle the COOKIE ECHO chunk
         with the ERROR chunk, the ERROR chunk MAY be sent separately but not
         before the COOKIE ACK has been received.

         Note: Any time a COOKIE ECHO is sent in a packet, it MUST be the
         first chunk.
         */
        if (chunk.errors) {
          this._sendChunk('error', {
            error_causes: [{
              cause: 'UNRECONGNIZED_PARAMETERS',
              unrecognized_parameters: Buffer.concat(chunk.errors)
            }]
          }, source)
        }
        this.state = 'COOKIE-ECHOED'
      } else {
        /*
         5.2.3.  Unexpected INIT ACK

         If an INIT ACK is received by an endpoint in any state other than the
         COOKIE-WAIT state, the endpoint should discard the INIT ACK chunk.
         An unexpected INIT ACK usually indicates the processing of an old or
         duplicated INIT chunk.
         */
        this.log('warn', 'Unexpected INIT ACK')
      }
    })

    this.on('heartbeat', (chunk, source) => {
      /*
       A receiver of a HEARTBEAT MUST respond to a
       HEARTBEAT with a HEARTBEAT-ACK after entering the COOKIE-ECHOED state
       (INIT sender) or the ESTABLISHED state (INIT receiver), up until
       reaching the SHUTDOWN-SENT state (SHUTDOWN sender) or the SHUTDOWN-
       ACK-SENT state (SHUTDOWN receiver). todo
      */
      this.log('trace', '< heartbeat', chunk.heartbeat_info.length, chunk.heartbeat_info)
      this._sendChunk('heartbeat_ack', {heartbeat_info: chunk.heartbeat_info}, source)
    })

    this.on('heartbeat_ack', (chunk) => {
      this.log('trace', '< heartbeat_ack', chunk.heartbeat_info.length, chunk.heartbeat_info)
      /*
       Upon receipt of the HEARTBEAT ACK, a verification is made that the
       nonce included in the HEARTBEAT parameter is the one sent to the
       address indicated inside the HEARTBEAT parameter.  When this match
       occurs, the address that the original HEARTBEAT was sent to is now
       considered CONFIRMED and available for normal data transfer.
      */
      let nonce = chunk.heartbeat_info.readUInt32BE(0)
      if (this.nonces[nonce]) {
        let address = ip.toString(chunk.heartbeat_info, 8, 4)
        this.log('trace', 'address confirmed alive', address)
      }
      delete this.nonces[nonce]
    })

    this.on('cookie_ack', () => {
      this._up()
      this.log('debug', '< CHUNK cookie_ack')
      if (this.state === 'COOKIE-ECHOED') {
        this.emit('COMMUNICATION UP')
      }
    })

    this.on('shutdown', (chunk, source) => {
      // TODO: 9.2.  Shutdown of an Association
      if (this.state === 'SHUTDOWN-RECEIVED') {
        /*
         Once an endpoint has reached the SHUTDOWN-RECEIVED state, it MUST NOT
         send a SHUTDOWN in response to a ULP request, and should discard
         subsequent SHUTDOWN chunks.
         */
        return
      } else if (this.state === 'SHUTDOWN-SENT') {
        /*
         If an endpoint is in the SHUTDOWN-SENT state and receives a SHUTDOWN
         chunk from its peer, the endpoint shall respond immediately with a
         SHUTDOWN ACK to its peer, and move into the SHUTDOWN-ACK-SENT state
         restarting its T2-shutdown timer.
         */
      } else {
        this.state = 'SHUTDOWN-RECEIVED'
      }
      this.log('info', '< CHUNK shutdown')
      this._down()
      //  TODO: check cumulative_tsn_ack
      /*
       cause: 'PROTOCOL_VIOLATION',
       additional_information: 'The cumulative tsn ack beyond the max tsn currently sent:\u0000\u0000\u0007\u0000\b'
       */
      /*
       verify, by checking the Cumulative TSN Ack field of the chunk,
       that all its outstanding DATA chunks have been received by the
       SHUTDOWN sender.
       If there are still outstanding DATA chunks left, the SHUTDOWN
       receiver MUST continue to follow normal data transmission procedures
       defined in Section 6, until all outstanding DATA chunks are
       acknowledged; however, the SHUTDOWN receiver MUST NOT accept new data
       from its SCTP user.
       */
      this._sendChunk('shutdown_ack', {}, source, () => {
        this.state = 'SHUTDOWN-ACK-SENT'
        this.log('info', 'sent shutdown_ack')
      })
    })

    this.on('shutdown_ack', (chunk, source) => {
      /*
       Upon the receipt of the SHUTDOWN ACK, the SHUTDOWN sender shall stop
       the T2-shutdown timer, send a SHUTDOWN COMPLETE chunk to its peer,
       and remove all record of the association.
       */
      this.log('info', '< CHUNK shutdown_ack')
      this.state = 'CLOSED'
      this.log('info', 'sending shutdown_complete')
      this._sendChunk('shutdown_complete', {}, source, () => {
        this.log('trace', 'sent shutdown_complete')
        this.emit('SHUTDOWN COMPLETE')
        this._destroy()
      })
    })

    this.on('shutdown_complete', () => {
      /*
       Upon reception of the SHUTDOWN COMPLETE chunk, the endpoint will
       verify that it is in the SHUTDOWN-ACK-SENT state; if it is not, the
       chunk should be discarded.  If the endpoint is in the SHUTDOWN-ACK-
       SENT state, the endpoint should stop the T2-shutdown timer and remove
       all knowledge of the association (and thus the association enters the
       CLOSED state).
       */
      if (this.state === 'SHUTDOWN-ACK-SENT') {
        this.log('info', '< CHUNK shutdown_complete')
        this.emit('SHUTDOWN COMPLETE')
        this._destroy()
      }
    })

    this.on('error', (chunk) => {
      this.log('error', '< CHUNK error', chunk)
      if (_.find(chunk.error_causes, {cause: 'STALE_COOKIE_ERROR'})) {
        // TODO: 5.2.6.  Handle Stale COOKIE Error
      }
      this.emit('COMMUNICATION ERROR', chunk.error_causes)
    })

    this.on('abort', (chunk) => {
      this.log('warn', '< CHUNK abort, connection closed')
      if (chunk.error_causes) {
        this.log('warn', chunk.error_causes)
      }
      this._down()
      if (this.bundleQueue.length) {
        this.log('trace', 'abandon sending of chunks', association.bundleQueue.length)
      }
      this.bundleQueue = []
      this.emit('COMMUNICATION LOST', 'abort', chunk.error_causes)
      this._destroy()
    })
  }

  /*
   B) SEND FAILURE notification

   If a message cannot be delivered, SCTP shall invoke this notification
   on the ULP.

   OPTIONAL
   o  data retrieval id - an identification used to retrieve unsent and
   unacknowledged data.
   o  cause code - indicating the reason of the failure, e.g., size too
   large, message life time expiration, etc.
   o  context - optional information associated with this message (see D
   in Section 10.1).

   C) NETWORK STATUS CHANGE notification

   When a destination transport address is marked inactive (e.g., when
   SCTP detects a failure) or marked active (e.g., when SCTP detects a
   recovery), SCTP shall invoke this notification on the ULP.

   MANDATORY
   o  destination transport address - this indicates the destination
   transport address of the peer endpoint affected by the change.

   o  new-status - this indicates the new status.

   D) COMMUNICATION UP notification

   This notification is used when SCTP becomes ready to send or receive
   user messages, or when a lost communication to an endpoint is
   restored.

   IMPLEMENTATION NOTE: If the ASSOCIATE primitive is implemented as a
   blocking function call, the association parameters are returned as a
   result of the ASSOCIATE primitive itself.  In that case,
   COMMUNICATION UP notification is optional at the association
   initiator's side.

   MANDATORY
   o  status -  This indicates what type of event has occurred.
   o  destination transport address list -  the complete set of
   transport addresses of the peer.
   o  outbound stream count -  the maximum number of streams allowed to
   be used in this association by the ULP.
   o  inbound stream count -  the number of streams the peer endpoint
   has requested with this association (this may not be the same
   number as 'outbound stream count').

   E) COMMUNICATION LOST notification

   When SCTP loses communication to an endpoint completely (e.g., via
   Heartbeats) or detects that the endpoint has performed an abort
   operation, it shall invoke this notification on the ULP.

   MANDATORY
   o  status -  this indicates what type of event has occurred; the
   status may indicate that a failure OR a normal
   termination event occurred in response to a shutdown or
   abort request.

   OPTIONAL
   o  data retrieval id -  an identification used to retrieve unsent and
   unacknowledged data.
   o  last-acked -  the TSN last acked by that peer endpoint.
   o  last-sent -  the TSN last sent to that peer endpoint.
   o  Upper Layer Abort Reason -  the abort reason specified in case of
   a user-initiated abort.


   G) RESTART notification

   When SCTP detects that the peer has restarted, it may send this
   notification to its ULP.
   */

  init() {
    let initParams = {
      initiate_tag: this.myTag,
      a_rwnd: defs.net_sctp.RWND,
      outbound_streams: this.OS,
      inbound_streams: this.MIS,
      initial_tsn: this.nextTSN.getNumber()
    }

    if (this.endpoint.localAddress) initParams.ipv4_address = this.endpoint.localAddress
    this.log('info', 'initParams', initParams)

    let counter = 0
    this.RTI = this.rto_initial
    let init = () => {
      if (counter >= defs.net_sctp.max_init_retransmits) {
        // fail
      } else {
        if (counter) {
          // not from RFC, but from lk-sctp
          this.RTI *= 2
          if (this.RTI > this.rto_max) this.RTI = this.rto_max
        }
        this._sendChunk('init', initParams)
        counter++
        this.T1 = setTimeout(init, this.RTO)
      }
    }
    init()
    this.state = 'COOKIE-WAIT'
  }

  _sendChunk(chunkType, options, destination, callback) {
    let chunk = new Chunk(chunkType, options)
    this.log('debug', '> send chunk', chunk)
    /*
     By default, an endpoint SHOULD always transmit to the primary path,
     unless the SCTP user explicitly specifies the destination transport
     address (and possibly source transport address) to use.

     An endpoint SHOULD transmit reply chunks (e.g., SACK, HEARTBEAT ACK,
     etc.) to the same destination transport address from which it
     received the DATA or control chunk to which it is replying.  This
     rule should also be followed if the endpoint is bundling DATA chunks
     together with the reply chunk.

     However, when acknowledging multiple DATA chunks received in packets
     from different source addresses in a single SACK, the SACK chunk may
     be transmitted to one of the destination transport addresses from
     which the DATA or control chunks being acknowledged were received.
    */
    if (chunkType === 'data' || chunkType === 'sack' || chunkType === 'heartbeat_ack') {
      // RFC allows to bundle other control chunks, but this gives almost no benefits
      this.log('trace', '> bundle-send', chunkType, options)
      chunk.callback = callback
      if (chunkType === 'data') {
        chunk.size = chunk.user_data.length + 16
      } else {
        chunk.buffer = chunk.toBuffer()
        chunk.size = chunk.buffer.length
      }
      this.bundleQueue.push(chunk)
      this.bundling++
      setTimeout(() => {
        this._bundle()
      }, 0)
    } else {
      // no bundle
      setTimeout(() => {
        // use nextTick to be in order with bundled chunks
        let buffer = chunk.toBuffer()
        this.log('trace', '> no-bundle send', chunkType)
        this._sendPacket([buffer], destination, [callback])
      }, 0)
    }
  }

  _scan() {
    let max = this.peerMaxTSN.delta(this.peerMinTrackTSN) - 1
    let res = null
    this.log('trace', 'start TSN scan from', this.peerMinTrackTSN.number, ', tracking length', this.mapping_array.length, max)
    for (let i = 0; i <= max; i++) {
      let chunk = this.mapping_array[i]
      if (typeof chunk === 'object') {
        if (chunk.flags.B) {
          // begin new probable reassemble
          if (chunk.flags.U || SerialNumber(chunk.stream_sequence_number).eq(this.peerSSN[chunk.stream_identifier])) {
            if (!chunk.flags.E) {
              this.log('trace', 'begin reassembling [U / SID / SSN]', chunk.flags.U, chunk.stream_identifier, chunk.stream_sequence_number)
            }
            res = {
              stream: chunk.stream_identifier,
              ssn: chunk.stream_sequence_number,
              data: [chunk.user_data],
              idx: [i]
            }
          } else {
            this.log('trace', 'postpone reassembling SID / SSN / peerSSN', chunk.stream_identifier, chunk.stream_sequence_number, this.peerSSN[chunk.stream_identifier].number)
          }
        }
        if (res && (chunk.flags.B || res.stream === chunk.stream_identifier && res.ssn === chunk.stream_sequence_number)) {
          if (!chunk.flags.B) {
            res.data.push(chunk.user_data)
            res.idx.push(i)
          }
          if (chunk.flags.E) {
            if (!chunk.flags.U) {
              this.peerSSN[res.stream].inc(1)
            }
            this.log('trace', 'deliver tracking index', res.idx, 'stream', res.stream, 'ssn', this.peerSSN[res.stream].number)
            this._deliver(Buffer.concat(res.data), res.stream)
            res.idx.forEach((i) => {
              this.mapping_array[i] = true
            })
            this._updateTrack()
          }
        } else {
          res = null
        }
      } else {
        res = null
      }
    }
    this.log('trace', 'end TSN scan, peerMinTrackTSN', this.peerMinTrackTSN.number)
  }

  _updateTrack() {
    let offsetTracking
    let max = this.peerMaxTSN.delta(this.peerMinTrackTSN)
    for (let i = 0; i < max; i++) {
      if (this.mapping_array[i] === true) {
        offsetTracking = i + 1
      } else {
        break
      }
    }
    if (offsetTracking) {
      this.peerMinTrackTSN.inc(offsetTracking)
      this.mapping_array.splice(0, offsetTracking)
      this.log('trace', 'updated track start peerMinTrackTSN / peerMaxTSN', this.peerMinTrackTSN.number, this.peerMaxTSN.number)
    }
  }

  _updateCumulative() {
    let max = this.peerMaxTSN.delta(this.peerMinTrackTSN)
    this.lastRcvdTSN = this.peerMinTrackTSN.copy()
    this.log('trace', 'update peerCumulativeTSN', this.lastRcvdTSN.number)
    let offsetCumulative
    for (let i = 0; i < max; i++) {
      if (this.mapping_array[i]) {
        offsetCumulative = i + 1
      } else {
        break
      }
    }
    if (offsetCumulative) {
      this.lastRcvdTSN.inc(offsetCumulative)
      this.log('trace', 'update peerCumulativeTSN', this.lastRcvdTSN.number)
    }
  }

  _sack() {
    if (this._sackTimeout) {
      clearTimeout(this._sackTimeout)
      delete this._sackTimeout
    }
    this.sacks--
    if (this.sacks > 0) {
      // wait for last sack request in idle cycle
      this.log('trace', this.sacks, 'grouping SACKs, wait next...')
      return
    }
    let gap_blocks = []
    let max = this.peerMaxTSN.delta(this.lastRcvdTSN)
    let offset = this.lastRcvdTSN.delta(this.peerMinTrackTSN)
    let start
    let finish
    let gap
    for (let i = 0; i <= max; i++) {
      let chunk = this.mapping_array[i + offset]
      if (chunk) {
        if (gap && !start) start = i
        //gap = false
      } else {
        gap = true
        if (start) {
          gap_blocks.push({
            start: start + 1,
            finish: i
          })
          start = null
          finish = null
        }
      }
    }
    let sackOptions = {
      a_rwnd: this.myRwnd > 0 ? this.myRwnd : 0,
      cumulative_tsn_ack: this.lastRcvdTSN.getNumber()
    }
    if (gap_blocks || this.duplicates.length) {
      sackOptions.sack_info = {
        gap_blocks: gap_blocks,
        duplicate_tsn: this.duplicates
      }
    }
    if (gap_blocks.length) {
      this.log('warn', '< packet loss:', gap_blocks.length, 'gap blocks')
      this.log('trace', 'gap_blocks', gap_blocks)
    }
    this.log('trace', 'prepared SACK', sackOptions)
    this._sendChunk('sack', sackOptions)
    if (!this.everSentSack) this.everSentSack = true
    this.duplicates = []
    this.packetsSinceLastSack = 0
  }

  _acknowledge(tsn) {
    this.flightsize -= this.sentChunks[tsn.getNumber()].size
    if (!this.HTNA || tsn.gt(this.HTNA)) {
      this.HTNA = tsn.copy()
    }
    delete this.sentChunks[tsn.getNumber()]
    // RTO calculation
    if (this.rtoPending && this.rtoPending.tsn.eq(tsn)) {
      this._updateRTO(new Date() - this.rtoPending.sent)
      this.rtoPending = false
    }
  }

  _updateRTO(R) {
    if (!this.SRTT) {
      this.SRTT = R
      this.RTTVAR = R / 2
      this.RTTVAR = Math.max(this.RTTVAR, defs.net_sctp.G)
      this.RTO = this.SRTT + 4 * this.RTTVAR
    } else {
      let alpha = 1 / defs.net_sctp.rto_alpha_exp_divisor
      let beta = 1 / defs.net_sctp.rto_beta_exp_divisor
      this.RTTVAR = (1 - beta) * this.RTTVAR + beta * Math.abs(this.SRTT - R)
      this.RTTVAR = Math.max(this.RTTVAR, defs.net_sctp.G)
      this.SRTT = (1 - alpha) * this.SRTT + alpha * R
      this.RTO = this.SRTT + 4 * this.RTTVAR
    }
    if (this.RTO < this.rto_min) this.RTO = this.rto_min
    if (this.RTO > this.rto_max) this.RTO = this.rto_max
    this.log('trace', 'new RTO', this.RTO)
  }

  _startT3() {
    if (this.T3) {
      this.log('trace', 'T3-rtx timer is already running')
      return
    }
    this.log('trace', 'start T3-rtx timer', this.RTO)
    this.T3 = setTimeout(this._expireT3.bind(this), this.RTO)
  }

  _stopT3() {
    if (this.T3) {
      this.log('trace', 'stop T3-rtx timer')
      clearTimeout(this.T3)
      this.T3 = null
    }
  }

  _restartT3() {
    this.log('trace', 'restart T3 timer')
    this._stopT3()
    this._startT3()
  }

  _expireT3() {
    this.T3 = null
    this.log('trace', 'T3-rtx timer has expired')
    if (Object.keys(this.sentChunks).length === 0) {
      this.log('warn', 'bug: there are no chunks in flight')
      return
    }

    /*
     6.3.3.  Handle T3-rtx Expiration

     Whenever the retransmission timer T3-rtx expires for a destination
     address, do the following:

     E1)  For the destination address for which the timer expires, adjust
     its ssthresh with rules defined in Section 7.2.3 and set the
     cwnd <- MTU.


     When the T3-rtx timer expires on an address, SCTP should perform slow
     start by:

     ssthresh = max(cwnd/2, 4*MTU)
     cwnd = 1*MTU

     and ensure that no more than one SCTP packet will be in flight for
     that address until the endpoint receives acknowledgement for
     successful delivery of data to that address.
     */
    this.ssthresh = Math.max(this.cwnd / 2, 4 * this.PMTU)
    this.cwnd = this.PMTU
    /*
     E2)  For the destination address for which the timer expires, set RTO
     <- RTO * 2 ("back off the timer").  The maximum value discussed
     in rule C7 above (RTO.max) may be used to provide an upper bound
     to this doubling operation.
     */
    if (this.RTO < this.rto_max) {
      this.RTO *= 2
      if (this.RTO > this.rto_max) {
        this.RTO = this.rto_max
      }
    }
    this.log('trace', 'adjustments on expire: cwnd / ssthresh / RTO', this.cwnd, this.ssthresh, this.RTO)
    /*
     E3)  Determine how many of the earliest (i.e., lowest TSN)
     outstanding DATA chunks for the address for which the T3-rtx has
     expired will fit into a single packet, subject to the MTU
     constraint for the path corresponding to the destination
     transport address to which the retransmission is being sent
     (this may be different from the address for which the timer
     expires; see Section 6.4).  Call this value K.  Bundle and
     retransmit those K DATA chunks in a single packet to the
     destination endpoint.
     */
    let bundledLength = 20
    let bundledCount = 0
    let tsns = []
    _.some(this.sentChunks, (chunk) => {
      this.log('trace', 'retransmit tsn', chunk.tsn)
      if (bundledLength + chunk.user_data.length + 16 > this.PMTU) {
        /*
         Note: Any DATA chunks that were sent to the address for which the
         T3-rtx timer expired but did not fit in one MTU (rule E3 above)
         should be marked for retransmission and sent as soon as cwnd allows
         (normally, when a SACK arrives).
         */
        this.log('trace', 'retransmit tsn later!', chunk.tsn)
        chunk.retransmit = true
      } else {
        bundledCount++
        bundledLength += chunk.user_data.length + 16
        tsns.push(chunk.tsn)
        this._sendChunk('data', chunk)
      }
    })
    this.log('trace', 'retransmitted chunks: count / bytes', bundledCount, bundledLength, tsns)
    if (bundledCount > 0) {
      /*
       E4)  Start the retransmission timer T3-rtx on the destination address
       to which the retransmission is sent, if rule R1 above indicates
       to do so.  The RTO to be used for starting T3-rtx should be the
       one for the destination address to which the retransmission is
       sent, which, when the receiver is multi-homed, may be different
       from the destination address for which the timer expired (see
       Section 6.4 below).
       */
      this._startT3()
    }
    /*
     After retransmitting, once a new RTT measurement is obtained (which
     can happen only when new data has been sent and acknowledged, per
     rule C5, or for a measurement made from a HEARTBEAT; see Section
     8.3), the computation in rule C3 is performed, including the
     computation of RTO, which may result in "collapsing" RTO back down
     after it has been subject to doubling (rule E2).
     */
  }

  _retransmit() {
    this.log('trace', 'check retransmit')
    _.some(this.sentChunks, (chunk) => {
      if (chunk.retransmit) {
        this.log('warn', 'more retransmit', chunk.tsn)
        this._sendChunk('data', chunk)
      }
    })
  }

  _fastRetransmit() {
    /*
     Note: Before the above adjustments, if the received SACK also
     acknowledges new DATA chunks and advances the Cumulative TSN Ack
     Point, the cwnd adjustment rules defined in Section 7.2.1 and Section
     7.2.2 must be applied first.
     */
    if (!this.fastRecovery) {
      /*
       If not in Fast Recovery, adjust the ssthresh and cwnd of the
       destination address(es) to which the missing DATA chunks were
       last sent, according to the formula described in Section 7.2.3.

       ssthresh = max(cwnd/2, 4*MTU)
       cwnd = ssthresh
       partial_bytes_acked = 0

       Basically, a packet loss causes cwnd to be cut in half.
       */
      this.ssthresh = Math.max(this.cwnd / 2, 4 * this.PMTU)
      this.cwnd = this.ssthresh
      this.partial_bytes_acked = 0 // todo
      /*
       If not in Fast Recovery, enter Fast Recovery and mark the highest
       outstanding TSN as the Fast Recovery exit point.  When a SACK
       acknowledges all TSNs up to and including this exit point, Fast
       Recovery is exited.  While in Fast Recovery, the ssthresh and
       cwnd SHOULD NOT change for any destinations due to a subsequent
       Fast Recovery event (i.e., one SHOULD NOT reduce the cwnd further
       due to a subsequent Fast Retransmit).
       */
      this.fastRecovery = true
      this.fastRecoveryExitPoint = this.nextTSN.prev()
      this.log('trace', 'entered fast recovery mode, cwnd/ ssthresh', this.cwnd, this.ssthresh)
    }
    /*
     3)  Determine how many of the earliest (i.e., lowest TSN) DATA chunks
     marked for retransmission will fit into a single packet, subject
     to constraint of the path MTU of the destination transport
     address to which the packet is being sent.  Call this value K.
     Retransmit those K DATA chunks in a single packet.  When a Fast
     Retransmit is being performed, the sender SHOULD ignore the value
     of cwnd and SHOULD NOT delay retransmission for this single
     packet.
     */
    let bundledLength = 36 // 20 + 16
    let bundledCount = 0
    let tsns = []
    _.some(this.sentChunks, (chunk) => {
      if (chunk.fastRetransmit) {
        this.log('trace', 'fast retransmit tsn', chunk.tsn)
        if (bundledLength + chunk.user_data.length + 16 > this.PMTU) {
          return true
        } else {
          bundledCount++
          bundledLength += chunk.user_data.length + 16
          tsns.push(chunk.tsn)
          this._sendChunk('data', chunk)
        }
      }
    })
    this.log('trace', 'fast retransmitted chunks / bytes', bundledCount, bundledLength, tsns)
    /*
     4)  Restart the T3-rtx timer only if the last SACK acknowledged the
     lowest outstanding TSN number sent to that address, or the
     endpoint is retransmitting the first outstanding DATA chunk sent
     to that address.
     */
    // TODO: Restart the T3-rtx timer only if the last SACK acknowledged
    if (bundledCount > 0) this._restartT3()
  }

  _up() {
    /*
     HEARTBEAT sending MAY begin upon reaching the
     ESTABLISHED state and is discontinued after sending either SHUTDOWN
     or SHUTDOWN-ACK. todo
    */
    this.state = 'ESTABLISHED'
    this._enableHeartbeat()
    this.log('info', 'association established')
  }

  _down() {
    clearInterval(this._heartbeatInterval)
    clearTimeout(this.T1)
    clearTimeout(this._sackTimeout)
  }

  _enableHeartbeat() {
    this._heartbeatInterval = setInterval(() => {
      /*
       To probe an address for verification, an endpoint will send
       HEARTBEATs including a 64-bit random nonce and a path indicator (to
       identify the address that the HEARTBEAT is sent to) within the
       HEARTBEAT parameter.
       */
      for (let address in this.destinations) {
        let destination = this.destinations[address]
        let heartbeat_info = crypto.randomBytes(12)
        let nonce = heartbeat_info.readUInt32BE(0)
        this.nonces[nonce] = true
        ip.toBuffer(address, heartbeat_info, 8)
        this.log('trace', '> heartbeat', heartbeat_info.length, heartbeat_info)
        this._sendChunk('heartbeat', {heartbeat_info}, address)
        /*
         The endpoint should increment the respective error counter of the
         destination transport address each time a HEARTBEAT is sent to that
         address and not acknowledged within one RTO.

         When the value of this counter reaches the protocol parameter
         'Path.Max.Retrans', the endpoint should mark the corresponding
         destination address as inactive if it is not so marked, and may also
         optionally report to the upper layer the change of reachability of
         this destination address.  After this, the endpoint should continue
         HEARTBEAT on this destination address but should stop increasing the
         counter.
        */
      }
    }, this.hb_interval)
  }

  _sendPacket(buffers, destination, callbacks) {
    // TODO: order of destroying
    if (!this.endpoint) return
    this.endpoint._sendPacket(destination || this.remoteAddress, this.remotePort, this.peerTag, buffers,
      () => {
        callbacks.forEach((cb) => {
          if (typeof cb === 'function') cb()
        })
      })
  }

  _deliver(user_data, stream) {
    this.log('debug', '< receive user data bytes ', user_data.length)
    this.myRwnd += user_data.length
    this.log('trace', 'new myRwnd ', this.myRwnd)
    if (this.listeners('DATA ARRIVE')) {
      this.readBuffer.push(user_data)
      this.emit('DATA ARRIVE', stream)
    }
  }

  _bundle() {
    if (this.state === 'CLOSED') return
    if (this.bundleQueue.length === 0) return
    this.bundling--
    if (this.bundling > 0) {
      return
    }
    let callbacks = []
    let bundledChunks = []
    let bundledLength = 36 // 20 + 16
    let mtu = this.PMTU
    this.bundleQueue.push(null)
    let emulateLoss = false
    let haveCookieEcho = false
    let haveData = false
    let tsns = []
    this.log('trace', 'process bundle queue', this.bundleQueue)
    this.bundleQueue.forEach((chunk, index) => {
      if (index === this.bundleQueue.length - 1 || bundledLength + chunk.size > mtu) {
        if (bundledChunks.length > 0) {
          this.log('trace', 'send bundled chunks bytes / count', bundledLength, bundledChunks.length)
          if (emulateLoss) {
            this.log('fatal', 'emulated loss of packet with tsns', tsns)
          } else {
            // todo select destination here?
            this._sendPacket(bundledChunks, null, callbacks)
          }
          if (haveData) this._startT3()
          bundledChunks = []
          callbacks = []
          tsns = []
          bundledLength = 36 // 20 + 16
          haveCookieEcho = false
          haveData = false
        }
      }
      let buffer
      if (chunk === null) return
      if (chunk.size > mtu) {
        this.log('error', 'chunk size > mtu', mtu, chunk)
        return
      }
      if (chunk.chunkType === 'data') {
        haveData = true
        /*
         Data transmission MUST only happen in the ESTABLISHED, SHUTDOWN-
         PENDING, and SHUTDOWN-RECEIVED states.  The only exception to this is
         that DATA chunks are allowed to be bundled with an outbound COOKIE
         ECHO chunk when in the COOKIE-WAIT state.
         */
        if (this.state === 'ESTABLISHED' || this.state === 'SHUTDOWN-PENDING' || this.state === 'SHUTDOWN-RECEIVED') {
          //  allow
        } else if (this.state === 'COOKIE-WAIT' && haveCookieEcho) {
          // allow
        } else {
          // TODO: force bundle
          this.log('error', 'data transmission MUST only happen in the ESTABLISHED, SHUTDOWN-PENDING, and SHUTDOWN-RECEIVED states', chunk)
          return
        }
        /*
         IMPLEMENTATION NOTE: In order to better support the data life time
         option, the transmitter may hold back the assigning of the TSN number
         to an outbound DATA chunk to the last moment.  And, for
         implementation simplicity, once a TSN number has been assigned the
         sender should consider the send of this DATA chunk as committed,
         overriding any life time option attached to the DATA chunk.
         */
        if (chunk.tsn === null) {
          // not a retransmit
          chunk.tsn = this.nextTSN.getNumber()
          this.nextTSN.inc(1)
        }
        if (!this.rtoPending) {
          this.rtoPending = {
            tsn: SerialNumber(chunk.tsn),
            sent: new Date()
          }
        }
        buffer = chunk.toBuffer()
        tsns.push(chunk.tsn)
        chunk.losses = 0
        this.sentChunks[chunk.tsn] = chunk
        this.flightsize += buffer.length
      } else {
        buffer = chunk.buffer
        delete chunk.buffer
        if (chunk.chunkType === 'cookie_echo') {
          haveCookieEcho = true
        }
      }
      bundledChunks.push(buffer)
      bundledLength += buffer.length
      callbacks.push(chunk.callback)
      this.log('trace', 'bundled chunk type/TSN/length/total', chunk.chunkType, chunk.tsn, buffer.length, bundledLength)
    })
    this.bundleQueue = []
  }

  _shutdown(callback) {
    this._down()
    this._sendChunk('shutdown', {cumulative_tsn_ack: this.lastRcvdTSN.getNumber()}, null, () => {
      /*
       It shall then start the T2-shutdown timer and enter the SHUTDOWN-SENT
       state.  If the timer expires, the endpoint must resend the SHUTDOWN
       with the updated last sequential TSN received from its peer.
       The rules in Section 6.3 MUST be followed to determine the proper
       timer value for T2-shutdown.
       */
      // TODO: T2-shutdown timer
      this.state = 'SHUTDOWN-SENT'
      this.log('info', 'sent shutdown')
      if (typeof callback === 'function') callback()
    })
    /*
     The sender of the SHUTDOWN MAY also start an overall guard timer
     'T5-shutdown-guard' to bound the overall time for the shutdown
     sequence.  At the expiration of this timer, the sender SHOULD abort
     the association by sending an ABORT chunk.  If the 'T5-shutdown-
     guard' timer is used, it SHOULD be set to the recommended value of 5
     times 'RTO.Max'.
     */
    this.T5 = setTimeout(() => {
      this._abort()
    }, this.rto_max * 5)
  }

  _destroy() {
    this.log('trace', 'destroy association')
    this.state = 'CLOSED'
    clearTimeout(this.T1)
    clearTimeout(this.T3)
    clearTimeout(this.T5)
    // TODO: better destroy assoc first, then endpoint
    if (this.endpoint) {
      for (let address in this.destinations) {
        let key = address + ':' + this.remotePort
        this.log('trace', 'destroy remote address', key)
        delete this.endpoint.associations[key]
      }
      delete this.endpoint
    }
  }

  SHUTDOWN(callback) {
    /*
     Format: SHUTDOWN(association id)
     -> result
     */

    this.log('trace', 'API SHUTDOWN in state', this.state)
    if (this.state !== 'ESTABLISHED') {
      this.log('trace', 'just destroy association')
      this._destroy()
      return
    }
    this.state = 'SHUTDOWN-PENDING'
    /*
     Upon receipt of the SHUTDOWN primitive from its upper layer, the
     endpoint enters the SHUTDOWN-PENDING state and remains there until
     all outstanding data has been acknowledged by its peer.  The endpoint
     accepts no new data from its upper layer, but retransmits data to the
     far end if necessary to fill gaps.

     Once all its outstanding data has been acknowledged, the endpoint
     shall send a SHUTDOWN chunk to its peer including in the Cumulative
     TSN Ack field the last sequential TSN it has received from the peer.
     */
    this._shutdown(callback)
  }

  ABORT(reason) {
    /*
     Format: ABORT(association id [, Upper Layer Abort Reason]) ->
     result
     */

    this.log('trace', 'API ABORT')
    this._down()
    let options = {}
    if (reason) {
      options.error_causes = [
        {
          cause: 'USER_INITIATED_ABORT',
          abort_reason: reason
        }
      ]
    }
    this._abort(options)
  }

  _abort(options, destination) {
    this._sendChunk('abort', options, destination, () => {
      this.log('info', 'sent abort')
    })
    this._destroy()
  }

  SEND(buffer, sctp_sndrcvinfo, callback) {
    /*
     Format: SEND(association id, buffer address, byte count [,context]
     [,stream id] [,life time] [,destination transport address]
     [,unordered flag] [,no-bundle flag] [,payload protocol-id] )
     -> result
     */

    // TODO: 6.1.  Transmission of DATA Chunks

    this.log('trace', 'SEND bytes', buffer.length, sctp_sndrcvinfo)
    let error = false
    if (this.state === 'SHUTDOWN-PENDING' || this.state === 'SHUTDOWN-RECEIVED') {
      /*
       Upon receipt of the SHUTDOWN primitive from its upper layer, the endpoint enters the SHUTDOWN-PENDING state ... accepts no new data from its upper layer
       Upon reception of the SHUTDOWN, the peer endpoint shall enter the SHUTDOWN-RECEIVED state, stop accepting new data from its SCTP user
       */
      error = 'not accepting new data in SHUTDOWN state'
    } else if (buffer.length >= this.peerRwnd) {
      /*
       At any given time, the data sender MUST NOT transmit new data to
       any destination transport address if its peer's rwnd indicates
       that the peer has no buffer space (i.e., rwnd is 0; see Section
       6.2.1).
       */
      error = 'peer has no buffer space (rwnd) for new packet ' + this.peerRwnd
    } else if (this.flightsize >= this.cwnd) {
      /*
       At any given time, the sender MUST NOT transmit new data to a
       given transport address if it has cwnd or more bytes of data
       outstanding to that transport address.
       */
      error = 'flightsize >= cwnd ' + this.flightsize + ' ' + this.cwnd
    }

    /*
     When the receiver's advertised window is zero, this probe is
     called a zero window probe.  Note that a zero window probe SHOULD
     only be sent when all outstanding DATA chunks have been
     cumulatively acknowledged and no DATA chunks are in flight.  Zero
     window probing MUST be supported.

     If the sender continues to receive new packets from the receiver
     while doing zero window probing, the unacknowledged window probes
     should not increment the error counter for the association or any
     destination transport address.  This is because the receiver MAY
     keep its window closed for an indefinite time.  Refer to Section
     6.2 on the receiver behavior when it advertises a zero window.
     The sender SHOULD send the first zero window probe after 1 RTO
     when it detects that the receiver has closed its window and SHOULD
     increase the probe interval exponentially afterwards.  Also note
     that the cwnd SHOULD be adjusted according to Section 7.2.1.  Zero
     window probing does not affect the calculation of cwnd.

     The sender MUST also have an algorithm for sending new DATA chunks
     to avoid silly window syndrome (SWS) as described in [RFC0813].
     The algorithm can be similar to the one described in Section
     4.2.3.4 of [RFC1122].
     */
    // TODO: !! zero window probe & silly window syndrome (SWS) !!
    // TODO: also look at cwnd calc

    if (error) {
      this.log('warn', 'SEND error', error)
      error = new Error(error)
    } else {
      /*
       Before an endpoint transmits a DATA chunk, if any received DATA
       chunks have not been acknowledged (e.g., due to delayed ack), the
       sender should create a SACK and bundle it with the outbound DATA
       chunk, as long as the size of the final SCTP packet does not exceed
       the current MTU.  See Section 6.2.
       */
      if (this._sackTimeout) {
        this.log('trace', 'cancel SACK timer and do it now')
        this._sack()
      }
      /*
       C) When the time comes for the sender to transmit, before sending new
       DATA chunks, the sender MUST first transmit any outstanding DATA
       chunks that are marked for retransmission (limited by the current
       cwnd).
       */
      this._retransmit()
      /*
       D) When the time comes for the sender to transmit new DATA chunks,
       the protocol parameter Max.Burst SHOULD be used to limit the
       number of packets sent.  The limit MAY be applied by adjusting
       cwnd as follows:

       if((flightsize + Max.Burst*MTU) < cwnd) cwnd = flightsize +
       Max.Burst*MTU

       Or it MAY be applied by strictly limiting the number of packets
       emitted by the output routine.
       */
      if (this.flightsize + defs.net_sctp.max_burst * this.PMTU < this.cwnd) {
        // TODO: compare to another adjustments
        this.cwnd = this.flightsize + defs.net_sctp.max_burst * this.PMTU
        this.log('trace', 'adjust cwnd to flightsize + Max.Burst*MTU ', this.cwnd)
      }
      let chunk
      let stream = sctp_sndrcvinfo.stream || 0
      if (stream < 0 || stream > this.OS) {
        this.log('warn', 'wrong stream id', stream)
        return
      }
      if (!this.SSN[stream]) this.SSN[stream] = SerialNumber(0, 16)
      let mtu = this.PMTU - 52 // - 16 - 16 - 20
      if (buffer.length > mtu) {
        let offset = 0
        while (offset < buffer.length) {
          chunk = {
            flags: {
              "E": buffer.length - offset <= mtu,
              "B": offset === 0,
              "U": sctp_sndrcvinfo.unordered,
              "I": 0
            },
            stream_identifier: stream,
            stream_sequence_number: this.SSN[stream].getNumber(),
            payload_protocol_identifier: sctp_sndrcvinfo.protocol,
            user_data: buffer.slice(offset, offset + mtu)
          }
          offset += mtu
          this._sendChunk('data', chunk)
        }
      } else {
        chunk = {
          flags: {
            "E": 1,
            "B": 1,
            "U": sctp_sndrcvinfo.unordered,
            "I": 0
          },
          stream_identifier: stream,
          stream_sequence_number: this.SSN[stream].getNumber(),
          payload_protocol_identifier: sctp_sndrcvinfo.protocol,
          user_data: buffer
        }
        this._sendChunk('data', chunk)
      }
      this.SSN[stream].inc(1)
      this.log('trace', buffer.length, 'bytes sent, cwnd', this.cwnd)
    }
    callback(error)
  }

  SETPRIMARY() {
    /*
     Format: SETPRIMARY(association id, destination transport address,
     [source transport address] )
     -> result
     */

  }

  RECEIVE() {
    /*
     Format: RECEIVE(association id, buffer address, buffer size
     [,stream id])
     -> byte count [,transport address] [,stream id] [,stream sequence
     number] [,partial flag] [,delivery number] [,payload protocol-id]
     */
    this.log('trace', 'API RECEIVE', this.readBuffer[0])
    return this.readBuffer.shift()
  }

  STATUS() {
    /*
     Format: STATUS(association id)
     -> status data

     association connection state,
     destination transport address list,
     destination transport address reachability states,
     current receiver window size,
     current congestion window sizes,
     number of unacknowledged DATA chunks,
     number of DATA chunks pending receipt,
     primary path,
     most recent SRTT on primary path,
     RTO on primary path,
     SRTT and RTO on other destination addresses, etc.
     */

  }

  CHANGEHEARTBEAT() {
    /*
     Format: CHANGE HEARTBEAT(association id,
     destination transport address, new state [,interval])
     -> result
     */

  }

  REQUESTHEARTBEAT() {
    /*
     Format: REQUESTHEARTBEAT(association id, destination transport
     address)
     -> result
     */

  }

  SETFAILURETHRESHOLD() {
    /*
     Format: SETFAILURETHRESHOLD(association id, destination transport
     address, failure threshold)

     -> result
     */

  }

  SETPROTOCOLPARAMETERS() {
    /*
     Format: SETPROTOCOLPARAMETERS(association id,
     [,destination transport address,]
     protocol parameter list)
     -> result
     */

  }

  RECEIVE_UNSENT() {
    /*
     Format: RECEIVE_UNSENT(data retrieval id, buffer address, buffer
     size [,stream id] [, stream sequence number] [,partial
     flag] [,payload protocol-id])

     */

  }

  RECEIVE_UNACKED() {
    /*
     Format: RECEIVE_UNACKED(data retrieval id, buffer address, buffer
     size, [,stream id] [, stream sequence number] [,partial
     flag] [,payload protocol-id])

     */
  }

  _updatePeer(chunk) {
    this.OS = chunk.inbound_streams
    this.peerTag = chunk.initiate_tag
    this.peerRwnd = chunk.a_rwnd
    this.ssthresh = chunk.a_rwnd
    this.peerInitialTSN = chunk.initial_tsn
    this.lastRcvdTSN = SerialNumber(this.peerInitialTSN).prev()
    this.peerMaxTSN = this.lastRcvdTSN.copy()
    this.peerMinTrackTSN = this.lastRcvdTSN.copy()
    if (chunk.ipv4_address) {
      chunk.ipv4_address.forEach((address) => {
          this.log('debug', 'peer ipv4_address', address)
          if (!(address in this.destinations)) {
            this.destinations[address] = this.default_address_data
            this.endpoint.associations[address + ':' + this.remotePort] = this
          }
        }
      )
    }
  }

}

module.exports = Association