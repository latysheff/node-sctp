const crypto = require('crypto')
const EventEmitter = require('events').EventEmitter
const debug = require('debug')
const ip = require('ip')
const Chunk = require('./chunk')
const defs = require('./defs')
const SN = require('./serial')

const MAX_DUPLICATES_LENGTH = 50

class Association extends EventEmitter {
  constructor(endpoint, options) {
    super()
    setInterval(() => {
      // This.debugger.warn('peer_rwnd %d', this.peer_rwnd, this.drain(65555))
    }, 777)
    this.state = 'CLOSED'
    this.endpoint = endpoint
    this.localPort = endpoint.localPort

    this.remoteAddress = options.remoteAddress || undefined
    this.remotePort = options.remotePort

    this.my_tag = options.my_tag || crypto.randomBytes(4).readUInt32BE(0)
    this.OS = options.OS
    this.MIS = options.MIS

    this.debugger = {}
    const label = `[${this.localPort}/${this.remoteAddress}:${this.remotePort}]`
    this.debugger.warn = debug(`sctp:assoc:### ${label}`)
    this.debugger.info = debug(`sctp:assoc:## ${label}`)
    this.debugger.debug = debug(`sctp:assoc:# ${label}`)
    this.debugger.trace = debug(`sctp:assoc: ${label}`)

    this.debugger.debug('create association')

    // Todo provide also way to iterate
    const key = this.remoteAddress + ':' + this.remotePort
    endpoint.associations_lookup[key] = this
    endpoint.associations.push(this)

    this.rto_initial = defs.NET_SCTP.rto_initial
    this.rto_min = defs.NET_SCTP.rto_min
    this.rto_max = defs.NET_SCTP.rto_max

    const PMTU = 1500 // Todo

    this.my_rwnd = this.my_rwnd || defs.NET_SCTP.RWND
    this.peer_rwnd = 0

    // TODO: for each remote address if multi-homing
    this.sack_timeout = defs.NET_SCTP.sack_timeout
    this.sack_freq = defs.NET_SCTP.sack_freq
    this.hb_interval = defs.NET_SCTP.hb_interval
    this.flightsize = 0

    //  13.3.  Per Transport Address Data
    this.default_address_data = {
      active: false,
      errors: 0,
      error_threshold: 10,
      cwnd: Math.min(4 * PMTU, Math.max(2 * PMTU, 4380)), //  7.2.1.  Slow-Start
      // ssthresh: this.my_rwnd, // todo ?
      RTO: this.rto_initial,
      SRTT: 0,
      RTTVAR: 0,
      PMTU,
      rtoPending: false // RTO-Pending
    }
    Object.assign(this, this.default_address_data) // Todo

    this.destinations = {}
    if (this.remoteAddress) {
      this.destinations[this.remoteAddress] = this.default_address_data
    }

    this.my_next_tsn = new SN(this.my_tag)
    this.mapping_array = []
    this.HTNA = this.my_next_tsn.copy()

    this.peer_ssn = []
    for (let sid = 0; sid < this.MIS; sid++) {
      this.peer_ssn.push(new SN(0, 16))
    }

    this.bundling = 0
    this.sacks = 0
    this.SSN = {}
    this.fastRecovery = false
    this.readBuffer = []
    this.duplicates = []
    this.everSentSack = false
    this.packetsSinceLastSack = 0
    this.queue = []
    this.sent = {}
    this.countRcv = 0
    this.nonces = {}
    this.mute = false // If received ABORT chunk

    this.on('data', this.onData.bind(this))
    this.on('sack', this.onSack.bind(this))
    this.on('init', this.onInit.bind(this))
    this.on('init_ack', this.onInitAck.bind(this))
    this.on('heartbeat', this.onHeartbeat.bind(this))
    this.on('heartbeat_ack', this.onHeartbeatAck.bind(this))
    this.on('cookie_echo', this.onCookieEcho.bind(this))
    this.on('cookie_ack', this.onCookieAck.bind(this))
    this.on('shutdown', this.onShutdown.bind(this))
    this.on('shutdown_ack', this.onShutdownAck.bind(this))
    this.on('shutdown_complete', this.onShutdownComplete.bind(this))
    this.on('error', this.onError.bind(this))
    this.on('abort', this.onAbort.bind(this))

    this.on('icmp', this.onICMP.bind(this))
  }

  acceptRemote(chunk) {
    if (!chunk) {
      throw new Error('peer init chunk not provided')
    }
    this._updatePeer(chunk)
    /*
      Todo
     A COOKIE ACK MAY be sent to an UNCONFIRMED address,
     but it MUST be bundled with a HEARTBEAT including a nonce.
     An implementation that does NOT support bundling
     MUST NOT send a COOKIE ACK to an UNCONFIRMED address.
     2)  For the receiver of the COOKIE ECHO,
     the only CONFIRMED address is the one to which the INIT-ACK was sent.
    */
    this._up()
    this._sendChunk('cookie_ack', {})
  }

  onInit(chunk, src, dst, header) {
    this.debugger.warn(
      'rfc4960 "5.2.2.  Unexpected INIT ...',
      this.state,
      chunk, src, dst, header
    )
  }

  onCookieEcho(chunk, src, dst, header) {
    this.debugger.warn(
      'Handle a COOKIE ECHO when a TCB Exists',
      this.state,
      chunk
    )
    const cookieData = this.endpoint.validateCookie(chunk.cookie, header)
    let initChunk
    if (cookieData) {
      this.debugger.trace('cookie is valid')
      initChunk = Chunk.fromBuffer(cookieData.init)
    }
    this.debugger.debug('association my_tag %d peer_tag %d, cookie my_tag %d peer_tag %d',
      this.my_tag, this.peer_tag, cookieData.my_tag, initChunk.initiate_tag)
    let action = ''
    if (this.my_tag === cookieData.my_tag) {
      // B or D
      if (this.peer_tag === initChunk.initiate_tag) {
        action = 'D'
      } else {
        action = 'B'
      }
    } else if (this.peer_tag === initChunk.initiate_tag) {
      // Todo tmp, implement tie-tags
      const tieTagsUnknown = true
      if (tieTagsUnknown) {
        action = 'C'
      }
    } else {
      // Todo tmp, implement tie-tags
      const tieTagsMatch = true
      if (tieTagsMatch) {
        action = 'A'
      }
    }
    this.debugger.warn('action', action)
    switch (action) {
      case 'A':
        /*
        Todo tie-tags
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
        if (this.state === 'SHUTDOWN-ACK-SENT') {
          this._sendChunk('shutdown_ack', {}, src, () => {
            this.debugger.info('sent shutdown_ack')
          })
          return
        }
        // Todo
        this.debugger.warn('association restart is not implemented and was not tested!')
        this.emit('RESTART')
        break
      case 'B':
        /*
        Todo init collision
        B) In this case, both sides may be attempting to start an association
        at about the same time, but the peer endpoint started its INIT
        after responding to the local endpoint's INIT.  Thus, it may have
        picked a new Verification Tag, not being aware of the previous tag
        it had sent this endpoint.  The endpoint should stay in or enter
        the ESTABLISHED state, but it MUST update its peer's Verification
        Tag from the State Cookie, stop any init or cookie timers that may
        be running, and send a COOKIE ACK.
        */
        this.peer_tag = initChunk.initiate_tag
        // Todo stop init & cookie timers
        this._sendChunk('cookie_ack')
        break
      case 'C':
        /*
        C) In this case, the local endpoint's cookie has arrived late.
        Before it arrived, the local endpoint sent an INIT and received an
        INIT ACK and finally sent a COOKIE ECHO with the peer's same tag
        but a new tag of its own.  The cookie should be silently
        discarded.  The endpoint SHOULD NOT change states and should leave
        any timers running.
        */
        break
      case 'D':
        /*
        D) When both local and remote tags match, the endpoint should enter
        the ESTABLISHED state, if it is in the COOKIE-ECHOED state.  It
        should stop any cookie timer that may be running and send a COOKIE ACK.
        */
        if (this.state === 'COOKIE-ECHOED') {
          this.state = 'ESTABLISHED'
        }
        // Todo should be already running, state also be ESTABLISHED
        // this._enableHeartbeat()
        // todo stop cookie timer
        this._sendChunk('cookie_ack')
        break
      default:
      /*
      Note: For any case not shown in Table 2,
       the cookie should be silently discarded
      */
    }
  }

  onICMP(packet, code) {
    this.debugger.warn('< ICMP code %d', code)
    if (packet.v_tag && packet.v_tag !== this.peer_tag) {
      return
    }
    if (code === 4) {
      if (packet.v_tag === 0 && packet.chunks.length === 1) {
        const chunk = packet.chunks[0]
        if (chunk.chunkType === 'init' && chunk.initiate_tag === this.my_tag) {
          this.debugger.warn('< ICMP fragmentation needed')
          // Todo process this information as defined for PATH MTU discovery
        }
      }
    } else if (code === 2) {
      this.debugger.warn('< ICMP protocol unreachable')
      this.emit('COMMUNICATION LOST')
      this._destroy()
    }
  }

  onData(chunk, source) {
    this.countRcv++
    this.debugger.debug('< DATA %d, total: %d', chunk.tsn, this.countRcv)
    if (
      !(
        this.state === 'ESTABLISHED' ||
        this.state === 'SHUTDOWN-PENDING' ||
        this.state === 'SHUTDOWN-SENT'
      )
    ) {
      return
    }
    if (!chunk.user_data || !chunk.user_data.length > 0) {
      this.debugger.warn('< received empty DATA chunk %o', chunk)
      this._abort(
        {
          error_causes: [{cause: 'NO_USER_DATA', tsn: chunk.tsn}]
        },
        source
      )
      return
    }
    this.debugger.debug(
      '< DATA chunk %d %o, last %d, user data %d bytes',
      chunk.tsn,
      chunk.flags,
      this.peer_last_tsn.number,
      chunk.user_data.length
    )
    const TSN = new SN(chunk.tsn)
    let isDuplicate = false
    let zeroRwndDrop = false
    if (this.my_rwnd <= 0 && TSN.gt(this.peer_max_tsn)) {
      /*
         When the receiver's advertised window is 0, the receiver MUST drop
         any new incoming DATA chunk with a TSN larger than the largest TSN
         received so far.

         If the new incoming DATA chunk holds a TSN value
         less than the largest TSN received so far, then the receiver SHOULD
         drop the largest TSN held for reordering and accept the new incoming
         DATA chunk.
         */
      this.debugger.warn('rwnd is 0, drop tsn %d', chunk.tsn)
      zeroRwndDrop = true
    } else {
      const isLast = TSN.gt(this.peer_max_tsn)
      if (isLast) {
        this.peer_max_tsn = TSN
      }
      const offset = TSN.delta(this.peer_min_tsn)
      if (offset <= 0 || this.mapping_array[offset - 1]) {
        this.debugger.trace(
          'duplicate tsn %d, peer_min_tsn %d',
          chunk.tsn,
          this.peer_min_tsn.number
        )
        isDuplicate = true
        if (this.duplicates.length < MAX_DUPLICATES_LENGTH) {
          this.duplicates.push(chunk.tsn)
        }
      } else {
        this.debugger.trace(
          'tsn offset for %d from peer_min_tsn %d is %d',
          chunk.tsn,
          this.peer_min_tsn.number,
          offset
        )
        this.mapping_array[offset - 1] = chunk
        this.my_rwnd -= chunk.user_data.length
        this.debugger.trace('reduce my_rwnd to %d', this.my_rwnd)
        if (isLast && !chunk.flags.E) {
          // Don't scan yet
        } else {
          this._scan(offset)
        }
        if (TSN.gt(this.peer_last_tsn)) {
          this._updateCumulative()
        }
        if (chunk.dataPacket) {
          this.packetsSinceLastSack++
        }
      }
    }
    const haveGaps = this.peer_last_tsn.lt(this.peer_max_tsn)
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
      this.debugger.trace('we are in the SHUTDOWN-SENT state - repeat SHUTDOWN')
      this._sendChunk('shutdown', {
        c_tsn_ack: this.peer_last_tsn.getNumber()
      })
      if (!(haveGaps || isDuplicate)) {
        this.debugger.trace('no gaps and not a duplicate')
        return
      }
    }
    if (
      this.packetsSinceLastSack >= this.sack_freq ||
      !this.everSentSack ||
      haveGaps ||
      isDuplicate ||
      zeroRwndDrop
    ) {
      // For all such we do sack immediately
      this.debugger.trace('SACK immediately')
      this.sacks++
      // Todo
      // postponed send may result in sack being placed after data chunk
      // this results in protocol violation -
      // 'DATA chunk followed by chunk of type 03'
      // setTimeout(() => {
      this._sack()
      // }, 0)
    } else if (this._sackTimeout) {
      this.debugger.trace('SACK timeout already set')
    } else {
      this.debugger.trace('SACK timeout set', this.sack_timeout)
      this._sackTimeout = setTimeout(() => {
        this.debugger.trace('SACK timeout expired', this.sack_timeout)
        this._sack()
      }, this.sack_timeout)
    }
  }

  onSack(chunk) {
    this.debugger.trace('< sack c_tsn %d, peer_rwnd %d', chunk.c_tsn_ack, chunk.a_rwnd)
    /*
      A SACK MUST be processed in ESTABLISHED, SHUTDOWN-PENDING, and
      SHUTDOWN-RECEIVED.  An incoming SACK MAY be processed in COOKIE-
      ECHOED.  A SACK in the CLOSED state is out of the blue and SHOULD be
      processed according to the rules in Section 8.4.  A SACK chunk
      received in any other state SHOULD be discarded.
      */
    if (
      !(
        this.state === 'ESTABLISHED' ||
        this.state === 'SHUTDOWN-PENDING' ||
        this.state === 'SHUTDOWN-RECEIVED' ||
        this.state === 'COOKIE-ECHOED'
      )
    ) {
      return
    }

    // This.debugger.warn('< sack %O', chunk)
    this.peer_rwnd = chunk.a_rwnd

    if (this.drain_callback && this.drain()) {
      this.debugger.debug('drain callback c_tsn %d, peer_rwnd %d', chunk.c_tsn_ack, chunk.a_rwnd)
      this.drain_callback()
      delete this.drain_callback
    }

    const cTSN = new SN(chunk.c_tsn_ack)
    const ackAdvanced = this.c_tsn_ack ? cTSN.gt(this.c_tsn_ack) : true
    this.c_tsn_ack = cTSN.copy()

    if (this.fastRecovery && cTSN.ge(this.fastRecoveryExitPoint)) {
      this.fastRecovery = false
      this.fastRecoveryExitPoint = null
    }
    const flightsize = this.flightsize
    for (const tsn in this.sent) {
      const TSN = new SN(tsn)
      if (TSN.le(this.c_tsn_ack)) {
        this.debugger.trace('acknowledge tsn %d', tsn)
        this._acknowledge(TSN)
      }
    }
    if (
      chunk.sack_info &&
      chunk.sack_info.gap_blocks &&
      chunk.sack_info.gap_blocks.length > 0
    ) {
      const gapBlocks = chunk.sack_info.gap_blocks
      this.debugger.trace('< gap blocks ', chunk.c_tsn_ack, gapBlocks)
      /*
       Whenever an endpoint receives a SACK that indicates that some TSNs
       are missing, it SHOULD wait for two further miss indications (via
       subsequent SACKs for a total of three missing reports) on the same
       TSNs before taking action with regard to Fast Retransmit.
       */

      const absent = []
      gapBlocks.forEach((block, idx) => {
        // Todo rewrite with SN api
        absent.push({
          start: new SN(idx ?
            chunk.c_tsn_ack + gapBlocks[idx - 1].finish + 1 :
            chunk.c_tsn_ack + 1
          ),
          finish: new SN(chunk.c_tsn_ack + block.start - 1)
        })
        for (
          let t = this.c_tsn_ack.copy().inc(block.start);
          t.le(this.c_tsn_ack.copy().inc(block.finish));
          t.inc(1)
        ) {
          if (this.sent[t.getNumber()]) {
            this._acknowledge(t)
          }
        }
      })
      // 7.2.4.  Fast Retransmit on Gap Reports
      /*
       Whenever an endpoint receives a SACK that indicates that some TSNs
       are missing, it SHOULD wait for two further miss indications (via
       subsequent SACKs for a total of three missing reports) on the same
       TSNs before taking action with regard to Fast Retransmit.
       */
      let doFastRetransmit = false
      absent.forEach(block => {
        for (let TSN = block.start.copy(); TSN.le(block.finish); TSN.inc(1)) {
          const tsn = TSN.getNumber()
          if (this.sent[tsn]) {
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
            this.debugger.trace(
              'fast retransmit %d ? HTNA %d, fast recovery %s, ack advanced %s',
              tsn,
              this.HTNA.number,
              this.fastRecovery,
              ackAdvanced
            )
            if (TSN.lt(this.HTNA) || (this.fastRecovery && ackAdvanced)) {
              this.sent[tsn].losses++
              this.debugger.trace(
                'increase miss indications for %d to %d',
                tsn,
                this.sent[tsn].losses
              )
              if (this.sent[tsn].losses >= 3) {
                /*
             Mark the DATA chunk(s) with three miss indications for
             retransmission.
             A straightforward implementation of the above keeps a counter for
             each TSN hole reported by a SACK.  The counter increments for each
             consecutive SACK reporting the TSN hole.  After reaching 3 and
             starting the Fast-Retransmit procedure, the counter resets to 0.
                */
                this.sent[tsn].losses = 0
                this.sent[tsn].fastRetransmit = true
                doFastRetransmit = true
              }
            }
          }
        }
      })
      if (doFastRetransmit) {
        this._fastRetransmit()
      }
      /*
       Whenever a SACK is received missing a TSN that was previously
       acknowledged via a Gap Ack Block, start the T3-rtx for the
       destination address to which the DATA chunk was originally
       transmitted if it is not already running.
       */
    } else if (this.my_next_tsn.eq(this.c_tsn_ack.copy().inc(1))) {
      /*
       Whenever all outstanding data sent to an address have been
       acknowledged, turn off the T3-rtx timer of that address.
       */
      this.flightsize = 0
      this.debugger.trace('all outstanding data has been acknowledged')
      this._stopT3()
      if (this.state === 'SHUTDOWN-PENDING') {
        this._shutdown()
        return
      }
    }
    if (
      chunk.sack_info &&
      chunk.sack_info.duplicate_tsn &&
      chunk.sack_info.duplicate_tsn.length > 0
    ) {
      this.debugger.trace(
        'peer indicates duplicates %o',
        chunk.sack_info.duplicate_tsn
      )
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
      if (
        this.cwnd <= this.ssthresh &&
        this.cwnd <= this.flightsize &&
        !this.fastRecovery
      ) {
        const totalAcknowledgedSize = flightsize - this.flightsize
        const cwndIncrease = Math.min(totalAcknowledgedSize, this.PMTU)
        this.cwnd += cwndIncrease
        this.debugger.trace('increase cwnd by %d to %d, ssthresh %d',
          cwndIncrease, this.cwnd, this.ssthresh)
      }
      /*
       Whenever a SACK is received that acknowledges the DATA chunk
       with the earliest outstanding TSN for that address, restart the
       T3-rtx timer for that address with its current RTO (if there is
       still outstanding data on that address).
       */
      this.debugger.trace('c_tsn_ack advanced to %d', this.c_tsn_ack.number)
      this._restartT3()
    }
    if (this.flightsize > 0 && this.flightsize < this.cwnd) {
      this.debugger.trace('flightsize %d < cwnd %d', this.flightsize, this.cwnd)
      this._retransmit()
    }
  }

  onInitAck(chunk, source) {
    if (this.state === 'COOKIE-WAIT') {
      this.debugger.debug('< init_ack cookie', chunk.state_cookie)
      clearTimeout(this.T1)
      if (chunk.inbound_streams === 0) {
        // Receiver of an INIT ACK with the MIS value set to 0
        // SHOULD destroy the association discarding its TCB
        this._abort(
          {
            error_causes: [{cause: 'INVALID_MANDATORY_PARAMETER'}]
          },
          source
        )
        return
      }
      this._updatePeer(chunk)
      this._sendChunk(
        'cookie_echo',
        {cookie: chunk.state_cookie},
        source,
        () => {
          this.debugger.debug('sent cookie_echo', chunk.state_cookie)
        }
      )
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
        this._sendChunk(
          'error',
          {
            error_causes: [
              {
                cause: 'UNRECONGNIZED_PARAMETERS',
                unrecognized_parameters: Buffer.concat(chunk.errors)
              }
            ]
          },
          source
        )
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
      this.debugger.warn('Unexpected INIT ACK')
    }
  }

  onHeartbeat(chunk, source) {
    /*
      A receiver of a HEARTBEAT MUST respond to a
      HEARTBEAT with a HEARTBEAT-ACK after entering the COOKIE-ECHOED state
      (INIT sender) or the ESTABLISHED state (INIT receiver), up until
      reaching the SHUTDOWN-SENT state (SHUTDOWN sender) or the SHUTDOWN-
      ACK-SENT state (SHUTDOWN receiver). todo
     */
    this.debugger.trace(
      '< HEARTBEAT',
      chunk.heartbeat_info.length,
      chunk.heartbeat_info
    )
    this._sendChunk(
      'heartbeat_ack',
      {heartbeat_info: chunk.heartbeat_info},
      source
    )
  }

  onHeartbeatAck(chunk) {
    this.debugger.trace(
      '< HEARTBEAT ACK',
      chunk.heartbeat_info.length,
      chunk.heartbeat_info
    )
    /*
     Upon receipt of the HEARTBEAT ACK, a verification is made that the
     nonce included in the HEARTBEAT parameter is the one sent to the
     address indicated inside the HEARTBEAT parameter.  When this match
     occurs, the address that the original HEARTBEAT was sent to is now
     considered CONFIRMED and available for normal data transfer.
    */
    const nonce = chunk.heartbeat_info.readUInt32BE(0)
    if (this.nonces[nonce]) {
      const address = ip.toString(chunk.heartbeat_info, 8, 4)
      this.debugger.trace('address confirmed alive', address)
    }
    delete this.nonces[nonce]
  }

  onCookieAck() {
    this.debugger.debug('< COOKIE ACK in state %s', this.state)
    if (this.state === 'COOKIE-ECHOED') {
      this._up()
    }
  }

  onShutdown(chunk, source) {
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
    this.debugger.info('< SHUTDOWN')
    this._down()
    // Todo check c_tsn_ack
    /*
     cause: 'PROTOCOL_VIOLATION',
     additional_information:
     'The cumulative tsn ack beyond the max tsn currently sent:...'

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
      this.debugger.info('sent shutdown_ack')
    })
  }

  onShutdownAck(chunk, source) {
    /*
     Upon the receipt of the SHUTDOWN ACK, the SHUTDOWN sender shall stop
     the T2-shutdown timer, send a SHUTDOWN COMPLETE chunk to its peer,
     and remove all record of the association.
     */
    this.debugger.info('< SHUTDOWN ACK in state %s', this.state)
    this.state = 'CLOSED'
    this.debugger.info('> sending SHUTDOWN COMPLETE')
    this._sendChunk('shutdown_complete', {}, source, () => {
      this.debugger.trace('sent SHUTDOWN COMPLETE')
      this.emit('SHUTDOWN COMPLETE')
      this._destroy()
    })
  }

  onShutdownComplete() {
    /*
     Upon reception of the SHUTDOWN COMPLETE chunk, the endpoint will
     verify that it is in the SHUTDOWN-ACK-SENT state; if it is not, the
     chunk should be discarded.  If the endpoint is in the SHUTDOWN-ACK-
     SENT state, the endpoint should stop the T2-shutdown timer and remove
     all knowledge of the association (and thus the association enters the
     CLOSED state).
     */
    if (this.state === 'SHUTDOWN-ACK-SENT') {
      this.debugger.info('< SHUTDOWN COMPLETE')
      this.emit('SHUTDOWN COMPLETE')
      this._destroy()
    }
  }

  onError(chunk) {
    this.debugger.warn('< ERROR', chunk)
    if (
      chunk.error_causes.some(
        item => item.cause === 'STALE_COOKIE_ERROR'
      )
    ) {
      // TODO: 5.2.6.  Handle Stale COOKIE Error
    }
    this.emit('COMMUNICATION ERROR', chunk.error_causes)
  }

  onAbort(chunk) {
    this.debugger.info('< ABORT, connection closed')
    if (chunk.error_causes) {
      this.debugger.warn('< ABORT has error causes', chunk.error_causes)
    }
    this._down()
    if (this.queue.length > 0) {
      this.debugger.trace('abandon sending of chunks', this.queue.length)
    }
    this.queue = []
    this.emit('COMMUNICATION LOST', 'abort', chunk.error_causes)
    this._destroy()
  }

  init() {
    const initParams = {
      initiate_tag: this.my_tag,
      a_rwnd: defs.NET_SCTP.RWND,
      outbound_streams: this.OS,
      inbound_streams: this.MIS,
      initial_tsn: this.my_next_tsn.getNumber()
    }

    if (this.endpoint.localAddress) {
      initParams.ipv4_address = this.endpoint.localAddress
    }
    this.debugger.info('INIT params', initParams)

    let counter = 0
    this.RTI = this.rto_initial
    const init = () => {
      if (counter >= defs.NET_SCTP.max_init_retransmits) {
        // Fail
      } else {
        if (counter) {
          // Not from RFC, but from lk-sctp
          this.RTI *= 2
          if (this.RTI > this.rto_max) {
            this.RTI = this.rto_max
          }
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
    const chunk = new Chunk(chunkType, options)
    this.debugger.debug('> send chunk', chunkType)
    this.debugger.trace('> %O', chunk)
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
    if (
      chunkType === 'data' ||
      chunkType === 'sack' ||
      chunkType === 'heartbeat_ack'
    ) {
      // RFC allows to bundle other control chunks,
      // but this gives almost no benefits
      this.debugger.trace('> bundle-send', chunkType, options)
      chunk.callback = callback
      if (chunkType === 'data') {
        // Do not encode here because we'll add tsn later, during bundling
        chunk.size = chunk.user_data.length + 16
      } else {
        chunk.buffer = chunk.toBuffer()
        chunk.size = chunk.buffer.length
      }
      this.queue.push(chunk)
      this.bundling++
      setTimeout(() => {
        this._bundle()
      }, 0)
    } else {
      // No bundle
      // setTimeout(() => {
      // use nextTick to be in order with bundled chunks
      const buffer = chunk.toBuffer()
      this.debugger.trace('> no-bundle send', chunkType)
      this._sendPacket([buffer], destination, [callback])
      // }, 0)
    }
  }

  _scan() {
    const max = this.peer_max_tsn.delta(this.peer_min_tsn) - 1
    let res = null
    this.debugger.trace(
      'start tsn scan %d/%d in array of %d',
      this.peer_min_tsn.number,
      max,
      this.mapping_array.length
    )
    for (let i = 0; i <= max; i++) {
      const chunk = this.mapping_array[i]
      if (typeof chunk === 'object') {
        if (chunk.flags.B) {
          // Begin new probable reassemble
          if (
            chunk.flags.U ||
            new SN(chunk.stream_sn).eq(this.peer_ssn[chunk.stream_id])
          ) {
            if (!chunk.flags.E) {
              this.debugger.trace(
                'begin reassembling [U %s / SID %d / SSN %d]',
                chunk.flags.U,
                chunk.stream_id,
                chunk.stream_sn
              )
            }
            res = {
              stream: chunk.stream_id,
              ssn: chunk.stream_sn,
              data: [chunk.user_data],
              idx: [i]
            }
          } else {
            this.debugger.trace(
              'postpone reassembling SID / SSN / peer_ssn',
              chunk.stream_id,
              chunk.stream_sn,
              this.peer_ssn[chunk.stream_id].number
            )
          }
        }
        if (
          res &&
          (chunk.flags.B ||
            (res.stream === chunk.stream_id && res.ssn === chunk.stream_sn))
        ) {
          if (!chunk.flags.B) {
            res.data.push(chunk.user_data)
            res.idx.push(i)
          }
          if (chunk.flags.E) {
            if (!chunk.flags.U) {
              this.peer_ssn[res.stream].inc(1)
            }
            this.debugger.trace(
              'deliver tracking index %d SID %d peer_ssn %d',
              res.idx,
              res.stream,
              this.peer_ssn[res.stream].number
            )
            this._deliver(Buffer.concat(res.data), res.stream)
            res.idx.forEach(i => {
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
    this.debugger.trace(
      'end TSN scan, peer_min_tsn %d',
      this.peer_min_tsn.number
    )
  }

  _updateTrack() {
    let offsetTracking
    const max = this.peer_max_tsn.delta(this.peer_min_tsn)
    for (let i = 0; i < max; i++) {
      if (this.mapping_array[i] === true) {
        offsetTracking = i + 1
      } else {
        break
      }
    }
    if (offsetTracking) {
      this.peer_min_tsn.inc(offsetTracking)
      this.mapping_array.splice(0, offsetTracking)
      this.debugger.trace(
        'updated mapping array peer_min_tsn %d peer_max_tsn %d',
        this.peer_min_tsn.number,
        this.peer_max_tsn.number
      )
    }
  }

  _updateCumulative() {
    const max = this.peer_max_tsn.delta(this.peer_min_tsn)
    this.peer_last_tsn = this.peer_min_tsn.copy()
    this.debugger.trace('update peer_last_tsn %d', this.peer_last_tsn.number)
    let offsetCumulative
    for (let i = 0; i < max; i++) {
      if (this.mapping_array[i]) {
        offsetCumulative = i + 1
      } else {
        break
      }
    }
    if (offsetCumulative) {
      this.peer_last_tsn.inc(offsetCumulative)
      this.debugger.trace('update peer_last_tsn %d', this.peer_last_tsn.number)
    }
  }

  _sack() {
    if (this._sackTimeout) {
      clearTimeout(this._sackTimeout)
      delete this._sackTimeout
    }
    this.sacks--
    if (this.sacks > 0) {
      // Wait for last sack request in idle cycle
      this.debugger.trace('grouping SACKs, wait %d more...', this.sacks)
      return
    }
    const gapBlocks = []
    const max = this.peer_max_tsn.delta(this.peer_last_tsn)
    const offset = this.peer_last_tsn.delta(this.peer_min_tsn)
    let start
    let gap
    for (let i = 0; i <= max; i++) {
      const chunk = this.mapping_array[i + offset]
      if (chunk) {
        if (gap && !start) {
          start = i
        }
        // Gap = false
      } else {
        gap = true
        if (start) {
          gapBlocks.push({
            start: start + 1,
            finish: i
          })
          start = null
        }
      }
    }
    const sackOptions = {
      a_rwnd: this.my_rwnd > 0 ? this.my_rwnd : 0,
      c_tsn_ack: this.peer_last_tsn.getNumber()
    }
    if (gapBlocks || this.duplicates.length > 0) {
      sackOptions.sack_info = {
        gap_blocks: gapBlocks,
        duplicate_tsn: this.duplicates
      }
    }
    if (gapBlocks.length > 0) {
      this.debugger.warn(
        '< packet loss %d gap blocks %o',
        gapBlocks.length,
        gapBlocks
      )
    }
    this.debugger.trace('prepared SACK %O', sackOptions)
    this._sendChunk('sack', sackOptions)
    if (!this.everSentSack) {
      this.everSentSack = true
    }
    this.duplicates = []
    this.packetsSinceLastSack = 0
  }

  _acknowledge(TSN) {
    this.debugger.trace('acknowledge tsn %d, peer_rwnd %d', TSN.number, this.peer_rwnd)
    this.flightsize -= this.sent[TSN.getNumber()].size
    if (!this.HTNA || TSN.gt(this.HTNA)) {
      this.HTNA = TSN.copy()
    }
    delete this.sent[TSN.getNumber()]
    // RTO calculation
    if (this.rtoPending && this.rtoPending.tsn.eq(TSN)) {
      this._updateRTO(new Date() - this.rtoPending.sent)
      this.rtoPending = false
    }
  }

  _updateRTO(R) {
    if (this.SRTT) {
      const alpha = 1 / defs.NET_SCTP.rto_alpha_exp_divisor
      const beta = 1 / defs.NET_SCTP.rto_beta_exp_divisor
      this.RTTVAR = (1 - beta) * this.RTTVAR + beta * Math.abs(this.SRTT - R)
      this.RTTVAR = Math.max(this.RTTVAR, defs.NET_SCTP.G)
      this.SRTT = (1 - alpha) * this.SRTT + alpha * R
      this.RTO = this.SRTT + 4 * this.RTTVAR
    } else {
      this.SRTT = R
      this.RTTVAR = R / 2
      this.RTTVAR = Math.max(this.RTTVAR, defs.NET_SCTP.G)
      this.RTO = this.SRTT + 4 * this.RTTVAR
    }
    if (this.RTO < this.rto_min) {
      this.RTO = this.rto_min
    }
    if (this.RTO > this.rto_max) {
      this.RTO = this.rto_max
    }
    this.debugger.trace('new RTO %d', this.RTO)
  }

  _startT3() {
    if (this.T3) {
      this.debugger.trace('T3-rtx timer is already running')
      return
    }
    this.debugger.trace('start T3-rtx timer (RTO %d)', this.RTO)
    this.T3 = setTimeout(this._expireT3.bind(this), this.RTO)
  }

  _stopT3() {
    if (this.T3) {
      this.debugger.trace('stop T3-rtx timer')
      clearTimeout(this.T3)
      this.T3 = null
    }
  }

  _restartT3() {
    this.debugger.trace('restart T3 timer')
    this._stopT3()
    this._startT3()
  }

  _expireT3() {
    this.T3 = null
    this.debugger.trace('T3-rtx timer has expired')
    if (Object.keys(this.sent).length === 0) {
      this.debugger.warn('bug: there are no chunks in flight')
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
    this.debugger.trace(
      'adjustments on expire: cwnd %d / ssthresh %d / RTO %d',
      this.cwnd,
      this.ssthresh,
      this.RTO
    )
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
    const tsns = []
    for (const tsn in this.sent) {
      const chunk = this.sent[tsn]
      this.debugger.trace('retransmit tsn %d', chunk.tsn)
      if (bundledLength + chunk.user_data.length + 16 > this.PMTU) {
        /*
         Note: Any DATA chunks that were sent to the address for which the
         T3-rtx timer expired but did not fit in one MTU (rule E3 above)
         should be marked for retransmission and sent as soon as cwnd allows
         (normally, when a SACK arrives).
         */
        this.debugger.trace('retransmit tsn later %d', chunk.tsn)
        chunk.retransmit = true
      } else {
        bundledCount++
        bundledLength += chunk.user_data.length + 16
        tsns.push(chunk.tsn)
        this._sendChunk('data', chunk)
      }
    }
    this.debugger.trace(
      'retransmit %d chunks, %d bytes, %o',
      bundledLength,
      bundledCount,
      tsns
    )
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
    this.debugger.trace('check retransmits')
    for (const tsn in this.sent) {
      const chunk = this.sent[tsn]
      if (chunk.retransmit) {
        // Todo explain
        this.debugger.warn('more retransmit', chunk.tsn)
        this._sendChunk('data', chunk)
      }
    }
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
      this.partial_bytes_acked = 0 // Todo
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
      this.fastRecoveryExitPoint = this.my_next_tsn.prev()
      this.debugger.trace(
        'entered fast recovery mode, cwnd %d, ssthresh %d',
        this.cwnd,
        this.ssthresh
      )
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
    const tsns = []
    for (const tsn in this.sent) {
      const chunk = this.sent[tsn]
      if (chunk.fastRetransmit) {
        this.debugger.trace('fast retransmit tsn %d', chunk.tsn)
        if (bundledLength + chunk.user_data.length + 16 > this.PMTU) {
          return true
        }
        bundledCount++
        bundledLength += chunk.user_data.length + 16
        tsns.push(chunk.tsn)
        this._sendChunk('data', chunk)
      }
    }

    this.debugger.trace(
      'fast retransmit %d chunks, %d bytes, %o',
      bundledLength,
      bundledCount,
      tsns
    )
    /*
     4)  Restart the T3-rtx timer only if the last SACK acknowledged the
     lowest outstanding TSN number sent to that address, or the
     endpoint is retransmitting the first outstanding DATA chunk sent
     to that address.
     */
    // TODO: Restart the T3-rtx timer only if the last SACK acknowledged
    if (bundledCount > 0) {
      this._restartT3()
    }
  }

  _up() {
    /*
     HEARTBEAT sending MAY begin upon reaching the
     ESTABLISHED state and is discontinued after sending either SHUTDOWN
     or SHUTDOWN-ACK. todo
    */
    this.state = 'ESTABLISHED'
    this._enableHeartbeat()
    this.debugger.info('association established')
    this.emit('COMMUNICATION UP')
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
      for (const address in this.destinations) {
        const destination = this.destinations[address]
        const heartbeatInfo = crypto.randomBytes(12)
        const nonce = heartbeatInfo.readUInt32BE(0)
        this.nonces[nonce] = true
        ip.toBuffer(address, heartbeatInfo, 8)
        this.debugger.trace(
          '> heartbeat to %s, %d bytes',
          destination,
          heartbeatInfo.length,
          heartbeatInfo
        )
        this._sendChunk('heartbeat', {heartbeat_info: heartbeatInfo}, address)
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
    if (this.mute) {
      return
    }
    if (!this.endpoint) {
      return
    }
    this.endpoint._sendPacket(
      destination || this.remoteAddress,
      this.remotePort,
      this.peer_tag,
      buffers,
      () => {
        callbacks.forEach(cb => {
          // Callback for each chunk
          if (typeof cb === 'function') {
            cb()
          }
        })
      }
    )
  }

  _deliver(data, stream) {
    this.debugger.debug('< receive user data %d bytes', data.length)
    this.my_rwnd += data.length
    this.debugger.trace('new my_rwnd is %d', this.my_rwnd)
    if (this.listeners('DATA ARRIVE')) {
      this.debugger.trace('emit DATA ARRIVE')
      this.readBuffer.push(data)
      this.emit('DATA ARRIVE', stream)
    }
  }

  _bundle() {
    if (this.state === 'CLOSED') {
      return
    }
    if (this.queue.length === 0) {
      return
    }
    this.bundling--
    if (this.bundling > 0) {
      return
    }
    let callbacks = []
    let bundledChunks = []
    let bundledLength = 36 // 20 + 16
    const mtu = this.PMTU
    const emulateLoss = false
    let haveCookieEcho = false
    let haveData = false
    let tsns = []
    let sack
    let skip

    // Move last sack to the beginning of queue, ignore others
    const processedQueue = []
    this.queue.forEach(chunk => {
      if (chunk.chunkType === 'sack') {
        sack = chunk
      } else {
        processedQueue.push(chunk)
      }
    })
    if (sack) {
      processedQueue.unshift(sack)
    }

    this.debugger.trace('process bundle queue %O', processedQueue)
    processedQueue.forEach((chunk, index) => {
      let buffer
      if (chunk.size > mtu) {
        this.debugger.warn('chunk size %d > MTU %d', chunk.size, mtu)
        // Todo split chunks
        skip = true
      } else if (chunk.chunkType === 'data') {
        haveData = true
        /*
         Data transmission MUST only happen in the ESTABLISHED, SHUTDOWN-
         PENDING, and SHUTDOWN-RECEIVED states.  The only exception to this is
         that DATA chunks are allowed to be bundled with an outbound COOKIE
         ECHO chunk when in the COOKIE-WAIT state.
         */
        if (
          this.state === 'ESTABLISHED' ||
          this.state === 'SHUTDOWN-PENDING' ||
          this.state === 'SHUTDOWN-RECEIVED'
        ) {
          //  Allow
        } else if (this.state === 'COOKIE-WAIT' && haveCookieEcho) {
          // Allow
        } else {
          // TODO: force bundle
          this.debugger.warn(
            'data transmission MUST only happen ' +
            'in the ESTABLISHED, SHUTDOWN-PENDING, ' +
            'and SHUTDOWN-RECEIVED states'
          )
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
          // Not a retransmit
          chunk.tsn = this.my_next_tsn.getNumber()
          this.debugger.trace('last-minute set tsn to %d', chunk.tsn)
          this.my_next_tsn.inc(1)
        }
        if (!this.rtoPending) {
          this.rtoPending = {
            tsn: new SN(chunk.tsn),
            sent: new Date()
          }
        }
        buffer = chunk.toBuffer()
        tsns.push(chunk.tsn)
        chunk.losses = 0
        this.sent[chunk.tsn] = chunk
        this.flightsize += buffer.length
      } else {
        buffer = chunk.buffer
        delete chunk.buffer
        if (chunk.chunkType === 'cookie_echo') {
          haveCookieEcho = true
        }
      }

      if (!skip) {
        bundledChunks.push(buffer)
        bundledLength += buffer.length
        callbacks.push(chunk.callback)
        this.debugger.trace(
          'bundled chunk %s %d bytes, total %d',
          chunk.chunkType,
          buffer.length,
          bundledLength
        )
      }

      const finish = index === processedQueue.length - 1
      const full = bundledLength + chunk.size > mtu

      if (finish || full) {
        if (bundledChunks.length > 0) {
          this.debugger.trace(
            'send bundled chunks %d bytes, %d chunks',
            bundledLength,
            bundledChunks.length
          )
          if (emulateLoss) {
            this.debugger.warn('emulated loss of packet with tsns %o', tsns)
          } else {
            // Todo select destination here?
            this._sendPacket(bundledChunks, null, callbacks)
          }
          if (haveData) {
            this._startT3()
          }
          bundledChunks = []
          callbacks = []
          tsns = []
          bundledLength = 36 // 20 + 16
          haveCookieEcho = false
          haveData = false
        }
      }
    })
    this.queue = []
  }

  _shutdown(callback) {
    this._down()
    this._sendChunk(
      'shutdown',
      {c_tsn_ack: this.peer_last_tsn.getNumber()},
      null,
      () => {
        /*
       It shall then start the T2-shutdown timer and enter the SHUTDOWN-SENT
       state.  If the timer expires, the endpoint must resend the SHUTDOWN
       with the updated last sequential TSN received from its peer.
       The rules in Section 6.3 MUST be followed to determine the proper
       timer value for T2-shutdown.
       */
        // TODO: T2-shutdown timer
        this.state = 'SHUTDOWN-SENT'
        this.debugger.info('> sent SHUTDOWN')
        if (typeof callback === 'function') {
          callback()
        }
      }
    )
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
    this.debugger.trace('destroy association')
    this.state = 'CLOSED'
    clearTimeout(this.T1)
    clearTimeout(this.T3)
    clearTimeout(this.T5)
    // TODO: better destroy assoc first, then endpoint
    // todo delete association properly (dtls) when no addresses, only port
    if (this.endpoint) {
      for (const address in this.destinations) {
        const key = address + ':' + this.remotePort
        this.debugger.trace('destroy remote address %s', key)
        delete this.endpoint.associations_lookup[key]
      }
      const index = this.endpoint.associations.indexOf(this)
      this.endpoint.associations.splice(index, index + 1)

      delete this.endpoint
    }
  }

  SHUTDOWN(callback) {
    /*
     Format: SHUTDOWN(association id)
     -> result
     */

    this.debugger.trace('API SHUTDOWN in state %s', this.state)
    if (this.state !== 'ESTABLISHED') {
      this.debugger.trace('just destroy association')
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

    this.debugger.trace('API ABORT')
    this._down()
    // If the association is aborted on request of the upper layer,
    // a User-Initiated Abort error cause (see Section 3.3.10.12)
    // SHOULD be present in the ABORT chunk.
    const errorCause = {cause: 'USER_INITIATED_ABORT'}
    if (reason) {
      errorCause.abort_reason = reason
    }
    this._abort({error_causes: [errorCause]})
  }

  _abort(options, destination) {
    /*
    An abort of an association is abortive by definition in
    that any data pending on either end of the association is discarded
    and not delivered to the peer.  A shutdown of an association is
    considered a graceful close where all data in queue by either
    endpoint is delivered to the respective peers.

    9.1.  Abort of an Association

    When an endpoint decides to abort an existing association, it MUST
    send an ABORT chunk to its peer endpoint.  The sender MUST fill in
    the peer's Verification Tag in the outbound packet and MUST NOT
    bundle any DATA chunk with the ABORT.  If the association is aborted
    on request of the upper layer, a User-Initiated Abort error cause
    (see Section 3.3.10.12) SHOULD be present in the ABORT chunk.

    An endpoint MUST NOT respond to any received packet that contains an
    ABORT chunk (also see Section 8.4).

    An endpoint receiving an ABORT MUST apply the special Verification
    Tag check rules described in Section 8.5.1.

    After checking the Verification Tag, the receiving endpoint MUST
    remove the association from its record and SHOULD report the
    termination to its upper layer.  If a User-Initiated Abort error
    cause is present in the ABORT chunk, the Upper Layer Abort Reason
    SHOULD be made available to the upper layer.

    */
    this._sendChunk('abort', options, destination, () => {
      this.debugger.info('sent abort')
    })
    this._destroy()
  }

  SEND(buffer, options, callback) {
    /*
     Format: SEND(association id, buffer address, byte count [,context]
     [,stream id] [,life time] [,destination transport address]
     [,unordered flag] [,no-bundle flag] [,payload protocol-id] )
     -> result
     */
    this.debugger.debug('SEND %d bytes, %o', buffer.length, options)
    this.lastChunkSize = buffer.length
    this.send(buffer, options, error => {
      const drain = this.drain(buffer.length)
      if (drain || error) {
        this.debugger.debug('drain is %s (flightsize %d cwnd %d peer_rwnd %d)',
          drain, this.flightsize, this.cwnd, this.peer_rwnd)
        if (typeof callback === 'function') {
          callback(error)
          callback = null
          this.drain_callback = null
        }
      } else {
        this.drain_callback = callback
      }
    })
    return this.drain()
  }

  drain() {
    const drain = (this.flightsize < this.cwnd) &&
      (this.lastChunkSize + this.flightsize < this.peer_rwnd)
    this.debugger.trace('check drain for chunk size %d: %s (flightsize %d cwnd %d peer_rwnd %d)',
      this.lastChunkSize, drain, this.flightsize, this.cwnd, this.peer_rwnd)
    return drain
  }

  send(buffer, options, callback) {
    // TODO: 6.1.  Transmission of DATA Chunks

    this.debugger.trace('send %d bytes, %o', buffer.length, options)
    let error = false
    if (
      this.state === 'SHUTDOWN-PENDING' ||
      this.state === 'SHUTDOWN-RECEIVED'
    ) {
      /*
       Upon receipt of the SHUTDOWN primitive from its upper layer,
       the endpoint enters the SHUTDOWN-PENDING state ...
       accepts no new data from its upper layer

       Upon reception of the SHUTDOWN,
       the peer endpoint shall enter the SHUTDOWN-RECEIVED state,
        stop accepting new data from its SCTP user
       */
      error = 'not accepting new data in SHUTDOWN state'
    } else if (buffer.length >= this.peer_rwnd) {
      /*
       At any given time, the data sender MUST NOT transmit new data to
       any destination transport address if its peer's rwnd indicates
       that the peer has no buffer space (i.e., rwnd is 0; see Section
       6.2.1).
       */
      error = 'peer has no buffer space (rwnd) for new packet ' + this.peer_rwnd
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
    // todo !! zero window probe & silly window syndrome (SWS) !!
    // todo also look at cwnd calc

    if (error) {
      this.debugger.warn('SEND error', error)
      error = new Error(error)
      callback(error)
      return
    }
    /*
     Before an endpoint transmits a DATA chunk, if any received DATA
     chunks have not been acknowledged (e.g., due to delayed ack), the
     sender should create a SACK and bundle it with the outbound DATA
     chunk, as long as the size of the final SCTP packet does not exceed
     the current MTU.  See Section 6.2.
     */
    if (this._sackTimeout) {
      this.debugger.trace('cancel SACK timer and do it now')
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
    if (this.flightsize + defs.NET_SCTP.max_burst * this.PMTU < this.cwnd) {
      // TODO: compare to another adjustments
      this.cwnd = this.flightsize + defs.NET_SCTP.max_burst * this.PMTU
      this.debugger.trace('adjust cwnd to flightsize + Max.Burst*MTU = %d', this.cwnd)
    }
    let chunk
    const stream = options.stream || 0
    if (stream < 0 || stream > this.OS) {
      this.debugger.warn('wrong stream id %d', stream)
      return
    }
    if (!this.SSN[stream]) {
      this.SSN[stream] = new SN(0, 16)
    }
    const mtu = this.PMTU - 52 // 16 + 16 + 20 headers
    if (buffer.length > mtu) {
      let offset = 0
      while (offset < buffer.length) {
        chunk = {
          flags: {
            E: buffer.length - offset <= mtu,
            B: offset === 0,
            U: options.unordered,
            I: 0
          },
          stream_id: stream,
          stream_sn: this.SSN[stream].getNumber(),
          payload_protocol_identifier: options.protocol,
          user_data: buffer.slice(offset, offset + mtu)
        }
        offset += mtu
        this._sendChunk('data', chunk, null, callback)
      }
    } else {
      chunk = {
        flags: {
          E: 1,
          B: 1,
          U: options.unordered,
          I: 0
        },
        stream_id: stream,
        stream_sn: this.SSN[stream].getNumber(),
        payload_protocol_identifier: options.protocol,
        user_data: buffer
      }
      this._sendChunk('data', chunk, null, callback)
    }
    this.SSN[stream].inc(1)
    this.debugger.trace('%d bytes sent, cwnd %d', buffer.length, this.cwnd)
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
    this.debugger.trace('API RECEIVE', this.readBuffer[0])
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
    this.peer_tag = chunk.initiate_tag
    this.peer_rwnd = chunk.a_rwnd
    this.ssthresh = chunk.a_rwnd
    this.peerInitialTSN = chunk.initial_tsn
    this.peer_last_tsn = new SN(this.peerInitialTSN).prev()
    this.peer_max_tsn = this.peer_last_tsn.copy()
    this.peer_min_tsn = this.peer_last_tsn.copy()
    if (chunk.ipv4_address) {
      chunk.ipv4_address.forEach(address => {
        this.debugger.debug('peer ipv4_address %s', address)
        if (!(address in this.destinations)) {
          this.destinations[address] = this.default_address_data
          const key = address + ':' + this.remotePort
          this.endpoint.associations_lookup[key] = this
        }
      })
    }
  }
}

module.exports = Association
