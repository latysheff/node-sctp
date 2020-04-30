const EventEmitter = require('events').EventEmitter
const debug = require('debug')('sctp:reasm')
const SN = require('./serial')

const MAX_DUPLICATES_LENGTH = 50

class Reassembly extends EventEmitter {
  constructor (options) {
    super()
    options = options || {}
    this.rwnd = options.rwnd
    this.mapping_array = []
    this.duplicates = []
    this.peer_ssn = []
    this._paused = {}
  }

  init (options) {
    options = options || {}
    this.initial_tsn = options.initial_tsn
    this.peer_c_tsn = new SN(this.initial_tsn).prev()
    this.peer_max_tsn = this.peer_c_tsn.copy()
    this.peer_min_tsn = this.peer_c_tsn.copy()
  }

  process (chunk) {
    if (chunk.chunkType !== 'data') {
      throw new Error('This is DATA chunk processing, not ' + chunk.chunkType)
    }
    debug('< process DATA chunk %d/%d stream [%d] %d bytes', chunk.tsn, chunk.ssn, chunk.stream_id,
      chunk.user_data.length
    )
    if (this._paused[chunk.stream_id]) {
      debug('< stream [%d] is paused', chunk.stream_id)
      return false
    }
    const TSN = new SN(chunk.tsn)
    const index = TSN.delta(this.peer_min_tsn) - 1
    if (index < 0 || this.mapping_array[index]) {
      debug('duplicate tsn %d, peer_min_tsn %d', chunk.tsn, this.peer_min_tsn.number)
      if (this.duplicates.length < MAX_DUPLICATES_LENGTH) {
        this.duplicates.push(chunk.tsn)
      }
      return false
    }

    if (this.rwnd <= 0) {
      /*
       When the receiver's advertised window is 0, the receiver MUST drop
       any new incoming DATA chunk with a TSN larger than the largest TSN
       received so far.  If the new incoming DATA chunk holds a TSN value
       less than the largest TSN received so far, then the receiver SHOULD
       drop the largest TSN held for reordering and accept the new incoming
       DATA chunk.  In either case, if such a DATA chunk is dropped, the
       receiver MUST immediately send back a SACK with the current receive
       window showing only DATA chunks received and accepted so far.  The
       dropped DATA chunk(s) MUST NOT be included in the SACK, as they were
       not accepted.  The receiver MUST also have an algorithm for
       advertising its receive window to avoid receiver silly window
       syndrome (SWS), as described in [RFC0813].  The algorithm can be
       similar to the one described in Section 4.2.3.3 of [RFC1122].
       */
      debug('rwnd is %d, drop chunk %d', this.rwnd, chunk.tsn)
      if (TSN.gt(this.peer_max_tsn)) {
        // MUST drop any new incoming DATA chunk
        return false
      }
      // SHOULD drop the largest TSN held for reordering and accept the new incoming DATA chunk
      let dropIndex
      for (let i = this.mapping_array.length - 1; i >= 0; i--) {
        if (typeof this.mapping_array[i] === 'object') {
          dropIndex = i
        }
      }
      this.rwnd += this.mapping_array[dropIndex].user_data.length
      this.mapping_array[dropIndex] = false
      // If the largest TSN held for reordering is the largest TSN received so far
      // then decrement peer_max_tsn
      // else largest TSN received so far is already delivered to the ULP
      if (dropIndex === this.mapping_array.length - 1) {
        this.peer_max_tsn--
      }
    }
    this.accept(chunk)
    return true
  }

  accept (chunk) {
    const TSN = new SN(chunk.tsn)
    // Adjust peer_max_tsn
    if (TSN.gt(this.peer_max_tsn)) {
      this.peer_max_tsn = TSN.copy()
    }
    const index = TSN.delta(this.peer_min_tsn) - 1
    // TODO before inserting check if it was empty => no scan
    this.mapping_array[index] = chunk
    this.rwnd -= chunk.user_data.length
    debug('reduce rwnd by %d to %d (%d/%d) %o', chunk.user_data.length, this.rwnd,
      chunk.tsn, chunk.ssn, chunk.flags)

    this.reassemble(chunk, TSN)
    this.cumulative(TSN)

    this.have_gaps = this.peer_c_tsn.lt(this.peer_max_tsn)
  }

  cumulative (TSN) {
    // Update cumulative TSN
    if (TSN.gt(this.peer_c_tsn)) {
      const max = this.peer_max_tsn.delta(this.peer_min_tsn)
      const offset = this.peer_c_tsn.delta(this.peer_min_tsn)
      let index = offset > 0 ? offset : 0
      while (this.mapping_array[index] && index <= max) {
        index++
      }
      const delta = index - offset
      if (delta > 0) {
        this.peer_c_tsn.inc(delta)
        debug('update peer_c_tsn +%d to %d', delta, this.peer_c_tsn.number)
      }
    }
  }

  reassemble (newChunk, TSN) {
    const streamId = newChunk.stream_id
    let ssn = newChunk.ssn
    if (this.peer_ssn[streamId] === undefined) {
      // Accept any start ssn here, but enforce 0 somewhere
      this.peer_ssn[streamId] = ssn
    }
    const ordered = !newChunk.flags.U
    if (ordered && (newChunk.ssn !== this.peer_ssn[streamId])) {
      debug('out-of-sequence ssn %d (wait %d), ignore', newChunk.ssn, this.peer_ssn[streamId])
      return
    }
    if (newChunk.tsn === this.peer_max_tsn.number && !newChunk.flags.E) {
      // Should wait for final fragment
      debug('%d/%d %o, wait for final fragment',
        newChunk.tsn,
        newChunk.ssn,
        newChunk.flags
      )
      return
    }
    const size = this.peer_max_tsn.delta(this.peer_min_tsn)
    const start = newChunk.flags.B ? TSN.delta(this.peer_min_tsn) - 1 : 0
    // Only for unordered we can short-cut scanning to new chunk's tsn
    const finish = (newChunk.flags.E && !ordered) ? TSN.delta(this.peer_min_tsn) : size
    let candidate = null
    debug('--> begin scan %d/%d stream [%d]: %d to %d, [%d - %d], in array of %d',
      newChunk.tsn,
      ssn,
      streamId,
      start,
      finish,
      this.peer_min_tsn.number,
      this.peer_max_tsn.number,
      this.mapping_array.length
    )
    let index
    for (index = start; index < finish; index++) {
      const chunk = this.mapping_array[index]
      if (typeof chunk === 'object' && chunk.stream_id === streamId && chunk.ssn === ssn) {
        debug('chunk %d/%d, chunk flags %o',
          chunk.tsn, chunk.ssn, chunk.flags)
        if (chunk.flags.B) {
          // Probable candidate for reassembly
          debug('flag B - begin reassemble ssn %d on stream %d',
            chunk.ssn,
            chunk.stream_id
          )
          candidate = {
            data: [chunk.user_data],
            idx: [index]
          }
          debug('candidate %o', candidate)
        }
        if (candidate) {
          if (!chunk.flags.B) {
            // Add data if not first fragment
            candidate.data.push(chunk.user_data)
            candidate.idx.push(index)
          }
          if (chunk.flags.E) {
            debug('got full data chunk')
            if (ordered) {
              this.peer_ssn[streamId]++
              debug('new stream sequence number %d', this.peer_ssn[streamId])
              // Serial arithmetic 16 bit
              if (this.peer_ssn[streamId] > 0xFFFF) {
                this.peer_ssn[streamId] = 0
              }
            }

            debug('deliver chunks %o from mapping array on stream %d', candidate.idx, streamId)
            const data = Buffer.concat(candidate.data)
            this.emit('data', data, streamId, chunk.ppid)
            this.rwnd += data.length
            debug('new rwnd is %d', this.rwnd)

            candidate.idx.forEach(index => {
              this.mapping_array[index] = true
            })
            if (ordered) {
              // Other chunks can also be ready for reassembly
              // reset candidate, shift expected ssn and scan for those possible chunks
              candidate = null
              ssn++
              ssn %= 0x10000
              debug('ordered delivery - continue to ssn %d', ssn)
            } else {
              debug('unordered delivery - finish scan')
              break
            }
          }
        }
      } else if (candidate) {
        // If there is a gap in ordered chunk, we should exit, can not continue to next chunk
        // but if unordered, there can be another B fragment, we don't know
        if (ordered) {
          debug('have candidate but found the gap in ordered delivery - exit scan')
          break
        } else {
          debug('unordered sequence broken, scan for another one')
          candidate = null
        }
      }
    }
    // Shrink mapping array
    let offset
    for (let index = 0; index < size; index++) {
      if (this.mapping_array[index] === true) {
        offset = index + 1
      } else {
        break
      }
    }
    if (offset) {
      this.peer_min_tsn.inc(offset)
      this.mapping_array.splice(0, offset)
      debug('shift mapping array %d chunks, [%d - %d]', offset,
        this.peer_min_tsn.number,
        this.peer_max_tsn.number
      )
    }
    debug('--> end scan %d/->%d stream [%d]: %d to %d, ->[%d - %d] (%d)',
      newChunk.tsn,
      ssn,
      streamId,
      start,
      index,
      this.peer_min_tsn.number,
      this.peer_max_tsn.number,
      this.mapping_array.length
    )
  }

  sackInfo () {
    const gapBlocks = []
    const max = this.peer_max_tsn.delta(this.peer_c_tsn)
    if (max > 0xFFFF) {
      throw new Error('bug? gap interval too big')
    }
    const offset = this.peer_c_tsn.delta(this.peer_min_tsn)
    let start
    let gap
    debug('scan mapping for gaps, offset %d, max %d', offset, max)
    for (let index = 0; index <= max; index++) {
      const chunk = this.mapping_array[index + offset]
      if (chunk) {
        if (gap && !start) {
          start = index
        }
      } else {
        gap = true
        if (start) {
          gapBlocks.push({
            start: start + 1,
            finish: index
          })
          start = null // TODO
        }
      }
    }
    const sackOptions = {
      a_rwnd: this.rwnd > 0 ? this.rwnd : 0,
      c_tsn_ack: this.peer_c_tsn.number
    }
    if (gapBlocks.length > 0 || this.duplicates.length > 0) {
      sackOptions.sack_info = {
        gap_blocks: gapBlocks,
        duplicate_tsn: this.duplicates
      }
    }
    if (gapBlocks.length > 0) {
      debug('< packet loss %d gap blocks %o,%O', gapBlocks.length, gapBlocks, sackOptions)
    }
    this.duplicates = []
    return sackOptions
  }

  pause (streamId) {
    this._paused[streamId] = true
  }

  unpause (streamId) {
    this._paused[streamId] = false
  }
}

module.exports = Reassembly
