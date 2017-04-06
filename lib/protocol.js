var _ = require('lodash');
var ip = require('ip');

var util = require('util');
var crypto = require('crypto');
var EventEmitter = require('events').EventEmitter;


var internet = require('./internet');
var Chunk = require('./packet').Chunk;
var defs = require('./defs');


class Endpoint extends EventEmitter {

    constructor(options) {
        super();

        options = options || {};

        this.localPort = options.localPort;
        this.localAddress = options.localAddress;
        this.MIS = options.MIS || 2;
        this.OS = options.OS || 2;
        this.cookieSecretKey = crypto.randomBytes(16);
        this._associations = [];

        var endpoint = this;

        endpoint.on('packet', function (header, chunks, source, destination) {
            if (!_.isArray(chunks)) {
                var abort = new Chunk('abort');
                endpoint._sendPacket(source, header.source_port, 0, abort.toBuffer(), function () {
                });
                return
            }
            var lastDataChunk = -1;
            var decodedChunks = [];
            var chunk;
            _.each(chunks, function (buffer, index) {
                // 3.3.10.6.  Unrecognized Chunk Type (6)
                var chunk = Chunk.fromBuffer(buffer);
                decodedChunks.push({chunk: chunk, buffer: buffer});
                if (chunk.chunkType == 'data') lastDataChunk = index
            });
            _.each(decodedChunks, function (item, index) {
                item.chunk.packet = index == lastDataChunk;
                endpoint.emit('chunk', item.chunk, item.buffer, source, destination, header)
            })
        });

        endpoint.on('chunk', function (chunk, buffer, source, destination, header) {
            var association = endpoint._getAssociation(source, header.source_port);
            if (association) {
                association.emit(chunk.chunkType, chunk)
            } else {
                endpoint.emit(chunk.chunkType, chunk, buffer, source, destination, header)
            }
        });

        endpoint.on('init', function (chunk, buffer, source, destination, header) {
            var doAbort = false;
            if (doAbort) {
                var abort = new Chunk('abort', {
                    cause_codes: [
                        {
                            cause_code: defs.cause_codes.PROTOCOL_VIOLATION,
                            additional_information: 'fuck off'
                        }
                    ]
                });
                endpoint._sendPacket(source, header.source_port, chunk.initiate_tag, abort, callback);
                return
            }
            var myTag = _.random(0, 0xffffffff);
            var cookie = endpoint.createCookie(buffer, header, myTag);
            var init_ack = new Chunk('init_ack', {
                initiate_tag: myTag,
                initial_tsn: myTag,
                a_rwnd: defs.net_sctp.RWND,
                state_cookie: cookie,
                outbound_streams: chunk.inbound_streams,
                inbound_streams: endpoint.MIS
                // ecn: chunk.forward_tsn_supported,
                // forward_tsn_supported: chunk.forward_tsn_supported
            });
            if (chunk.errors) {
                init_ack.unrecognized_parameter = chunk.errors
            }
            internet.sendPacket(source, {
                    source_port: endpoint.localPort,
                    destination_port: header.source_port,
                    verification_tag: chunk.initiate_tag
                }, [init_ack.toBuffer()]
            );
            /*
             After sending the INIT ACK with the State Cookie parameter, the
             sender SHOULD delete the TCB and any other local resource related to
             the new association, so as to prevent resource attacks.
             */
        });

        endpoint.on('cookie_echo', function (chunk, buffer, source, destination, header) {
            var cookieData = endpoint.validateCookie(chunk.cookie, header);
            /*
             If the State Cookie is valid, create an association to the sender
             of the COOKIE ECHO chunk with the information in the TCB data
             carried in the COOKIE ECHO and enter the ESTABLISHED state.
             */
            if (cookieData) {
                var initChunk = Chunk.fromBuffer(cookieData.buffer);
                var tcb = {
                    remoteAddress: source,
                    myTag: cookieData.myTag,
                    remotePort: cookieData.source_port,
                    peerTag: initChunk.initiate_tag,
                    peerCumulativeTSN: initChunk.initial_tsn - 1,
                    peerRwnd: initChunk.a_rwnd,
                    OS: initChunk.inbound_streams,
                    MIS: endpoint.MIS
                };
                var association = new Association(endpoint, tcb);
                association._up();
                association.cookie_ack({}, function () {
                });
                endpoint.emit('COMMUNICATION UP', association);
            }
        });
    }

    _sendPacket(host, port, tag, chunk, callback) {
        var endpoint = this;
        internet.sendPacket(host, {
                source_port: endpoint.localPort,
                destination_port: port,
                verification_tag: tag
            }, [chunk], callback
        )
    }

    createCookie(chunk, header, myTag) {
        var created = Math.floor(new Date() / 1000);
        var information = Buffer.alloc(16);
        information.writeUInt32BE(created, 0);
        information.writeUInt32BE(defs.net_sctp.valid_cookie_life, 4);
        information.writeUInt16BE(header.source_port, 8);
        information.writeUInt16BE(header.destination_port, 10);
        information.writeUInt32BE(myTag, 12);
        var hash = crypto.createHash(defs.net_sctp.cookie_hmac_alg);
        hash.update(information);
        hash.update(chunk);
        hash.update(this.cookieSecretKey);
        var mac = hash.digest(); // length 16
        return Buffer.concat([mac, information, chunk])
    }

    validateCookie(cookie, header) {
        var endpoint = this;
        if (cookie.length < 32) {
            return
        }
        var information = cookie.slice(16, 32);
        var chunk = cookie.slice(32);
        /*
         Compute a MAC using the TCB data carried in the State Cookie and
         the secret key (note the timestamp in the State Cookie MAY be
         used to determine which secret key to use).
         */
        var hash = crypto.createHash(defs.net_sctp.cookie_hmac_alg);
        hash.update(information);
        hash.update(chunk);
        hash.update(this.cookieSecretKey);
        var mac = hash.digest();
        /*
         Authenticate the State Cookie as one that it previously generated
         by comparing the computed MAC against the one carried in the
         State Cookie.  If this comparison fails, the SCTP header,
         including the COOKIE ECHO and any DATA chunks, should be silently
         discarded
         */
        if (mac.equals(cookie.slice(0, 16))) {
            var result = {
                created: new Date(information.readUInt32BE(0) * 1000),
                cookie_lifespan: information.readUInt32BE(4),
                source_port: information.readUInt16BE(8),
                destination_port: information.readUInt16BE(10),
                myTag: information.readUInt32BE(12)
            };
            /*
             Compare the port numbers and the Verification Tag contained
             within the COOKIE ECHO chunk to the actual port numbers and the
             Verification Tag within the SCTP common header of the received
             header.  If these values do not match, the packet MUST be
             silently discarded.
             */
            if (header.source_port == result.source_port &&
                header.destination_port == result.destination_port &&
                header.verification_tag == result.myTag) {
                /*
                 Compare the creation timestamp in the State Cookie to the current
                 local time.  If the elapsed time is longer than the lifespan
                 carried in the State Cookie, then the packet, including the
                 COOKIE ECHO and any attached DATA chunks, SHOULD be discarded,
                 and the endpoint MUST transmit an ERROR chunk with a "Stale
                 Cookie" error cause to the peer endpoint.
                 */
                if (new Date() - result.created < result.cookie_lifespan) {
                    result.buffer = chunk;
                    return result
                }
            } else {
            }
        } else {
        }
    }

    _destroy() {
        this._associations = [];
        internet.releasePort(this.localPort)
    }

    _getAssociation(host, port) {
        var association = _.find(this._associations, {remoteAddress: host, remotePort: port});
        return association
    }

    ASSOCIATE(options) {
        /*
         Format: ASSOCIATE(local SCTP instance name,
         destination transport addr, outbound stream count)
         -> association id [,destination transport addr list]
         [,outbound stream count]
         */
        var endpoint = this;
        options = options || {};
        if (!options.remotePort) {
            this.emit('error', new Error(util.format('associate EADDRNOTAVAIL %s', options.remoteAddress)))
        }
        var association = new Association(this, {
            remoteAddress: options.remoteAddress,
            remotePort: options.remotePort
        });
        association.init({
            initiate_tag: association.myTag,
            initial_tsn: association.tsn,
            supported_address_type: 5
            // ecn: true,
            // forward_tsn_supported: true
        });

        association.state = 'COOKIE-WAIT';
        return association
    }

    DESTROY() {
        /*
         Format: DESTROY(local SCTP instance name)
         */
        var endpoint = this;
        this._destroy()
    }
}


class Association extends EventEmitter {
    constructor(endpoint, options) {
        super();

        _.assign(this, options);
        var association = this;

        association.endpoint = endpoint;
        endpoint._associations.push(association);

        /*
         RTO    -  Retransmission Timeout
         RTT    -  Round-Trip Time
         RTTVAR -  Round-Trip Time Variation
         SRTT   -  Smoothed RTT
         */

        // 13.3.  Per Transport Address Data
        association.errorCount = 0;
        association.errorThreshold = 10;
        /*
         Congestion window (cwnd): An SCTP variable that limits the data,
         in number of bytes, a sender can send to a particular destination
         transport address before receiving an acknowledgement.
         */
        association.cwnd = 10;
        association.ssthresh = 10;
        association.RTO = defs.net_sctp.rto_initial;
        association.SRTT = 0;
        association.RTTVAR = 0;
        association.rtoPending = false;
        association.PMTU = 1500;
        association.lastTime = new Date();

        association.SSN = {}
        /*
         Receiver Window (rwnd): An SCTP variable a data sender uses to
         store the most recently calculated receiver window of its peer, in
         number of bytes.  This gives the sender an indication of the space
         available in the receiver's inbound buffer.
         */
        association.peerRwnd = 64000;
        association.readBuffer = [];
        association.sackQueue = [];
        association.lastSackDate = null;
        association.bundleQueue = [];
        association.blocks = [];
        association.sentChunks = {};
        association.reassemblyQueue = {};
        association.receivedChunks = {};
        association.state = 'IDLE';
        association.peerMaxTSN = association.peerCumulativeTSN;
        if (!association.myTag) association.myTag = _.random(0, 0xffffffff);
        association.tsn = association.myTag;
        if (!association.myRwnd) association.myRwnd = defs.net_sctp.RWND;

        association.on('data', function (chunk) {
                if (!(association.state == 'ESTABLISHED' || association.state == 'SHUTDOWN-PENDING' || association.state == 'SHUTDOWN-SENT')) return;
                if (!chunk.user_data || !chunk.user_data.length) {
                    association.abort({
                        error_causes: [
                            {
                                cause: 'NO_USER_DATA',
                                tsn: chunk.tsn
                            }
                        ]
                    });
                    return
                }

                var drop = false;
                var duplicate = false;
                var dontProcess = false;
                if (association.myRwnd <= 0 && chunk.tsn > association.peerMaxTSN) {
                    /*
                     When the receiver's advertised window is 0, the receiver MUST drop
                     any new incoming DATA chunk with a TSN larger than the largest TSN
                     received so far.

                     If the new incoming DATA chunk holds a TSN value
                     less than the largest TSN received so far, then the receiver SHOULD
                     drop the largest TSN held for reordering and accept the new incoming
                     DATA chunk.
                     */
                    dontProcess = true;
                } else {
                    // process TSN and modify SACK structures (GAP blocks, duplicates)
                    association.duplicates = [];
                    if (chunk.tsn > association.peerMaxTSN) association.peerMaxTSN = chunk.tsn;
                    var tsn = chunk.tsn;
                    if (tsn <= association.peerCumulativeTSN) {
                        dontProcess = true;
                        association.duplicates.push(tsn);
                    } else if (tsn == association.peerCumulativeTSN + 1) {
                        if (association.blocks.length && (tsn + 1 == association.blocks[0].start)) {
                            association.peerCumulativeTSN = association.blocks[0].finish;
                            association.blocks.shift();
                        } else {
                            association.peerCumulativeTSN = tsn;
                        }
                    } else {
                        var newBlock = {
                            start: tsn,
                            finish: tsn
                        };
                        var blockIndex = -1;
                        var insert = false;
                        var deleteCount = 0;
                        if (association.blocks.length) {
                            var putAfterLast = _.every(association.blocks, function (block, index) {
                                // Iteration is stopped once predicate returns false
                                if (tsn == block.start - 1) {
                                    block.start = tsn;
                                } else if (tsn == block.finish + 1) {
                                    block.finish = tsn;
                                    if (association.blocks[index + 1] && association.blocks[index + 1].start == tsn + 1) {
                                        block.finish = association.blocks[index + 1].finish;
                                        blockIndex = index + 1;
                                        deleteCount = 1
                                    }
                                } else if (tsn < block.start) {
                                    blockIndex = index;
                                    insert = true
                                } else if (tsn >= block.start && tsn <= block.finish) {
                                    dontProcess = true;
                                    association.duplicates.push(tsn);
                                } else {
                                    return true
                                }
                            });
                            if (putAfterLast) {
                                blockIndex = association.blocks.length;
                                insert = true
                            }
                        } else {
                            association.blocks.push(newBlock)
                        }
                        if (blockIndex > -1) {
                            if (insert)
                                association.blocks.splice(blockIndex, deleteCount, newBlock);
                            else
                                association.blocks.splice(blockIndex, deleteCount)
                        }
                    }
                }

                // now we have updated sack structures
                // then we have 3 options about sack: 1) don't send 2) send immediately 3) put to queue

                /*

                 */
                if (chunk.packet || dontProcess) {
                    // prepare sack chunk
                    var sackOptions = {
                        a_rwnd: association.myRwnd > 0 ? association.myRwnd : 0,
                        cumulative_tsn_ack: association.peerCumulativeTSN
                    };
                    if (association.blocks.length) {
                        sackOptions.gap_blocks_number = association.blocks.length;
                        var gap_blocks = [];
                        _.each(association.blocks, function (block) {
                            gap_blocks.push({
                                start: block.start - association.peerCumulativeTSN,
                                finish: block.finish - association.peerCumulativeTSN
                            })
                        });
                        sackOptions.sack_info = {gap_blocks: gap_blocks};
                    }

                    // now we prepared chunk and need to decide, send it, or queue or even throw away
                    // send SACK or shutdown (with or without SACK) immediately or queued
                    if (association.state == 'SHUTDOWN-SENT') {
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
                        association.shutdown({
                            cumulative_tsn_ack: association.peerCumulativeTSN
                        });
                        if (sackOptions.sack_info) {
                            association.sack(sackOptions);
                        }
                    } else {
                        association.sackQueue.push(sackOptions);
                        var timeout = 0;
                        if (dontProcess || !association.lastSackDate || association.sackQueue.length >= defs.net_sctp.sack_freq) {
                            /*
                             After the reception of the first DATA chunk in an association the
                             endpoint MUST immediately respond with a SACK to acknowledge the DATA
                             chunk.  Subsequent acknowledgements should be done as described in
                             Section 6.2.

                             The guidelines on delayed acknowledgement algorithm specified in
                             Section 4.2 of [RFC2581] SHOULD be followed.  Specifically, an
                             acknowledgement SHOULD be generated for at least every second packet
                             (not every second DATA chunk) received, and SHOULD be generated
                             within 200 ms of the arrival of any unacknowledged DATA chunk.  In
                             some situations, it may be beneficial for an SCTP transmitter to be
                             more conservative than the algorithms detailed in this document
                             allow.  However, an SCTP transmitter MUST NOT be more aggressive than
                             the following algorithms allow.

                             When a packet arrives with duplicate DATA chunk(s) and with no new
                             DATA chunk(s), the endpoint MUST immediately send a SACK with no
                             delay.  If a packet arrives with duplicate DATA chunk(s) bundled with
                             new DATA chunks, the endpoint MAY immediately send a SACK.  Normally,
                             receipt of duplicate DATA chunks will occur when the original SACK
                             chunk was lost and the peer's RTO has expired.  The duplicate TSN
                             number(s) SHOULD be reported in the SACK as duplicate.

                             (rwnd=0)
                             In either case, if such a DATA chunk is dropped, the
                             receiver MUST immediately send back a SACK with the current receive
                             window showing only DATA chunks received and accepted so far.  The
                             dropped DATA chunk(s) MUST NOT be included in the SACK, as they were
                             not accepted.  The receiver MUST also have an algorithm for
                             advertising its receive window to avoid receiver silly window
                             syndrome (SWS), as described in [RFC0813].  The algorithm can be
                             similar to the one described in Section 4.2.3.3 of [RFC1122].
                             */
                        } else {
                            timeout = defs.net_sctp.sack_timeout
                        }
                        association._sackTimeout = setTimeout(function () {
                            association._sendSacks()
                        }, timeout)
                    }
                }

                if (dontProcess) return;

                association.myRwnd -= chunk.user_data.length;

                if (chunk.flags.B && chunk.flags.E) {
                    // chunk is not fragmented
                    association._deliver(chunk.user_data, chunk.stream_identifier)
                } else {
                    // chunk is fragmented
                    if (!association.reassemblyQueue[chunk.stream_identifier]) {
                        // store all chunks, begin and end tsns
                        association.reassemblyQueue[chunk.stream_identifier] = {
                            parity: 0,
                            sorted: []
                        }
                    }
                    var reasmQueue = association.reassemblyQueue[chunk.stream_identifier];
                    if (association.receivedChunks[chunk.tsn]) {
                    } else {
                        association.receivedChunks[chunk.tsn] = chunk;
                        if (chunk.flags.B) reasmQueue.parity += 1;
                        if (chunk.flags.E) reasmQueue.parity -= 1;
                        reasmQueue.sorted.splice(_.sortedIndex(reasmQueue.sorted, chunk.tsn), 0, chunk.tsn);
                        if (reasmQueue.parity === 0) {
                            var B;
                            var N;
                            var E;
                            var buffers = [];
                            var tsns = [];
                            var removed = [];
                            _.each(reasmQueue.sorted, function (tsn, idx) {
                                if (association.receivedChunks[tsn].flags.B) {
                                    B = N = tsn;
                                    tsns = [B]
                                } else if (association.receivedChunks[tsn].flags.E) {
                                    if (tsn == N + 1) {
                                        E = tsn;
                                        tsns.push(E);
                                        buffers = [];
                                        _.each(tsns, function (tsn) {
                                            buffers.push(association.receivedChunks[tsn].user_data);
                                            delete association.receivedChunks[tsn]
                                        });
                                        removed = removed.concat(tsns);
                                        association._deliver(Buffer.concat(buffers), chunk.stream_identifier)
                                    }
                                } else {
                                    if (tsn == N + 1) {
                                        N = tsn;
                                        tsns.push(N)
                                    } else {
                                        N = null
                                    }
                                }
                            });
                            _.pullAll(reasmQueue.sorted, removed)
                        }
                    }

                }
            }
        );

        association.on('sack', function (chunk) {
            /*
             A SACK MUST be processed in ESTABLISHED, SHUTDOWN-PENDING, and
             SHUTDOWN-RECEIVED.  An incoming SACK MAY be processed in COOKIE-
             ECHOED.  A SACK in the CLOSED state is out of the blue and SHOULD be
             processed according to the rules in Section 8.4.  A SACK chunk
             received in any other state SHOULD be discarded.
             */
            if (!(association.state == 'ESTABLISHED'
                || association.state == 'SHUTDOWN-PENDING'
                || association.state == 'SHUTDOWN-RECEIVED'
                || association.state == 'COOKIE-ECHOED')) return;

            association.peerRwnd = chunk.a_rwnd;

            var ackAdvanced = association.cumulativeTsnAck ? chunk.cumulative_tsn_ack > association.cumulativeTsnAck : true;
            var noOutstandingData = false;
            association.cumulativeTsnAck = chunk.cumulative_tsn_ack;
            _.each(association.sentChunks, function (item, key) {
                if (key <= association.cumulativeTsnAck) {
                    association._acknowledge(key)
                }
            });
            if (chunk.sack_info && chunk.sack_info.gap_blocks && chunk.sack_info.gap_blocks.length) {
                // _.sortBy(chunk.sack_info.gap_blocks, ['start'])
                _.each(chunk.sack_info.gap_blocks, function (block) {
                    for (var tsn = block.start; tsn <= block.finish; tsn++) {
                        if (association.sentChunks[association.cumulativeTsnAck + tsn]) {
                            association._acknowledge(association.cumulativeTsnAck + tsn)
                        }
                    }
                });
                /*
                 Whenever a SACK is received missing a TSN that was previously
                 acknowledged via a Gap Ack Block, start the T3-rtx for the
                 destination address to which the DATA chunk was originally
                 transmitted if it is not already running.
                 */
            } else {
                if (association.cumulativeTsnAck == association.tsn - 1) {
                    /*
                     Whenever all outstanding data sent to an address have been
                     acknowledged, turn off the T3-rtx timer of that address.
                     */
                    noOutstandingData = true;
                    association._stopT3()
                }
            }
            if (ackAdvanced && !noOutstandingData) {
                /*
                 Whenever a SACK is received that acknowledges the DATA chunk
                 with the earliest outstanding TSN for that address, restart the
                 T3-rtx timer for that address with its current RTO (if there is
                 still outstanding data on that address).
                 */
                association._restartT3()
            }
        });

        association.on('init', function (chunk) {
            if (association.state == 'COOKIE-WAIT' || association.state == 'COOKIE-ECHOED') {
                // 5.2.1.  INIT Received in COOKIE-WAIT or COOKIE-ECHOED State (Item B)
            } else {
                // 5.2.2.  Unexpected INIT in States Other than CLOSED, COOKIE-ECHOED, COOKIE-WAIT, and SHUTDOWN-ACK-SENT
            }
        });

        association.on('cookie_echo', function (chunk) {
            /*
             5.2.4.  Handle a COOKIE ECHO when a TCB Exists
             */
        });

        association.on('init_ack', function (chunk) {
            if (association.state == 'COOKIE-WAIT') {
                association.peerTag = chunk.initiate_tag;
                //association.MIS = chunk.a_rwnd; todo ???
                association.peerRwnd = chunk.a_rwnd;
                association.peerCumulativeTSN = chunk.initial_tsn - 1;
                association.cookie_echo({
                    cookie: chunk.state_cookie
                }, function () {
                });
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

                // chunk.errors = [Buffer.from('80000004', 'hex')] // <- test
                if (chunk.errors) {
                    association.error({
                        error_causes: [{
                            cause: 'UNRECONGNIZED_PARAMETERS',
                            unrecognized_parameters: Buffer.concat(chunk.errors)
                        }]
                    })
                }
                association.state = 'COOKIE-ECHOED'
            } else {
                /*
                 5.2.3.  Unexpected INIT ACK

                 If an INIT ACK is received by an endpoint in any state other than the
                 COOKIE-WAIT state, the endpoint should discard the INIT ACK chunk.
                 An unexpected INIT ACK usually indicates the processing of an old or
                 duplicated INIT chunk.
                 */
            }
        });

        association.on('heartbeat', function (chunk) {
            association.heartbeat_ack({
                heartbeat_info: chunk.heartbeat_info
            })
        });

        association.on('heartbeat_ack', function (chunk) {
        });

        association.on('cookie_ack', function () {
            if (association.state == 'COOKIE-ECHOED') {
                association._up();
                association.emit('COMMUNICATION UP')
            }
        });

        association.on('shutdown', function () {
            if (association.state == 'SHUTDOWN-RECEIVED') {
                /*
                 Once an endpoint has reached the SHUTDOWN-RECEIVED state, it MUST NOT
                 send a SHUTDOWN in response to a ULP request, and should discard
                 subsequent SHUTDOWN chunks.
                 */
                return
            } else if (association.state == 'SHUTDOWN-SENT') {
                /*
                 If an endpoint is in the SHUTDOWN-SENT state and receives a SHUTDOWN
                 chunk from its peer, the endpoint shall respond immediately with a
                 SHUTDOWN ACK to its peer, and move into the SHUTDOWN-ACK-SENT state
                 restarting its T2-shutdown timer.
                 */
            } else {
                association.state = 'SHUTDOWN-RECEIVED'
            }
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
            association.shutdown_ack({}, function () {
                association.state = 'SHUTDOWN-ACK-SENT';
            })
        });

        association.on('shutdown_ack', function () {
            /*
             Upon the receipt of the SHUTDOWN ACK, the SHUTDOWN sender shall stop
             the T2-shutdown timer, send a SHUTDOWN COMPLETE chunk to its peer,
             and remove all record of the association.
             */
            association.state = 'CLOSED';
            association.shutdown_complete({}, function () {
                association.emit('SHUTDOWN COMPLETE');
                association._destroy()
            })
        });

        association.on('shutdown_complete', function () {
            /*
             Upon reception of the SHUTDOWN COMPLETE chunk, the endpoint will
             verify that it is in the SHUTDOWN-ACK-SENT state; if it is not, the
             chunk should be discarded.  If the endpoint is in the SHUTDOWN-ACK-
             SENT state, the endpoint should stop the T2-shutdown timer and remove
             all knowledge of the association (and thus the association enters the
             CLOSED state).
             */
            if (association.state == 'SHUTDOWN-ACK-SENT') {
                association.emit('SHUTDOWN COMPLETE');
                association._destroy()
            }
        });

        association.on('error', function (chunk) {
            if (_.find(chunk.error_causes, {cause: 'STALE_COOKIE_ERROR'})) {
                // 5.2.6.  Handle Stale COOKIE Error
            }
            association.emit('COMMUNICATION ERROR', chunk.error_causes)

        });

        association.on('abort', function (chunk) {
            association._down();
            if (association.bundleQueue.length) {
            }
            association.bundleQueue = [];
            //var user_error = _.find(chunk.error_causes, {cause: 'USER_INITIATED_ABORT'});
            association.emit('COMMUNICATION LOST', 'abort', chunk.error_causes);
            association._destroy()
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

    _acknowledge(tsn) {
        var association = this;
        delete association.sentChunks[tsn];
        // RTO calculation
        if (association.rtoPending && association.rtoPending.tsn == tsn) {
            var R = new Date() - association.rtoPending.sent;
            if (!association.SRTT) {
                association.SRTT = R;
                association.RTTVAR = R / 2;
                association.RTO = association.SRTT + 4 * association.RTTVAR;
            } else {
                var alpha = 1 / defs.net_sctp.rto_alpha_exp_divisor;
                var beta = 1 / defs.net_sctp.rto_beta_exp_divisor;
                association.RTTVAR = (1 - beta) * association.RTTVAR + beta * Math.abs(association.SRTT - R);
                association.SRTT = (1 - alpha) * association.SRTT + alpha * R;
                association.RTO = association.SRTT + 4 * association.RTTVAR;
            }
            if (association.RTO < defs.net_sctp.rto_min) association.RTO = defs.net_sctp.rto_min;
            if (association.RTO > defs.net_sctp.rto_max) association.RTO = defs.net_sctp.rto_max;
            association.rtoPending = false
        }
    }

    _sendSacks() {
        var association = this;
        var length = association.sackQueue.length;
        if (length) {
            // send only one most recent sack
            var sackOptions = association.sackQueue.pop();
            association.sackQueue = [];
            sackOptions.sack_info = sackOptions.sack_info || [];
            sackOptions.sack_info.duplicate_tsn = association.duplicates;
            association.duplicates = [];
            association.sack(sackOptions);
            association.lastSackDate = new Date();
            if (association._sackTimeout) {
                clearTimeout(association._sackTimeout)
            }
        }
    }

    _down() {
        if (this._heartbeatInterval) {
            clearInterval(this._heartbeatInterval)
        }
        this.sackQueue = []
        if (this._sackTimeout) {
            clearTimeout(this._sackTimeout)
        }
    }

    _up() {
        var association = this;
        association.state = 'ESTABLISHED';
        association._heartbeatInterval = setInterval(function () {
            /*
             The Sender-Specific Heartbeat Info field should normally include
             information about the sender's current time when this HEARTBEAT
             chunk is sent and the destination transport address to which this
             HEARTBEAT is sent (see Section 8.3).  This information is simply
             reflected back by the receiver in the HEARTBEAT ACK message (see
             Section 3.3.6).  Note also that the HEARTBEAT message is both for
             reachability checking and for path verification (see Section 5.4).
             When a HEARTBEAT chunk is being used for path verification
             purposes, it MUST hold a 64-bit random nonce.
             */

            var heartbeat_info = Buffer.alloc(44);
            heartbeat_info.writeUInt16BE(512, 0);
            heartbeat_info.writeUInt16BE(association.remotePort, 2);
            ip.toBuffer(association.remoteAddress, heartbeat_info, 4);
            var need_nonce = false;
            if (need_nonce) {
                var nonce_length = 8;
                var nonce_start = 16;
                var nonce = crypto.randomBytes(nonce_length);
                heartbeat_info.fill(nonce, nonce_start, nonce_start + nonce_length)
            }
            association.heartbeat({
                heartbeat_info: heartbeat_info
            })
        }, defs.net_sctp.hb_interval)
    }

    _sendPacket(buffers, callbacks) {
        var association = this;
        var endpoint = association.endpoint;
        internet.sendPacket(association.remoteAddress, {
                source_port: endpoint.localPort,
                destination_port: association.remotePort,
                verification_tag: association.peerTag
            },
            buffers,
            function () {
                _.each(callbacks, function (chunk_callback) {
                    if (_.isFunction(chunk_callback)) {
                        chunk_callback()
                    }
                })
            }
        )
    }

    _deliver(user_data, stream) {
        var association = this;
        association.myRwnd += user_data.length;
        if (association.listeners('DATA ARRIVE')) {
            association.readBuffer.push(user_data);
            association.emit('DATA ARRIVE', stream)
        }
    }

    _destroy() {
        this._stopT3();
        if (this.endpoint)
            _.remove(this.endpoint._associations, this);
        delete this.endpoint;
        this.state = 'CLOSED'
    }

    SHUTDOWN(callback) {
        /*
         Format: SHUTDOWN(association id)
         -> result
         */
        var association = this;
        if (association.state == 'SHUTDOWN-RECEIVED') {
            return
        }
        association._down();
        association.state = 'SHUTDOWN-PENDING';

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

        association._down();

        association.shutdown({
            cumulative_tsn_ack: association.peerCumulativeTSN
        }, function () {
            /*
             It shall then start the T2-shutdown timer and enter the SHUTDOWN-SENT
             state.  If the timer expires, the endpoint must resend the SHUTDOWN
             with the updated last sequential TSN received from its peer.
             The rules in Section 6.3 MUST be followed to determine the proper
             timer value for T2-shutdown.
             */
            association.state = 'SHUTDOWN-SENT';
            if (_.isFunction(callback)) {
                callback()
            }
        })
    }

    ABORT(reason) {
        /*
         Format: ABORT(association id [, Upper Layer Abort Reason]) ->
         result
         */

        var association = this;
        association._down();
        var options;
        if (_.isString(reason)) {
            options.error_causes = [
                {
                    cause: 'USER_INITIATED_ABORT',
                    abort_reason: reason
                }
            ]
        }
        association.abort(options, function () {
        })
    }

    SEND(buffer, options, callback) {
        /*
         Format: SEND(association id, buffer address, byte count [,context]
         [,stream id] [,life time] [,destination transport address]
         [,unordered flag] [,no-bundle flag] [,payload protocol-id] )
         -> result
         */
        var association = this;

        if (association.state == 'SHUTDOWN-PENDING' || association.state == 'SHUTDOWN-RECEIVED') {
            /*
             Upon receipt of the SHUTDOWN primitive from its upper layer, the endpoint enters the SHUTDOWN-PENDING state ... accepts no new data from its upper layer
             Upon reception of the SHUTDOWN, the peer endpoint shall enter the SHUTDOWN-RECEIVED state, stop accepting new data from its SCTP user
             */
            return
        }

        /*
         Before an endpoint transmits a DATA chunk, if any received DATA
         chunks have not been acknowledged (e.g., due to delayed ack), the
         sender should create a SACK and bundle it with the outbound DATA
         chunk, as long as the size of the final SCTP packet does not exceed
         the current MTU.  See Section 6.2.
         */

        var chunk;
        options.stream = options.stream || 0;
        if (options.stream < 0 || options.stream > association.OS) {
            return
        } else {
            if (association.SSN[options.stream] === undefined || association.SSN[options.stream] > 65535) {
                association.SSN[options.stream] = 0
            }
        }
        var mtu = association.PMTU - 36;
        if (buffer.length > mtu) {
            var offset = 0;
            while (offset < buffer.length) {
                chunk = {
                    flags: {
                        "E": buffer.length - offset <= mtu,
                        "B": offset == 0,
                        "U": options.unordered,
                        "I": 0
                    },
                    stream_identifier: options.stream,
                    stream_sequence_number: association.SSN[options.stream]++,
                    payload_protocol_identifier: options.protocol,
                    user_data: buffer.slice(offset, offset + mtu)
                };
                offset += mtu;
                association._sendData(chunk);
            }
        } else {
            chunk = {
                flags: {
                    "E": 1,
                    "B": 1,
                    "U": options.unordered,
                    "I": 0
                },
                stream_identifier: options.stream,
                stream_sequence_number: association.SSN[options.stream]++,
                payload_protocol_identifier: options.protocol,
                user_data: buffer
            };
            association._sendData(chunk)
        }
        if (_.isFunction(callback)) {
            callback()
        }
    }

    _sendData(chunk) {
        var association = this;
        chunk.tsn = association.tsn;
        association.sentChunks[chunk.tsn] = chunk;
        // emulate local packet loss
        if (_.random(1, 10) > 0)
            association.data(chunk);
        association.tsn++;
        association._startT3()
    }

    _startT3() {
        var association = this;
        if (association.T3) return;
        association.T3 = setTimeout(function () {
            if (association.sentChunks.length == 0) return;
            // E1
            /*
             For the destination address for which the timer expires, adjust
             its ssthresh with rules defined in Section 7.2.3 and set the
             cwnd <- MTU.

             ssthresh = max(cwnd/2, 4*MTU)
             cwnd = ssthresh
             partial_bytes_acked = 0

             Basically, a packet loss causes cwnd to be cut in half.
             */
            // E2
            if (association.RTO < defs.net_sctp.rto_max) {
                association.RTO *= 2;
                if (association.RTO > defs.net_sctp.rto_max) association.RTO = defs.net_sctp.rto_max
            }
            // E3
            /*
             Determine how many of the earliest (i.e., lowest TSN)
             outstanding DATA chunks for the address for which the T3-rtx has
             expired will fit into a single packet, subject to the MTU
             constraint for the path corresponding to the destination
             transport address to which the retransmission is being sent
             (this may be different from the address for which the timer
             expires; see Section 6.4).  Call this value K.  Bundle and
             retransmit those K DATA chunks in a single packet to the
             destination endpoint.
             */
            var bundledLength = 20;
            var bundledCount = 0;
            _.some(association.sentChunks, function (chunk) {
                bundledLength += chunk.user_data.length + 16;
                if (bundledLength > association.PMTU) {
                    bundledLength -= chunk.user_data.length + 16;
                    return true
                } else {
                    bundledCount++;
                    association.data(chunk);
                }
            });
            if (bundledCount > 0) association._restartT3();

            /*
             E4)  Start the retransmission timer T3-rtx on the destination address
             to which the retransmission is sent, if rule R1 above indicates
             to do so.  The RTO to be used for starting T3-rtx should be the
             one for the destination address to which the retransmission is
             sent, which, when the receiver is multi-homed, may be different
             from the destination address for which the timer expired (see
             Section 6.4 below).

             After retransmitting, once a new RTT measurement is obtained (which
             can happen only when new data has been sent and acknowledged, per
             rule C5, or for a measurement made from a HEARTBEAT; see Section
             8.3), the computation in rule C3 is performed, including the
             computation of RTO, which may result in "collapsing" RTO back down
             after it has been subject to doubling (rule E2).

             Note: Any DATA chunks that were sent to the address for which the
             T3-rtx timer expired but did not fit in one MTU (rule E3 above)
             should be marked for retransmission and sent as soon as cwnd allows
             (normally, when a SACK arrives).

             The final rule for managing the retransmission timer concerns
             failover (see Section 6.4.1):

             F1)  Whenever an endpoint switches from the current destination
             transport address to a different one, the current retransmission
             timers are left running.  As soon as the endpoint transmits a
             packet containing DATA chunk(s) to the new transport address,
             start the timer on that transport address, using the RTO value
             of the destination address to which the data is being sent, if
             rule R1 indicates to do so.
             */
        }, association.RTO)
    }

    _stopT3() {
        if (this.T3) {
            clearTimeout(this.T3);
            this.T3 = null
        }
    }

    _restartT3() {
        this._stopT3();
        this._startT3()
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
        var association = this;
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

        return {
            state: this.state
        }
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
}

_.forEach(defs.chunks, function (chunk, chunkType) {
    Association.prototype[chunkType] = function (options, callback) {
        var association = this;
        var chunk = new Chunk(chunkType, options);
        var buffer = chunk.toBuffer();
        setTimeout(function () {
        }, 0);
        // are this checks statically optimized?
        if (chunkType == 'init' || chunkType == 'init_ack' || chunkType == 'shutdown_complete') {
            // no bundle
            setTimeout(function () {
                // use nextTick to be in order with bundled chunks
                association._sendPacket([buffer], [callback])
            }, 0)
        } else {
            association.bundleQueue.push({
                buffer: buffer,
                chunk: chunk,
                callback: callback
            });
            setTimeout(function () {
                if (association.state == 'CLOSED') return;
                if (!association.bundleQueue.length) return;
                var callbacks = [];
                var bundledChunks = [];
                var bundledLength = 20;
                var mtu = association.PMTU;
                association.bundleQueue.push(false);
                var haveCookieEcho = false;
                association.bundleQueue.forEach(function (item, key) {
                    if (!item || bundledLength + item.buffer.length > mtu) {
                        association._sendPacket(bundledChunks, callbacks);
                        bundledChunks = [];
                        callbacks = [];
                        bundledLength = 20
                    } else {
                        if (item.chunk.chunkType == 'data') {
                            /*
                             Data transmission MUST only happen in the ESTABLISHED, SHUTDOWN-
                             PENDING, and SHUTDOWN-RECEIVED states.  The only exception to this is
                             that DATA chunks are allowed to be bundled with an outbound COOKIE
                             ECHO chunk when in the COOKIE-WAIT state.
                             */
                            if (association.state == 'ESTABLISHED' || association.state == 'SHUTDOWN-PENDING' || association.state == 'SHUTDOWN-RECEIVED') {
                                //  allow
                            } else if (association.state == 'COOKIE-WAIT' && haveCookieEcho) {
                                // allow
                            } else {
                                return
                            }
                            if (!association.rtoPending) {
                                association.rtoPending = {
                                    tsn: item.chunk.tsn,
                                    sent: new Date()
                                }
                            }
                        } else if (item.chunk.chunkType == 'cookie_echo') {
                            haveCookieEcho = true
                        }
                        bundledChunks.push(item.buffer);
                        bundledLength += item.buffer.length;
                        callbacks.push(item.callback);
                    }
                });
                association.bundleQueue = []
            }, 0)
        }
    }
});


function INITIALIZE(options) {
    var endpoint = new Endpoint(options);
    return internet.takePort(endpoint)
}

module.exports.INITIALIZE = INITIALIZE;
module.exports.Association = Association;
