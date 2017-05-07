'use strict';

var _ = require('lodash');
var ip = require('ip');

var util = require('util');
var crypto = require('crypto');
var EventEmitter = require('events').EventEmitter;


var internet = require('./internet');
var Chunk = require('./packet').Chunk;
var defs = require('./defs');
var SerialNumber = require('./serial');

const MAX_DUPLICATES_LENGTH = 100;

class Endpoint extends EventEmitter {

    constructor(options) {
        super();
        options = options || {};
        var endpoint = this;
        endpoint.localPort = options.localPort;
        endpoint.localAddress = options.localAddress;
        endpoint.MIS = options.MIS || 2;
        endpoint.OS = options.OS || 2;
        endpoint.cookieSecretKey = crypto.randomBytes(32);
        setInterval(function () {
            endpoint.cookieSecretKey = crypto.randomBytes(32);
        }, defs.net_sctp.valid_cookie_life * 5);
        endpoint._associations = [];

        endpoint.on('packet', function (header, chunks, source, destination) {
            if (!_.isArray(chunks)) {
                return
            }
            var emulateLoss;
            //emulateLoss = (_.random(1, 10) == 10);
            if (emulateLoss) {
                return;
            }
            var lastDataChunk = -1;
            var decodedChunks = [];
            var chunk;
            var discard = false;
            var errors = [];
            _.each(chunks, function (buffer, index) {
                var chunk = Chunk.fromBuffer(buffer);
                if (!chunk.chunkType) {
                    switch (chunk.action) {
                        case 1:
                            /*00 -  Stop processing this SCTP packet and discard it, do not
                             process any further chunks within it.*/
                            discard = true;
                            return;
                        case 0:
                            /*01 -  Stop processing this SCTP packet and discard it, do not
                             process any further chunks within it, and report the
                             unrecognized chunk in an 'Unrecognized Chunk Type'.*/
                            errors.push({cause: 'UNRECONGNIZED_CHUNK_TYPE', unrecognized_chunk: buffer});
                            discard = true;
                            return;
                        case 2:
                            /*10 -  Skip this chunk and continue processing.*/
                            break;
                        case 3:
                            /*11 -  Skip this chunk and continue processing, but report in an
                             ERROR chunk using the 'Unrecognized Chunk Type' cause of
                             error.*/
                            errors.push({cause: 'UNRECONGNIZED_CHUNK_TYPE', unrecognized_chunk: buffer});
                            break;
                    }
                }
                chunk.buffer = buffer;
                decodedChunks.push(chunk);
                if (chunk.chunkType == 'data') lastDataChunk = index
            });

            var association = endpoint._getAssociation(source, header.source_port);
            if (association) {
                if (header.verification_tag != association.myTag) {
                    /*
                     When receiving an SCTP packet, the endpoint MUST ensure that the
                     value in the Verification Tag field of the received SCTP packet
                     matches its own tag.  If the received Verification Tag value does not
                     match the receiver's own tag value, the receiver shall silently
                     discard the packet and shall not process it any further except for
                     those cases listed in Section 8.5.1 below.
                     */
                    return
                }
                /*
                 B) Rules for packet carrying ABORT:

                 -   The endpoint MUST always fill in the Verification Tag field of
                 the outbound packet with the destination endpoint's tag value, if
                 it is known.

                 -   If the ABORT is sent in response to an OOTB packet, the endpoint
                 MUST follow the procedure described in Section 8.4.



                 Stewart                     Standards Track                   [Page 105]

                 RFC 4960          Stream Control Transmission Protocol    September 2007


                 -   The receiver of an ABORT MUST accept the packet if the
                 Verification Tag field of the packet matches its own tag and the
                 T bit is not set OR if it is set to its peer's tag and the T bit
                 is set in the Chunk Flags.  Otherwise, the receiver MUST silently
                 discard the packet and take no further action.

                 C) Rules for packet carrying SHUTDOWN COMPLETE:

                 -   When sending a SHUTDOWN COMPLETE, if the receiver of the SHUTDOWN
                 ACK has a TCB, then the destination endpoint's tag MUST be used,
                 and the T bit MUST NOT be set.  Only where no TCB exists should
                 the sender use the Verification Tag from the SHUTDOWN ACK, and
                 MUST set the T bit.

                 -   The receiver of a SHUTDOWN COMPLETE shall accept the packet if
                 the Verification Tag field of the packet matches its own tag and
                 the T bit is not set OR if it is set to its peer's tag and the T
                 bit is set in the Chunk Flags.  Otherwise, the receiver MUST
                 silently discard the packet and take no further action.  An
                 endpoint MUST ignore the SHUTDOWN COMPLETE if it is not in the
                 SHUTDOWN-ACK-SENT state.

                 D) Rules for packet carrying a COOKIE ECHO

                 -   When sending a COOKIE ECHO, the endpoint MUST use the value of
                 the Initiate Tag received in the INIT ACK.

                 -   The receiver of a COOKIE ECHO follows the procedures in Section
                 5.

                 E) Rules for packet carrying a SHUTDOWN ACK

                 -   If the receiver is in COOKIE-ECHOED or COOKIE-WAIT state the
                 procedures in Section 8.4 SHOULD be followed; in other words, it
                 should be treated as an Out Of The Blue packet.
                 */
            } else {
                if (header.verification_tag == 0) {
                    if (decodedChunks.length == 1 && decodedChunks[0].chunkType && decodedChunks[0].chunkType == 'init') {
                        /*
                         A) Rules for packet carrying INIT:

                         -   The sender MUST set the Verification Tag of the packet to 0.

                         -   When an endpoint receives an SCTP packet with the Verification
                         Tag set to 0, it should verify that the packet contains only an
                         INIT chunk.  Otherwise, the receiver MUST silently discard the
                         packet.
                         */
                    } else {
                        return;
                    }
                }
            }

            if (discard) {
                if (errors.length > 0) {
                    if (association) {
                        association.error({error_causes: errors})
                    } else {
                        var abort = new Chunk('abort', {
                            flags: {T: true},
                            error_causes: errors
                        });
                        endpoint._sendPacket(source, header.source_port, header.verification_tag, abort.toBuffer());
                    }
                }
                return;
            }

            _.each(decodedChunks, function (chunk, index) {
                chunk.packet = index == lastDataChunk;
                endpoint.emit('chunk', chunk, source, destination, header)
            })
        });

        endpoint.on('chunk', function (chunk, source, destination, header) {
            var association = endpoint._getAssociation(source, header.source_port);
            if (association) {
                association.emit('chunk', chunk, header);
                association.emit(chunk.chunkType, chunk);
            } else {
                endpoint.emit(chunk.chunkType, chunk, source, destination, header)
            }
        });

        endpoint.on('abort', function (chunk, source, destination, header) {
        });

        endpoint.on('init', function (chunk, source, destination, header) {
            var errors = [];
            if (chunk.initiate_tag == 0
                || chunk.a_rwnd < 1500
                || chunk.inbound_streams == 0
                || chunk.outbound_streams == 0) {
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
                errors.push({cause: 'INVALID_MANDATORY_PARAMETER'});
            }
            if (errors.length > 0) {
                var abort = new Chunk('abort', {error_causes: errors});
                endpoint._sendPacket(source, header.source_port, chunk.initiate_tag, abort.toBuffer());
                return
            }
            var myTag = _.random(0, 0xffffffff);
            var cookie = endpoint.createCookie(chunk.buffer, header, myTag);
            var init_ack = new Chunk('init_ack', {
                initiate_tag: myTag,
                initial_tsn: myTag,
                a_rwnd: defs.net_sctp.RWND,
                state_cookie: cookie,
                outbound_streams: chunk.inbound_streams,
                inbound_streams: endpoint.MIS
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

        endpoint.on('cookie_echo', function (chunk, source, destination, header) {
            var cookieData = endpoint.validateCookie(chunk.cookie, header);
            /*
             If the State Cookie is valid, create an association to the sender
             of the COOKIE ECHO chunk with the information in the TCB data
             carried in the COOKIE ECHO and enter the ESTABLISHED state.
             */
            if (cookieData) {
                var initChunk = Chunk.fromBuffer(cookieData.init);
                var tcb = {
                    remoteAddress: source,
                    myTag: cookieData.myTag,
                    remotePort: cookieData.source_port,
                    peerTag: initChunk.initiate_tag,
                    peerInitialTSN: initChunk.initial_tsn,
                    peerRwnd: initChunk.a_rwnd,
                    ssthresh: initChunk.a_rwnd,
                    OS: initChunk.inbound_streams,
                    MIS: endpoint.MIS
                };
                var association = new Association(endpoint, tcb);
                association.state = 'ESTABLISHED';
                association._enableHeartbeat();
                /*
                 A COOKIE ACK MAY be sent to an UNCONFIRMED address, but it MUST be
                 bundled with a HEARTBEAT including a nonce.  An implementation
                 that does NOT support bundling MUST NOT send a COOKIE ACK to an
                 UNCONFIRMED address.
                 2)  For the receiver of the COOKIE ECHO, the only CONFIRMED address
                 is the one to which the INIT-ACK was sent.
                 */
                association.cookie_ack({}, function () {
                    endpoint.emit('COMMUNICATION UP', association);
                });
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
        var result;
        if (cookie.length < 32) {
            return
        }
        var information = cookie.slice(16, 32);
        var init = cookie.slice(32);
        /*
         Compute a MAC using the TCB data carried in the State Cookie and
         the secret key (note the timestamp in the State Cookie MAY be
         used to determine which secret key to use).
         */
        var hash = crypto.createHash(defs.net_sctp.cookie_hmac_alg);
        hash.update(information);
        hash.update(init);
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
            result = {
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
                    result.init = init;
                    return result
                }
            } else {
            }
        } else {
        }
    }

    _destroy() {
        this._associations = [];
        internet.releasePort(this.localPort);
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
        var initParams = {
            initiate_tag: association.myTag,
            a_rwnd: defs.net_sctp.RWND,
            outbound_streams: options.OS || endpoint.OS,
            inbound_streams: options.MIS || endpoint.MIS,
            initial_tsn: association.tsn.getNumber()
            //,supported_address_type: 5
        };
        var counter = 0;
        association.RTI = defs.net_sctp.rto_initial;
        var init = function () {
            if (counter >= defs.net_sctp.max_init_retransmits) {
                // fail
            } else {
                if (counter) {
                    // not from RFC, but from lk-sctp
                    association.RTI *= 2;
                    if (association.RTI > defs.net_sctp.rto_max) association.RTI = defs.net_sctp.rto_max;
                }
                association.init(initParams);
                counter++;
                association.T1 = setTimeout(init, association.RTO)
            }
        };
        init();
        association.state = 'COOKIE-WAIT';
        return association;
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
        association.MIS = association.MIS || endpoint.MIS;
        association.peerSSN = [];
        for (var sid = 0; sid < association.MIS; sid++) {
            association.peerSSN.push(SerialNumber(0, 16))
        }

        association.bundling = 0;
        association.sacks = 0;
        association.errorCount = 0;
        association.errorThreshold = 10;
        association.RTO = defs.net_sctp.rto_initial;
        association.SRTT = 0;
        association.RTTVAR = 0;
        association.rtoPending = false;
        association.PMTU = 1500;
        /*
         Congestion window (cwnd): An SCTP variable that limits the data,
         in number of bytes, a sender can send to a particular destination
         transport address before receiving an acknowledgement.

         7.2.1.  Slow-Start

         Beginning data transmission into a network with unknown conditions or
         after a sufficiently long idle period requires SCTP to probe the
         network to determine the available capacity.  The slow-start
         algorithm is used for this purpose at the beginning of a transfer, or
         after repairing loss detected by the retransmission timer.

         o  The initial cwnd before DATA transmission or after a sufficiently
         long idle period MUST be set to min(4*MTU, max (2*MTU, 4380
         bytes)).

         o  The initial cwnd after a retransmission timeout MUST be no more
         than 1*MTU.

         o  The initial value of ssthresh MAY be arbitrarily high (for
         example, implementations MAY use the size of the receiver
         advertised window).
         */
        association.cwnd = Math.min(4 * association.PMTU, Math.max(2 * association.PMTU, 4380));
        association.lastTime = new Date();
        association.flightsize = 0;

        association.SSN = {};
        /*
         Receiver Window (rwnd): An SCTP variable a data sender uses to
         store the most recently calculated receiver window of its peer, in
         number of bytes.  This gives the sender an indication of the space
         available in the receiver's inbound buffer.
         */
        association.track = [];
        association.fastRecovery = false;
        association.readBuffer = [];
        association.duplicates = [];
        association.everSentSack = false;
        association.packetsSinceLastSack = 0;
        association.bundleQueue = [];
        association.sentChunks = {};
        association.state = 'IDLE';
        association.peerCumulativeTSN = SerialNumber(association.peerInitialTSN).prev();
        association.peerMaxTSN = association.peerCumulativeTSN.copy();
        association.peerTrackTSN = association.peerCumulativeTSN.copy();
        if (!association.myTag) association.myTag = _.random(0, 0xffffffff);
        association.tsn = SerialNumber(association.myTag);
        association.HTNA = association.tsn.copy();
        if (!association.myRwnd) association.myRwnd = defs.net_sctp.RWND;

        //association.on('chunk', function (chunk, header) {
        //})

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

                var tsn = SerialNumber(chunk.tsn);
                var isDuplicate = false;
                var zeroRwndDrop = false;
                if (association.myRwnd <= 0 && tsn.gt(association.peerMaxTSN)) {
                    /*
                     When the receiver's advertised window is 0, the receiver MUST drop
                     any new incoming DATA chunk with a TSN larger than the largest TSN
                     received so far.

                     If the new incoming DATA chunk holds a TSN value
                     less than the largest TSN received so far, then the receiver SHOULD
                     drop the largest TSN held for reordering and accept the new incoming
                     DATA chunk.
                     */
                    zeroRwndDrop = true;
                } else {
                    var isLast = tsn.gt(association.peerMaxTSN);
                    if (isLast) {
                        association.peerMaxTSN = tsn;
                    }
                    var offset = tsn.delta(association.peerTrackTSN);
                    if (offset <= 0 || association.track[offset - 1]) {
                        isDuplicate = true;
                        if (association.duplicates.length < MAX_DUPLICATES_LENGTH) {
                            association.duplicates.push(chunk.tsn);
                        }
                    } else {
                        association.track[offset - 1] = chunk;
                        association.myRwnd -= chunk.user_data.length;
                        if (isLast && !chunk.flags.E) {
                            // don't scan yet
                        } else {
                            association._scan(offset);
                        }
                        if (tsn.gt(association.peerCumulativeTSN)) {
                            association._updateCumulative();
                        }
                        if (chunk.packet) {
                            association.packetsSinceLastSack++;
                        }
                    }
                }
                var haveGaps = association.peerCumulativeTSN.lt(association.peerMaxTSN);
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
                        cumulative_tsn_ack: association.peerCumulativeTSN.getNumber()
                    });
                    if (!(haveGaps || isDuplicate)) {
                        return;
                    }
                }
                var timeout = 0;
                if (association.packetsSinceLastSack >= defs.net_sctp.sack_freq // every 2nd packet
                    || !association.everSentSack // first data chunk
                    || haveGaps
                    || isDuplicate
                    || zeroRwndDrop
                ) {
                    // for all such we do sack immediately
                    if (association._sackTimeout) {
                        // if have timer, cancel it and set new one with value 0
                        clearTimeout(association._sackTimeout);
                        delete association._sackTimeout;
                    }
                    // some street magic to achieve prompt sack, but still bundled
                    association.sacks++;
                    if (association.sacks > 1) {
                        setImmediate(function () {
                            association._sack()
                        })
                    } else {
                        setTimeout(function () {
                            association._sack()
                        }, 0);
                    }
                } else {
                    // normally set timeout 200 ms
                    timeout = defs.net_sctp.sack_timeout;
                }

                if (timeout && !association._sackTimeout) {
                    association._sackTimeout = setTimeout(function () {
                        delete association._sackTimeout;
                        if (timeout) {
                        }
                        association._sack()
                    }, timeout)
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

            //var count = _.keys(association.sentChunks).length;
            association.peerRwnd = chunk.a_rwnd;

            var cumulativeTsnAck = SerialNumber(chunk.cumulative_tsn_ack);
            var ackAdvanced = association.cumulativeTsnAck ? cumulativeTsnAck.gt(association.cumulativeTsnAck) : true;
            association.cumulativeTsnAck = cumulativeTsnAck.copy();

            if (association.fastRecovery && cumulativeTsnAck.ge(association.fastRecoveryExitPoint)) {
                association.fastRecovery = false;
                association.fastRecoveryExitPoint = null;
            }
            var flightsize = association.flightsize;
            _.each(association.sentChunks, function (item, key) {
                var t = SerialNumber(key);
                if (t.le(association.cumulativeTsnAck)) {
                    association._acknowledge(t)
                }
            });
            if (chunk.sack_info && chunk.sack_info.gap_blocks && chunk.sack_info.gap_blocks.length) {
                /*
                 Whenever an endpoint receives a SACK that indicates that some TSNs
                 are missing, it SHOULD wait for two further miss indications (via
                 subsequent SACKs for a total of three missing reports) on the same
                 TSNs before taking action with regard to Fast Retransmit.
                 */

                var absent = [];
                var tmp = [];
                _.each(chunk.sack_info.gap_blocks, function (block, index) {
                    absent.push({
                        start: SerialNumber(index ? chunk.cumulative_tsn_ack + chunk.sack_info.gap_blocks[index - 1].finish + 1 : chunk.cumulative_tsn_ack + 1),
                        finish: SerialNumber(chunk.cumulative_tsn_ack + block.start - 1)
                    });
                    tmp.push({
                        start: index ? chunk.cumulative_tsn_ack + chunk.sack_info.gap_blocks[index - 1].finish + 1 : chunk.cumulative_tsn_ack + 1,
                        finish: chunk.cumulative_tsn_ack + block.start - 1
                    });
                    for (var t = association.cumulativeTsnAck.copy().inc(block.start); t.le(association.cumulativeTsnAck.copy().inc(block.finish)); t.inc(1)) {
                        if (association.sentChunks[t.getNumber()]) {
                            association._acknowledge(t)
                        }
                    }
                });
                // 7.2.4.  Fast Retransmit on Gap Reports
                /*
                 Whenever an endpoint receives a SACK that indicates that some TSNs
                 are missing, it SHOULD wait for two further miss indications (via
                 subsequent SACKs for a total of three missing reports) on the same
                 TSNs before taking action with regard to Fast Retransmit.
                 */
                var doFastRetransmit = false;
                _.each(absent, function (block) {
                    for (var tsn = block.start.copy(); tsn.le(block.finish); tsn.inc(1)) {
                        var tsnNum = tsn.getNumber();
                        if (association.sentChunks[tsnNum]) {
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
                            if (tsn.lt(association.HTNA) || association.fastRecovery && ackAdvanced) {
                                association.sentChunks[tsnNum].losses++;
                                if (association.sentChunks[tsnNum].losses >= 3) {
                                    /*
                                     Mark the DATA chunk(s) with three miss indications for
                                     retransmission.

                                     A straightforward implementation of the above keeps a counter for
                                     each TSN hole reported by a SACK.  The counter increments for each
                                     consecutive SACK reporting the TSN hole.  After reaching 3 and
                                     starting the Fast-Retransmit procedure, the counter resets to 0.
                                     */
                                    association.sentChunks[tsnNum].losses = 0;
                                    association.sentChunks[tsnNum].fastRetransmit = true;
                                    doFastRetransmit = true;
                                }
                            }
                        }
                    }
                });
                if (doFastRetransmit) {
                    association._fastRetransmit();
                }

                /*
                 Whenever a SACK is received missing a TSN that was previously
                 acknowledged via a Gap Ack Block, start the T3-rtx for the
                 destination address to which the DATA chunk was originally
                 transmitted if it is not already running.
                 */
            } else {
                if (association.tsn.eq(association.cumulativeTsnAck.copy().inc(1))) {
                    /*
                     Whenever all outstanding data sent to an address have been
                     acknowledged, turn off the T3-rtx timer of that address.
                     */
                    association.flightsize = 0;
                    association._stopT3();
                    if (association.state == 'SHUTDOWN-PENDING') {
                        association._shutdown();
                        return;
                    }
                }
            }
            if (chunk.sack_info && chunk.sack_info.duplicate_tsn && chunk.sack_info.duplicate_tsn.length) {
            }
            if (ackAdvanced && association.flightsize) {
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
                if (association.cwnd <= association.ssthresh
                    && association.cwnd <= association.flightsize
                    && !association.fastRecovery) {
                    var totalAcknowledgedSize = flightsize - association.flightsize;
                    var cwndIncrease = Math.min(totalAcknowledgedSize, association.PMTU);
                    association.cwnd += cwndIncrease;
                }

                /*
                 Whenever a SACK is received that acknowledges the DATA chunk
                 with the earliest outstanding TSN for that address, restart the
                 T3-rtx timer for that address with its current RTO (if there is
                 still outstanding data on that address).
                 */
                association._restartT3()
            }
            if (association.flightsize && association.flightsize < association.cwnd) {
                association._retransmit();
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
                clearTimeout(association.T1);
                association.peerTag = chunk.initiate_tag;
                if (chunk.inbound_streams) {
                    association.OS = chunk.inbound_streams;
                } else {
                    /*
                     Note: A receiver of an INIT ACK with the MIS value set to 0 SHOULD
                     destroy the association discarding its TCB.
                     */
                    association._destroy();
                    return;
                }
                association.peerRwnd = chunk.a_rwnd;
                /*The initial value of ssthresh MAY be arbitrarily high (for
                 example, implementations MAY use the size of the receiver
                 advertised window).*/
                association.ssthresh = chunk.a_rwnd;
                association.peerInitialTSN = chunk.initial_tsn;
                association.peerCumulativeTSN = SerialNumber(association.peerInitialTSN).prev();
                association.peerMaxTSN = association.peerCumulativeTSN.copy();
                association.peerTrackTSN = association.peerCumulativeTSN.copy();

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
                association.state = 'ESTABLISHED';
                association._enableHeartbeat();
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
                return;
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
            association._down();
            //  todo check cumulative_tsn_ack
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

    _scan() {
        var association = this;
        var max = association.peerMaxTSN.delta(association.peerTrackTSN) - 1;
        var res = null;
        for (var i = 0; i <= max; i++) {
            var chunk = association.track[i];
            if (_.isObject(chunk)) {
                if (chunk.flags.B) {
                    // begin new probable reassemble

                    if (chunk.flags.U || SerialNumber(chunk.stream_sequence_number).eq(association.peerSSN[chunk.stream_identifier])) {
                        if (!chunk.flags.E) {
                        }
                        res = {
                            stream: chunk.stream_identifier,
                            ssn: chunk.stream_sequence_number,
                            data: [chunk.user_data],
                            idx: [i]
                        };
                    } else {
                    }
                }
                if (res && (chunk.flags.B || res.stream == chunk.stream_identifier && res.ssn == chunk.stream_sequence_number)) {
                    if (!chunk.flags.B) {
                        res.data.push(chunk.user_data);
                        res.idx.push(i);
                    }
                    if (chunk.flags.E) {
                        if (!chunk.flags.U) {
                            association.peerSSN[res.stream].inc(1);
                        }
                        association._deliver(Buffer.concat(res.data), res.stream);
                        res.idx.forEach(function (i) {
                            association.track[i] = true;
                        });
                        association._updateTrack();
                    }
                } else {
                    res = null;
                }
            } else {
                res = null;
            }
        }
    }

    _updateTrack() {
        var association = this;
        var offsetTracking;
        var max = association.peerMaxTSN.delta(association.peerTrackTSN);
        for (var i = 0; i < max; i++) {
            if (association.track[i] === true) {
                offsetTracking = i + 1;
            } else {
                break;
            }
        }
        if (offsetTracking) {
            association.peerTrackTSN.inc(offsetTracking);
            association.track.splice(0, offsetTracking);
        }
    }

    _updateCumulative1() {
        var association = this;
        var max = association.peerMaxTSN.delta(association.peerCumulativeTSN);
        var delta = association.peerCumulativeTSN.delta(association.peerTrackTSN);
        var offsetCumulative;
        for (var i = 0; i < max; i++) {
            if (association.track[i + delta]) {
                offsetCumulative = i + 1;
            } else {
                break;
            }
        }
        if (offsetCumulative) {
            association.peerCumulativeTSN.inc(offsetCumulative);
        }
    }

    _updateCumulative() {
        var association = this;
        var max = association.peerMaxTSN.delta(association.peerTrackTSN);
        association.peerCumulativeTSN = association.peerTrackTSN.copy();
        var offsetCumulative;
        for (var i = 0; i < max; i++) {
            if (association.track[i]) {
                offsetCumulative = i + 1;
            } else {
                break;
            }
        }
        if (offsetCumulative) {
            association.peerCumulativeTSN.inc(offsetCumulative);
        }
    }


    _sack() {
        var association = this;
        association.sacks--;
        if (association.sacks > 0) {
            return;
        }
        var gap_blocks = [];
        var max = association.peerMaxTSN.delta(association.peerCumulativeTSN);
        var offset = association.peerCumulativeTSN.delta(association.peerTrackTSN);
        var start;
        var finish;
        var gap;
        for (var i = 0; i <= max; i++) {
            var chunk = association.track[i + offset];
            if (chunk) {
                if (gap && !start) start = i;
                //gap = false;
            } else {
                gap = true;
                if (start) {
                    gap_blocks.push({
                        start: start + 1,
                        finish: i
                    });
                    start = null;
                    finish = null;
                }
            }
        }
        var sackOptions = {
            a_rwnd: association.myRwnd > 0 ? association.myRwnd : 0,
            cumulative_tsn_ack: association.peerCumulativeTSN.getNumber()
        };
        if (gap_blocks || association.duplicates.length) {
            sackOptions.sack_info = {
                gap_blocks: gap_blocks,
                duplicate_tsn: association.duplicates
            };
        }
        association.sack(sackOptions);
        if (!association.everSentSack) association.everSentSack = true;
        association.duplicates = [];
        association.packetsSinceLastSack = 0;
    }

    _acknowledge(tsn) {
        var association = this;
        association.flightsize -= association.sentChunks[tsn.getNumber()].size;
        if (!association.HTNA || tsn.gt(association.HTNA)) {
            association.HTNA = tsn.copy();
        }
        delete association.sentChunks[tsn.getNumber()];
        // RTO calculation
        if (association.rtoPending && association.rtoPending.tsn.eq(tsn)) {
            association._updateRTO(new Date() - association.rtoPending.sent);
            association.rtoPending = false;
        }
    }

    _updateRTO(R) {
        var association = this;
        if (!association.SRTT) {
            association.SRTT = R;
            association.RTTVAR = R / 2;
            association.RTTVAR = Math.max(association.RTTVAR, defs.net_sctp.G);
            association.RTO = association.SRTT + 4 * association.RTTVAR;
        } else {
            var alpha = 1 / defs.net_sctp.rto_alpha_exp_divisor;
            var beta = 1 / defs.net_sctp.rto_beta_exp_divisor;
            association.RTTVAR = (1 - beta) * association.RTTVAR + beta * Math.abs(association.SRTT - R);
            association.RTTVAR = Math.max(association.RTTVAR, defs.net_sctp.G);
            association.SRTT = (1 - alpha) * association.SRTT + alpha * R;
            association.RTO = association.SRTT + 4 * association.RTTVAR;
        }
        if (association.RTO < defs.net_sctp.rto_min) association.RTO = defs.net_sctp.rto_min;
        if (association.RTO > defs.net_sctp.rto_max) association.RTO = defs.net_sctp.rto_max;
    }

    _expireT3() {
        var association = this;
        association.T3 = null;
        if (_.keys(association.sentChunks).length === 0) {
            process.exit();
            return;
        }
        //if (association.peerRwnd == 0) {
        //    return;
        //}

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
        association.ssthresh = Math.max(association.cwnd / 2, 4 * association.PMTU);
        association.cwnd = association.PMTU;
        /*
         E2)  For the destination address for which the timer expires, set RTO
         <- RTO * 2 ("back off the timer").  The maximum value discussed
         in rule C7 above (RTO.max) may be used to provide an upper bound
         to this doubling operation.
         */
        if (association.RTO < defs.net_sctp.rto_max) {
            association.RTO *= 2;
            if (association.RTO > defs.net_sctp.rto_max) {
                association.RTO = defs.net_sctp.rto_max
            }
        }
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
        var bundledLength = 20;
        var bundledCount = 0;
        var tsns = [];
        _.some(association.sentChunks, function (chunk) {
            if (bundledLength + chunk.user_data.length + 16 > association.PMTU) {
                /*
                 Note: Any DATA chunks that were sent to the address for which the
                 T3-rtx timer expired but did not fit in one MTU (rule E3 above)
                 should be marked for retransmission and sent as soon as cwnd allows
                 (normally, when a SACK arrives).
                 */
                chunk.retransmit = true;
            } else {
                bundledCount++;
                bundledLength += chunk.user_data.length + 16;
                tsns.push(chunk.tsn);
                association.data(chunk);
            }
        });
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
            association._startT3();
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
        var association = this;
        _.some(association.sentChunks, function (chunk) {
            if (chunk.retransmit) {
                association.data(chunk)
            }
        })
    }

    _startT3() {
        var association = this;
        if (association.T3) {
            return;
        }
        association.T3 = setTimeout(association._expireT3.bind(association), association.RTO)
    }

    _stopT3() {
        var association = this;
        if (association.T3) {
            clearTimeout(association.T3);
            association.T3 = null
        }
    }

    _restartT3() {
        this._stopT3();
        this._startT3()
    }

    _fastRetransmit() {
        var association = this;
        /*
         Note: Before the above adjustments, if the received SACK also
         acknowledges new DATA chunks and advances the Cumulative TSN Ack
         Point, the cwnd adjustment rules defined in Section 7.2.1 and Section
         7.2.2 must be applied first.
         */
        if (!association.fastRecovery) {
            /*
             If not in Fast Recovery, adjust the ssthresh and cwnd of the
             destination address(es) to which the missing DATA chunks were
             last sent, according to the formula described in Section 7.2.3.

             ssthresh = max(cwnd/2, 4*MTU)
             cwnd = ssthresh
             partial_bytes_acked = 0

             Basically, a packet loss causes cwnd to be cut in half.
             */
            association.ssthresh = Math.max(association.cwnd / 2, 4 * association.PMTU);
            association.cwnd = association.ssthresh;
            association.partial_bytes_acked = 0;
            /*
             If not in Fast Recovery, enter Fast Recovery and mark the highest
             outstanding TSN as the Fast Recovery exit point.  When a SACK
             acknowledges all TSNs up to and including this exit point, Fast
             Recovery is exited.  While in Fast Recovery, the ssthresh and
             cwnd SHOULD NOT change for any destinations due to a subsequent
             Fast Recovery event (i.e., one SHOULD NOT reduce the cwnd further
             due to a subsequent Fast Retransmit).
             */
            association.fastRecovery = true;
            association.fastRecoveryExitPoint = association.tsn.prev();
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
        var bundledLength = 20 + 16;
        var bundledCount = 0;
        var tsns = [];
        _.some(association.sentChunks, function (chunk) {
            if (chunk.fastRetransmit) {
                if (bundledLength + chunk.user_data.length + 16 > association.PMTU) {
                    return true
                } else {
                    bundledCount++;
                    bundledLength += chunk.user_data.length + 16;
                    tsns.push(chunk.tsn);
                    association.data(chunk);
                }
            }
        });
        /*
         4)  Restart the T3-rtx timer only if the last SACK acknowledged the
         lowest outstanding TSN number sent to that address, or the
         endpoint is retransmitting the first outstanding DATA chunk sent
         to that address.
         */
        if (bundledCount > 0) association._restartT3();
    }

    _down() {
        var association = this;
        clearInterval(association._heartbeatInterval);
        clearTimeout(association.T1);
        clearTimeout(this._sackTimeout)
    }

    _enableHeartbeat() {
        var association = this;
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
            var multihoming = false;
            if (multihoming) {
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

    _bundle() {
        var association = this;
        if (association.state === 'CLOSED') return;
        if (association.bundleQueue.length === 0) return;
        association.bundling--;
        if (association.bundling > 0) {
            return;
        }
        var callbacks = [];
        var bundledChunks = [];
        var bundledLength = 20 + 16;
        var mtu = association.PMTU;
        association.bundleQueue.push(null);
        var emulateLoss = false;
        var haveCookieEcho = false;
        var haveData = false;
        var tsns = [];
        association.bundleQueue.forEach(function (chunk, index) {
            if (index == association.bundleQueue.length - 1 || bundledLength + chunk.size > mtu) {
                if (bundledChunks.length > 0) {
                    //emulateLoss = (haveData && _.random(1, 10) == 10);
                    if (emulateLoss) {
                    } else {
                        association._sendPacket(bundledChunks, callbacks);
                    }
                    if (haveData) association._startT3();
                    bundledChunks = [];
                    callbacks = [];
                    tsns = [];
                    bundledLength = 20 + 16;
                    haveCookieEcho = false;
                    haveData = false;
                }
            }
            var buffer;
            if (chunk === null) return;
            if (chunk.size > mtu) {
                return;
            }
            if (chunk.chunkType == 'data') {
                haveData = true;
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
                    chunk.tsn = association.tsn.getNumber();
                    association.tsn.inc(1);

                }
                if (!association.rtoPending) {
                    association.rtoPending = {
                        tsn: SerialNumber(chunk.tsn),
                        sent: new Date()
                    }
                }
                buffer = chunk.toBuffer();
                tsns.push(chunk.tsn);
                chunk.losses = 0;
                association.sentChunks[chunk.tsn] = chunk;
                association.flightsize += buffer.length;
            } else {
                buffer = chunk.buffer;
                delete chunk.buffer;
                if (chunk.chunkType == 'cookie_echo') {
                    haveCookieEcho = true
                }
            }
            bundledChunks.push(buffer);
            bundledLength += buffer.length;
            callbacks.push(chunk.callback);
        });
        association.bundleQueue = []
    }

    _shutdown() {
        var association = this;
        association._down();
        association.shutdown({
            cumulative_tsn_ack: association.peerCumulativeTSN.getNumber()
        }, function () {
            /*
             It shall then start the T2-shutdown timer and enter the SHUTDOWN-SENT
             state.  If the timer expires, the endpoint must resend the SHUTDOWN
             with the updated last sequential TSN received from its peer.
             The rules in Section 6.3 MUST be followed to determine the proper
             timer value for T2-shutdown.
             */
            association.state = 'SHUTDOWN-SENT';
            if (_.isFunction(association.shutdownCallback)) {
                association.shutdownCallback()
            }
        });
        /*
         The sender of the SHUTDOWN MAY also start an overall guard timer
         'T5-shutdown-guard' to bound the overall time for the shutdown
         sequence.  At the expiration of this timer, the sender SHOULD abort
         the association by sending an ABORT chunk.  If the 'T5-shutdown-
         guard' timer is used, it SHOULD be set to the recommended value of 5
         times 'RTO.Max'.
         */
        association.T5 = setTimeout(function () {
            association.abort();
        }, defs.net_sctp.rto_max * 5)
    }

    _destroy() {
        var association = this;
        association.state = 'CLOSED';
        clearTimeout(association.T3);
        clearTimeout(association.T5);
        if (association.endpoint)
            _.remove(association.endpoint._associations, association);
        delete association.endpoint;
    }

    SHUTDOWN(callback) {
        /*
         Format: SHUTDOWN(association id)
         -> result
         */

        var association = this;
        if (association.state === 'SHUTDOWN-RECEIVED') {
            return
        }
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
        association.shutdownCallback = callback;
        association._shutdown();
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
        var error = false;
        if (association.state === 'SHUTDOWN-PENDING' || association.state === 'SHUTDOWN-RECEIVED') {
            /*
             Upon receipt of the SHUTDOWN primitive from its upper layer, the endpoint enters the SHUTDOWN-PENDING state ... accepts no new data from its upper layer
             Upon reception of the SHUTDOWN, the peer endpoint shall enter the SHUTDOWN-RECEIVED state, stop accepting new data from its SCTP user
             */
            error = 'state';
        } else if (buffer.length >= association.peerRwnd) {
            /*
             At any given time, the data sender MUST NOT transmit new data to
             any destination transport address if its peer's rwnd indicates
             that the peer has no buffer space (i.e., rwnd is 0; see Section
             6.2.1).
             */
            error = 'peerRwnd';
        } else if (association.flightsize >= association.cwnd) {
            /*
             At any given time, the sender MUST NOT transmit new data to a
             given transport address if it has cwnd or more bytes of data
             outstanding to that transport address.
             */
            error = 'flightsize';
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

        if (error) {
        } else {
            /*
             Before an endpoint transmits a DATA chunk, if any received DATA
             chunks have not been acknowledged (e.g., due to delayed ack), the
             sender should create a SACK and bundle it with the outbound DATA
             chunk, as long as the size of the final SCTP packet does not exceed
             the current MTU.  See Section 6.2.
             */
            if (association._sackTimeout) {
                clearTimeout(association._sackTimeout);
                delete association._sackTimeout;
                association._sack();
            }
            /*
             C) When the time comes for the sender to transmit, before sending new
             DATA chunks, the sender MUST first transmit any outstanding DATA
             chunks that are marked for retransmission (limited by the current
             cwnd).
             */
            association._retransmit();
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
            if (association.flightsize + defs.net_sctp.max_burst * association.PMTU < association.cwnd) {
                association.cwnd = association.flightsize + defs.net_sctp.max_burst * association.PMTU;
            }
            var chunk;
            var stream = options.stream || 0;
            if (stream < 0 || stream > association.OS) {
                return;
            }
            if (!association.SSN[stream]) association.SSN[stream] = SerialNumber(0, 16);
            var mtu = association.PMTU - 16 - 16 - 20;
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
                        stream_identifier: stream,
                        stream_sequence_number: association.SSN[stream].getNumber(),
                        payload_protocol_identifier: options.protocol,
                        user_data: buffer.slice(offset, offset + mtu)
                    };
                    offset += mtu;
                    association.data(chunk);
                }
            } else {
                chunk = {
                    flags: {
                        "E": 1,
                        "B": 1,
                        "U": options.unordered,
                        "I": 0
                    },
                    stream_identifier: stream,
                    stream_sequence_number: association.SSN[stream].getNumber(),
                    payload_protocol_identifier: options.protocol,
                    user_data: buffer
                };
                association.data(chunk)
            }
            association.SSN[stream].inc(1);
        }
        if (_.isFunction(callback)) {
            callback(error)
        }
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


_.forEach(defs.chunkdefs, function (chunk, chunkType) {
    Association.prototype[chunkType] = function (options, callback) {
        var association = this;
        var chunk = new Chunk(chunkType, options);
        if (chunkType === 'init' || chunkType === 'init_ack' || chunkType === 'shutdown_complete') {
            // no bundle
            setTimeout(function () {
                // use nextTick to be in order with bundled chunks
                var buffer = chunk.toBuffer();
                association._sendPacket([buffer], [callback])
            }, 0)
        } else {
            chunk.callback = callback;
            if (chunkType == 'data') {
                chunk.size = chunk.user_data.length + 16;
            } else {
                chunk.buffer = chunk.toBuffer();
                chunk.size = chunk.buffer.length;
            }
            association.bundleQueue.push(chunk);
            association.bundling++;
            association._bundleTimout = setTimeout(association._bundle.bind(association), 0);
        }
    }
});


function INITIALIZE(options) {
    var endpoint = new Endpoint(options);
    return internet.takePort(endpoint)
}


module.exports.INITIALIZE = INITIALIZE;
module.exports.Association = Association;
