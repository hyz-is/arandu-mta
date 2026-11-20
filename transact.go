package mta

import (
	"strconv"
	"time"
)

// txn is one SMTP transaction: one envelope, several recipients, one message.
type txn struct {
	mailFrom string
	rcpts    []string
	data     []byte
}

func appendInt(dst []byte, n int64) []byte { return strconv.AppendInt(dst, n, 10) }

type txStep struct {
	kind cmdKind
	i    int // position in smtpConn.idx for kRCPT
}

// txRun is the state of the transaction a connection is running. It lives in
// the connection and is reused, so a transaction allocates nothing for it.
type txRun struct {
	c       *smtpConn
	replies []Reply
	o       *clientOpts

	steps     []txStep
	mailRep   Reply
	mailOK    bool
	accepted  int
	dataReply Reply
	dataOK    bool
	final     Reply
	haveFinal bool

	failStatus txStatus
	failWhy    Reply
	failErr    error
}

// readStep reads the reply to one command and records what it says. It returns
// false when the transaction cannot go on, with the failure in r.fail*.
func (r *txRun) readStep(s txStep) bool {
	c := r.c
	code, text, err := c.readReply()
	if err != nil {
		r.failStatus, r.failErr = txFail, err
		return false
	}
	switch s.kind {
	case kRSET:
		if code != 250 {
			c.broken = true
			r.failStatus, r.failWhy = txStale, buildReply(code, text)
			return false
		}
	case kMAIL:
		if code/100 == 2 {
			r.mailOK = true
			return true
		}
		r.mailRep = buildReply(code, text)
		if code == 421 {
			c.broken = true
			r.failStatus, r.failWhy = txFail, r.mailRep
			return false
		}
	case kRCPT:
		if code/100 == 2 {
			r.accepted++
			return true
		}
		r.replies[c.idx[s.i]] = buildReply(code, text)
		if code == 421 {
			c.broken = true
		}
	case kDATA:
		if code == 354 {
			r.dataOK = true
			return true
		}
		r.dataReply = buildReply(code, text)
		if code == 421 {
			c.broken = true
		}
	case kBDAT:
		r.final, r.haveFinal = buildReply(code, text), true
		if code == 421 {
			c.broken = true
		}
	}
	return true
}

// queue either remembers that a reply is owed, when commands are pipelined, or
// flushes and reads it at once.
func (r *txRun) queue(s txStep, pipelined bool) bool {
	if pipelined {
		r.steps = append(r.steps, s)
		return true
	}
	if err := r.c.bw.Flush(); err != nil {
		r.failStatus, r.failErr = txFail, err
		return false
	}
	return r.readStep(s)
}

// transact runs one transaction. replies has one entry per recipient and gets
// the final reply for each when the status is txDone. For txStale and txFail
// the returned reply, or the error, says why.
func (c *smtpConn) transact(t *txn, replies []Reply, o *clientOpts) (txStatus, Reply, error) {
	n := len(t.rcpts)
	for i := range replies[:n] {
		replies[i] = Reply{}
	}

	// Refuse locally what the server has said it cannot take.
	if c.caps.Size > 0 && int64(len(t.data)) > c.caps.Size {
		r := localReply(552, "5.3.4", "message of "+strconv.Itoa(len(t.data))+" bytes exceeds the size limit of "+strconv.FormatInt(c.caps.Size, 10)+" announced by "+c.host)
		for i := range replies[:n] {
			replies[i] = r
		}
		return txDone, Reply{}, nil
	}
	utf8 := hasNonASCII(t.mailFrom)
	if utf8 && !c.caps.SMTPUTF8 {
		r := localReply(553, "5.6.7", "sender address needs SMTPUTF8, which "+c.host+" does not offer")
		for i := range replies[:n] {
			replies[i] = r
		}
		return txDone, Reply{}, nil
	}
	c.idx, c.wire = c.idx[:0], c.wire[:0]
	for i, a := range t.rcpts {
		if hasNonASCII(a) {
			if c.caps.SMTPUTF8 {
				utf8 = true
			} else if w, ok := asciiAddress(a); ok {
				a = w
			} else {
				replies[i] = localReply(553, "5.6.7", "recipient address needs SMTPUTF8, which "+c.host+" does not offer")
				continue
			}
		}
		c.idx = append(c.idx, i)
		c.wire = append(c.wire, a)
	}
	if len(c.idx) == 0 {
		return txDone, Reply{}, nil
	}

	r := &c.run
	*r = txRun{c: c, replies: replies, o: o, steps: r.steps[:0]}

	pipelined := c.caps.Pipelining && !o.noPipelining
	useBDAT := o.chunking && c.caps.Chunking
	reuse := c.uses > 0

	c.setDeadline(o.timeouts.Command)

	// RSET, only on a connection that carried a transaction before.
	if reuse {
		_, _ = c.bw.WriteString("RSET\r\n")
		if !r.queue(txStep{kind: kRSET}, pipelined) {
			return c.finishFail(r.failStatus, r.failWhy, r.failErr, reuse)
		}
	}
	// MAIL FROM.
	_, _ = c.bw.WriteString("MAIL FROM:<")
	_, _ = c.bw.WriteString(t.mailFrom)
	_, _ = c.bw.WriteString(">")
	if c.caps.Size > 0 {
		var b [24]byte
		_, _ = c.bw.WriteString(" SIZE=")
		_, _ = c.bw.Write(appendInt(b[:0], int64(len(t.data))))
	}
	if c.caps.EightBitMIME && has8Bit(t.data) {
		_, _ = c.bw.WriteString(" BODY=8BITMIME")
	}
	if utf8 {
		_, _ = c.bw.WriteString(" SMTPUTF8")
	}
	_, _ = c.bw.WriteString("\r\n")
	if !r.queue(txStep{kind: kMAIL}, pipelined) {
		return c.finishFail(r.failStatus, r.failWhy, r.failErr, reuse)
	}
	if !pipelined && !r.mailOK {
		return c.failAll(replies, r.mailRep, true)
	}
	// RCPT TO.
	for i, a := range c.wire {
		_, _ = c.bw.WriteString("RCPT TO:<")
		_, _ = c.bw.WriteString(a)
		_, _ = c.bw.WriteString(">\r\n")
		if !r.queue(txStep{kind: kRCPT, i: i}, pipelined) {
			return c.finishFail(r.failStatus, r.failWhy, r.failErr, reuse)
		}
		if !pipelined && c.broken {
			return c.failRest(replies, buildReply(421, []byte("connection closed by server")))
		}
	}
	dataTimeout := o.timeouts.DataBlock * time.Duration(1+len(t.data)/(64<<10))
	switch {
	case useBDAT && pipelined:
		// RFC 3030 lets BDAT ride in the same batch as the envelope: the whole
		// transaction costs one round trip.
		c.writeBDAT(t.data)
		r.steps = append(r.steps, txStep{kind: kBDAT})
	case !useBDAT:
		_, _ = c.bw.WriteString("DATA\r\n")
		if !r.queue(txStep{kind: kDATA}, pipelined) {
			return c.finishFail(r.failStatus, r.failWhy, r.failErr, reuse)
		}
	}
	if pipelined {
		if useBDAT {
			c.setDeadline(dataTimeout)
		}
		if err := c.bw.Flush(); err != nil {
			if useBDAT {
				return c.dataLost(replies, err)
			}
			return c.finishFail(txFail, Reply{}, err, reuse)
		}
		if useBDAT {
			c.setDeadline(o.timeouts.DataTermination)
		}
		for _, s := range r.steps {
			if !r.readStep(s) {
				if useBDAT && s.kind == kBDAT {
					return c.dataLost(replies, r.failErr)
				}
				return c.finishFail(r.failStatus, r.failWhy, r.failErr, reuse)
			}
		}
	}

	if !r.mailOK {
		return c.failAll(replies, r.mailRep, true)
	}
	if c.broken && !r.haveFinal {
		return c.failRest(replies, buildReply(421, []byte("connection closed by server")))
	}
	if r.accepted == 0 {
		// Nothing was accepted, so nothing is sent. A reply to DATA that was
		// pipelined has been read already; a server in sync needs only RSET.
		c.uses++
		return txDone, Reply{}, nil
	}

	switch {
	case useBDAT && pipelined:
		// The final reply was read with the rest.
	case useBDAT:
		c.setDeadline(dataTimeout)
		c.writeBDAT(t.data)
		if err := c.bw.Flush(); err != nil {
			return c.dataLost(replies, err)
		}
		c.setDeadline(o.timeouts.DataTermination)
		code, text, err := c.readReply()
		if err != nil {
			return c.dataLost(replies, err)
		}
		r.final = buildReply(code, text)
	default:
		if !r.dataOK {
			// The server refused DATA: its reply is final for every recipient it
			// had accepted.
			for _, ri := range c.idx {
				if replies[ri].Code == 0 {
					replies[ri] = r.dataReply
				}
			}
			c.uses++
			return txDone, Reply{}, nil
		}
		c.setDeadline(dataTimeout)
		if err := WriteData(c.bw, t.data); err != nil {
			return c.dataLost(replies, err)
		}
		if err := c.bw.Flush(); err != nil {
			return c.dataLost(replies, err)
		}
		c.setDeadline(o.timeouts.DataTermination)
		code, text, err := c.readReply()
		if err != nil {
			return c.dataLost(replies, err)
		}
		r.final = buildReply(code, text)
	}
	if o.metrics != nil {
		o.metrics.BytesSent.Add(uint64(len(t.data)))
	}
	for _, ri := range c.idx {
		if replies[ri].Code == 0 {
			replies[ri] = r.final
		}
	}
	if r.final.Code == 421 {
		c.broken = true
	}
	c.uses++
	return txDone, Reply{}, nil
}

// writeBDAT buffers the one and only chunk of a message.
func (c *smtpConn) writeBDAT(data []byte) {
	var h [48]byte
	hdr := append(h[:0], "BDAT "...)
	hdr = appendInt(hdr, int64(len(data)))
	hdr = append(hdr, " LAST\r\n"...)
	_, _ = c.bw.Write(hdr)
	_, _ = c.bw.Write(data)
}
