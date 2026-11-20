package mta

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
)

// Reply is one SMTP reply, or the engine's stand-in for one.
type Reply struct {
	// Code is the three-digit reply code; 0 when no server answered and the
	// engine has no number to give.
	Code int
	// Enhanced is the RFC 3463 status code, "5.1.1", when the server sent one
	// or the engine chose one.
	Enhanced string
	// Text is the reply text with the enhanced code removed and a multi-line
	// reply joined by single spaces.
	Text string
	// Local is true when the engine produced the reply itself.
	Local bool
}

func (r Reply) class() byte {
	if r.Code >= 200 && r.Code < 600 {
		return byte('0' + r.Code/100)
	}
	if len(r.Enhanced) > 0 {
		return r.Enhanced[0]
	}
	return 0
}

func localReply(code int, enhanced, text string) Reply {
	return Reply{Code: code, Enhanced: enhanced, Text: text, Local: true}
}

// ErrBadReply is returned by ParseReplyLine for a line that is not an SMTP
// reply line.
var ErrBadReply = errors.New("mta: malformed SMTP reply line")

// ParseReplyLine reads one line of an SMTP reply, "250-text" or "250 text",
// with or without its line ending. last is true for the final line of a reply
// (a space or nothing after the code). text aliases line and has the line
// ending removed. A code is three digits starting with 2, 3, 4 or 5.
func ParseReplyLine(line []byte) (code int, last bool, text []byte, err error) {
	line = bytes.TrimRight(line, "\r\n")
	if len(line) < 3 {
		return 0, false, nil, ErrBadReply
	}
	c0, c1, c2 := line[0], line[1], line[2]
	if c0 < '2' || c0 > '5' || c1 < '0' || c1 > '9' || c2 < '0' || c2 > '9' {
		return 0, false, nil, ErrBadReply
	}
	code = int(c0-'0')*100 + int(c1-'0')*10 + int(c2-'0')
	if len(line) == 3 {
		return code, true, nil, nil
	}
	switch line[3] {
	case ' ':
		return code, true, line[4:], nil
	case '-':
		return code, false, line[4:], nil
	}
	return 0, false, nil, ErrBadReply
}

// ParseEnhancedStatus splits an RFC 3463 enhanced status code off the front of
// reply text: "5.1.1 User unknown" gives "5.1.1" and "User unknown". Text that
// does not start with a code, class 2, 4 or 5, subject and detail of one to
// three digits, followed by a space or the end, is returned whole with ok
// false.
func ParseEnhancedStatus(text string) (status, rest string, ok bool) {
	n := len(text)
	if n < 5 || (text[0] != '2' && text[0] != '4' && text[0] != '5') || text[1] != '.' {
		return "", text, false
	}
	i := 2
	digits := func() int {
		start := i
		for i < n && i-start < 3 && text[i] >= '0' && text[i] <= '9' {
			i++
		}
		return i - start
	}
	if digits() == 0 || i >= n || text[i] != '.' {
		return "", text, false
	}
	i++
	if digits() == 0 {
		return "", text, false
	}
	if i < n && text[i] != ' ' {
		return "", text, false
	}
	status = text[:i]
	if i < n {
		i++
	}
	return status, text[i:], true
}

// buildReply makes a Reply from a code and the text lines of a reply, joined
// by '\n'. The enhanced code is taken from the first line and, when the other
// lines repeat it, removed from them.
func buildReply(code int, text []byte) Reply {
	r := Reply{Code: code}
	if len(text) == 0 {
		return r
	}
	s := string(text)
	enh, rest, ok := ParseEnhancedStatus(firstLine(s))
	if ok && enh[0] != byte('0'+code/100) {
		ok = false // the class of the enhanced code must agree with the reply code
	}
	if !strings.Contains(s, "\n") {
		if ok {
			r.Enhanced, r.Text = enh, rest
		} else {
			r.Text = s
		}
		return r
	}
	lines := strings.Split(s, "\n")
	if ok {
		r.Enhanced = enh
	}
	var b strings.Builder
	for i, l := range lines {
		if ok {
			if e2, rest2, ok2 := ParseEnhancedStatus(l); ok2 && e2 == enh {
				l = rest2
			}
		}
		if i > 0 && l != "" {
			b.WriteByte(' ')
		}
		b.WriteString(l)
	}
	r.Text = b.String()
	return r
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// Capabilities are the ESMTP extensions a server announced in its EHLO reply.
type Capabilities struct {
	STARTTLS     bool
	Pipelining   bool
	EightBitMIME bool
	SMTPUTF8     bool
	Chunking     bool
	// EnhancedStatusCodes is true when the server uses RFC 3463 codes.
	EnhancedStatusCodes bool
	// Size is the largest message the server accepts, in bytes; 0 when it
	// announced none or announced no limit.
	Size int64
	// Greeting is the first line of the reply, the server's name.
	Greeting string
}

// ParseEHLO reads the text of a multi-line EHLO reply, one line per extension
// with the lines joined by '\n'. The first line is the greeting; every other
// line is an extension keyword with its parameters, in any case. Unknown
// keywords and malformed parameters are ignored, never an error.
func ParseEHLO(text string) Capabilities {
	var c Capabilities
	first := true
	for text != "" {
		var line string
		if i := strings.IndexByte(text, '\n'); i >= 0 {
			line, text = text[:i], text[i+1:]
		} else {
			line, text = text, ""
		}
		line = strings.TrimSpace(line)
		if first {
			first = false
			if sp := strings.IndexByte(line, ' '); sp >= 0 {
				c.Greeting = line[:sp]
			} else {
				c.Greeting = line
			}
			continue
		}
		key, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(key) {
		case "STARTTLS":
			c.STARTTLS = true
		case "PIPELINING":
			c.Pipelining = true
		case "8BITMIME":
			c.EightBitMIME = true
		case "SMTPUTF8":
			c.SMTPUTF8 = true
		case "CHUNKING":
			c.Chunking = true
		case "ENHANCEDSTATUSCODES":
			c.EnhancedStatusCodes = true
		case "SIZE":
			if n, err := strconv.ParseInt(strings.TrimSpace(arg), 10, 64); err == nil && n > 0 {
				c.Size = n
			}
		}
	}
	return c
}
