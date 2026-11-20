package unit_test

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	mta "github.com/hyz-is/arandu-mta"
)

func FuzzParseReplyLine(f *testing.F) {
	for _, s := range []string{"250 OK\r\n", "250-PIPELINING\r\n", "550 5.1.1 no\r\n", "", "25", "999 x", "250", "354 go", "421-\r\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, line []byte) {
		code, last, text, err := mta.ParseReplyLine(line)
		if err != nil {
			return
		}
		if code < 200 || code > 599 {
			t.Fatalf("code %d out of range for %q", code, line)
		}
		if bytes.HasSuffix(text, []byte("\n")) {
			t.Fatalf("text keeps its line ending: %q", text)
		}
		// What was parsed parses back the same.
		sep := "-"
		if last {
			sep = " "
		}
		again := append([]byte(strings.Join([]string{itoa(code), sep}, "")), text...)
		c2, l2, t2, err := mta.ParseReplyLine(again)
		if err != nil || c2 != code || l2 != last || !bytes.Equal(t2, text) {
			t.Fatalf("round trip of %q: %d %v %q %v", line, c2, l2, t2, err)
		}
	})
}

func FuzzParseEnhancedStatus(f *testing.F) {
	for _, s := range []string{"5.1.1 user unknown", "2.0.0", "", "5.1", "9.9.9 x", "4.7.0 Try later", "5.1.1x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		status, rest, ok := mta.ParseEnhancedStatus(in)
		if !ok {
			if status != "" || rest != in {
				t.Fatalf("a refusal must return the input whole: %q -> %q %q", in, status, rest)
			}
			return
		}
		if c := status[0]; c != '2' && c != '4' && c != '5' {
			t.Fatalf("class %q accepted", status)
		}
		if in != status && in != status+" "+rest {
			t.Fatalf("status and rest do not rebuild the input: %q + %q vs %q", status, rest, in)
		}
	})
}

func FuzzParseEHLO(f *testing.F) {
	f.Add("mx.example.com hi\nPIPELINING\nSIZE 100\nSTARTTLS")
	f.Add("")
	f.Add("x\nSIZE 99999999999999999999")
	f.Add("\n\n\n")
	f.Fuzz(func(t *testing.T, in string) {
		c := mta.ParseEHLO(in)
		if c.Size < 0 {
			t.Fatalf("negative size from %q", in)
		}
	})
}

func FuzzDecodeMeta(f *testing.F) {
	good, _ := mta.EncodeMeta(sample("fuzz-1"))
	f.Add(good)
	f.Add([]byte("MTA1 00000000\n{}"))
	f.Add([]byte("MTA1 zzzzzzzz\n"))
	f.Add([]byte{})
	f.Add(good[:len(good)/2])
	f.Fuzz(func(t *testing.T, in []byte) {
		m, err := mta.DecodeMeta(in)
		if err != nil {
			return
		}
		if !mta.ValidID(m.ID) || len(m.Recipients) == 0 {
			t.Fatalf("DecodeMeta accepted an unusable message: %+v", m)
		}
		for _, r := range m.Recipients {
			if r.State == mta.StateSending {
				t.Fatal("a Sending state must never come back from disk")
			}
		}
		enc, err := mta.EncodeMeta(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := mta.DecodeMeta(enc); err != nil {
			t.Fatalf("a decoded message does not survive being encoded again: %v", err)
		}
	})
}

func FuzzParseWarmupSchedule(f *testing.F) {
	for _, s := range []string{"50,100,200", "10,*", "", "a", "1,,2", "unlimited", " 5 , 6 "} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		w, err := mta.ParseWarmupSchedule(in)
		if err != nil {
			return
		}
		for _, d := range w.Days {
			if d < 1 {
				t.Fatalf("non-positive quota from %q", in)
			}
		}
		if w.Unlimited && len(w.Days) == 0 {
			t.Fatalf("unlimited without quota from %q", in)
		}
		for day := -1; day < 5; day++ {
			w.Quota(day) // must not panic
		}
	})
}

// normalizeLines is the reference: every line ends in CRLF, and the data ends
// with a line ending.
func normalizeLines(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}
	var out bytes.Buffer
	for _, l := range bytes.SplitAfter(in, []byte("\n")) {
		if len(l) == 0 {
			continue
		}
		l = bytes.TrimSuffix(l, []byte("\n"))
		l = bytes.TrimSuffix(l, []byte("\r"))
		out.Write(l)
		out.WriteString("\r\n")
	}
	return out.Bytes()
}

func FuzzWriteData(f *testing.F) {
	for _, s := range []string{"", "a", "a\r\n.b\r\n", ".\r\n.\r\n", "a\nb", "\r\n\r\n", "..", "x\r"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		var buf bytes.Buffer
		w := bufio.NewWriter(&buf)
		if err := mta.WriteData(w, in); err != nil {
			t.Fatal(err)
		}
		w.Flush()
		out := buf.Bytes()
		if !bytes.HasSuffix(out, []byte("\r\n.\r\n")) && string(out) != ".\r\n" {
			t.Fatalf("no terminator: %q", out)
		}
		// Undo the stuffing the way a server does and compare with the reference.
		var got bytes.Buffer
		r := bufio.NewReader(bytes.NewReader(out))
		for {
			line, err := r.ReadBytes('\n')
			if err != nil {
				t.Fatalf("data did not end with the terminator: %q", out)
			}
			if string(line) == ".\r\n" {
				break
			}
			if len(line) > 0 && line[0] == '.' {
				line = line[1:]
			}
			if !bytes.HasSuffix(line, []byte("\r\n")) || bytes.Contains(line[:len(line)-2], []byte("\n")) {
				t.Fatalf("a line without CRLF, or with a bare LF inside: %q", line)
			}
			got.Write(line)
		}
		if want := normalizeLines(in); !bytes.Equal(got.Bytes(), want) {
			t.Fatalf("unstuffed %q, want %q (input %q)", got.Bytes(), want, in)
		}
	})
}

func FuzzClassify(f *testing.F) {
	f.Add(550, "5.1.1", "user unknown")
	f.Add(421, "", "")
	f.Add(0, "x", "\x00")
	f.Add(-1, "5.7.1", "SPAM")
	f.Fuzz(func(t *testing.T, code int, enh, text string) {
		c := mta.DefaultClassifier{}.Classify(code, enh, text)
		if code >= 200 && code < 300 && (enh == "" || enh[0] == '2') && (c.Permanent || c.Throttle) {
			t.Fatalf("a 2xx reply classified as failure: %+v", c)
		}
		if c.Permanent && c.Throttle {
			t.Fatalf("throttling is temporary: %+v", c)
		}
		switch c.Type {
		case mta.BouncePermanent, mta.BounceTransient, mta.BounceUndetermined:
		default:
			t.Fatalf("unknown type %q", c.Type)
		}
		if c.Type == mta.BouncePermanent && !c.Permanent {
			t.Fatalf("a permanent bounce that is retried: %+v", c)
		}
	})
}

func FuzzMatchesMX(f *testing.F) {
	f.Add("mail.example.com", "mail.example.com")
	f.Add("*.example.com", "a.example.com")
	f.Add("*.", "x")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, pattern, host string) {
		p := mta.MTASTSPolicy{MX: []string{pattern}}
		got := p.MatchesMX(host)
		if !strings.HasPrefix(pattern, "*") && pattern != "" && strings.EqualFold(strings.TrimSuffix(pattern, "."), strings.TrimSuffix(host, ".")) && !got {
			if strings.TrimSuffix(host, ".") != "" {
				t.Fatalf("an exact pattern %q does not match %q", pattern, host)
			}
		}
		if got && host == "" {
			t.Fatal("empty host matched")
		}
	})
}

func FuzzAddress(f *testing.F) {
	for _, s := range []string{"a@b.c", "a@b.c\r\nRCPT TO:<x@y.z>", "<a@b.c>", "a@@b", "", "\x00@x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		if err := mta.ValidAddress(in); err != nil {
			return
		}
		// An address that passes can be put on an SMTP command line.
		for i := 0; i < len(in); i++ {
			if c := in[i]; c <= ' ' || c == 0x7f || c == '<' || c == '>' {
				t.Fatalf("accepted %q with byte 0x%02x", in, c)
			}
		}
		if _, ok := mta.DomainOf(in); !ok {
			t.Fatalf("a valid address %q without a domain", in)
		}
	})
}

func FuzzParsePriority(f *testing.F) {
	f.Add("marketing")
	f.Add("")
	f.Fuzz(func(t *testing.T, in string) {
		p, err := mta.ParsePriority(in)
		if err == nil && p != mta.PriorityTransactional && p != mta.PriorityMarketing {
			t.Fatalf("priority %d out of range", p)
		}
	})
}

// FuzzClientAgainstAServerThatSaysAnything feeds the engine's SMTP client
// arbitrary bytes as the server's side of the conversation. Whatever the bytes
// are, the engine must not panic or hang, and the recipient must get an event.
func FuzzClientAgainstAServerThatSaysAnything(f *testing.F) {
	f.Add([]byte("220 hi\r\n250-mx\r\n250 PIPELINING\r\n250 ok\r\n250 ok\r\n354 go\r\n250 done\r\n"))
	f.Add([]byte("220 hi\r\n250 mx\r\n550 no\r\n"))
	f.Add([]byte("garbage"))
	f.Add([]byte("220-a\r\n220-b\r\n220 c\r\n"))
	f.Add([]byte("220 x\r\n250 y\r\n250 a\r\n250 b\r\n421 bye\r\n"))
	f.Add(append([]byte("220 "), bytes.Repeat([]byte("A"), 20000)...))
	f.Add([]byte("220 hi\r\n250-mx\r\n250-SIZE 10\r\n250 8BITMIME\r\n"))
	f.Fuzz(func(t *testing.T, script []byte) {
		res := newFuzzResolver()
		events := &eventLog{}
		eng, err := mta.New(mta.Config{
			Spool: mta.NewMemorySpool(), Resolver: res, Events: events, Workers: 2, EHLOName: "mta.test",
			Backoff: mta.Backoff{Schedule: []time.Duration{time.Hour}, Jitter: -1}, Expiry: 48 * time.Hour,
			Timeouts: mta.Timeouts{Connect: time.Second, Greeting: 150 * time.Millisecond, Command: 150 * time.Millisecond, DataInit: 150 * time.Millisecond, DataBlock: 150 * time.Millisecond, DataTermination: 150 * time.Millisecond},
			Dial: func(ctx context.Context, _ mta.DialTarget) (net.Conn, error) {
				c, s := net.Pipe()
				go func() {
					defer s.Close()
					go io.Copy(io.Discard, s) // drain what the client writes
					s.SetWriteDeadline(time.Now().Add(300 * time.Millisecond))
					s.Write(script)
					time.Sleep(200 * time.Millisecond)
				}()
				return c, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := eng.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := eng.Shutdown(ctx); err != nil {
				t.Errorf("Shutdown: %v", err)
			}
		}()
		if err := eng.Submit(context.Background(), msg("fz", "a@fuzz.test")); err != nil {
			t.Fatal(err)
		}
		events.wait(t, "an event", func(ev []mta.Event) bool { return len(ev) > 0 })
	})
}

func FuzzResolvConf(f *testing.F) {
	f.Add("nameserver 192.0.2.1\nnameserver 2001:db8::1\n")
	f.Add("")
	f.Add("nameserver\nnameserver %%%\n\x00\xff")
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, content string) {
		path := dir + "/resolv.conf"
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		servers, err := mta.ResolvConfServers(path)
		if err != nil {
			return
		}
		for _, s := range servers {
			if _, err := netip.ParseAddrPort(s); err != nil {
				t.Fatalf("server %q is not host:port: %v", s, err)
			}
		}
	})
}

// FuzzDNSClientAgainstGarbage answers the client's queries with arbitrary
// bytes. It must return an error or an answer, never panic or hang.
func FuzzDNSClientAgainstGarbage(f *testing.F) {
	srv := startFakeDNSForFuzz(f)
	for _, q := range [][]byte{srv, {}, {0, 0}, bytes.Repeat([]byte{0xff}, 600), []byte("\x00\x01\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00")} {
		f.Add(q)
	}
	f.Fuzz(func(t *testing.T, garbage []byte) {
		c := &mta.DNSClient{
			Servers: []string{"192.0.2.1:53"}, Timeout: 100 * time.Millisecond, Attempts: 1,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				cl, sv := net.Pipe()
				go func() {
					defer sv.Close()
					buf := make([]byte, 4096)
					sv.SetDeadline(time.Now().Add(200 * time.Millisecond))
					n, _ := sv.Read(buf)
					out := garbage
					if len(out) >= 2 && n >= 2 {
						// Echo the query's ID half of the time, so the parser goes further.
						out = append([]byte{buf[0], buf[1]}, garbage[2:]...)
					}
					if network == "tcp" {
						out = append([]byte{byte(len(out) >> 8), byte(len(out))}, out...)
					}
					sv.Write(out)
				}()
				return cl, nil
			},
		}
		_, _ = c.LookupMX(context.Background(), "example.com")
		_, _ = c.LookupAddr(context.Background(), "example.com")
	})
}
