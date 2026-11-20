package unit_test

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
	"time"

	mta "github.com/hyz-is/arandu-mta"
)

func TestParseReplyLine(t *testing.T) {
	type want struct {
		code int
		last bool
		text string
		bad  bool
	}
	for in, w := range map[string]want{
		"250 OK\r\n":               {250, true, "OK", false},
		"250-PIPELINING\r\n":       {250, false, "PIPELINING", false},
		"250\r\n":                  {250, true, "", false},
		"354 go ahead":             {354, true, "go ahead", false},
		"550 5.1.1 no such user\n": {550, true, "5.1.1 no such user", false},
		"421-closing\r\n":          {421, false, "closing", false},
		"250 ":                     {250, true, "", false},
		"":                         {bad: true},
		"25":                       {bad: true},
		"abc OK":                   {bad: true},
		"150 preliminary":          {bad: true},
		"650 nope":                 {bad: true},
		"250OK":                    {bad: true},
		"250_text":                 {bad: true},
		"2500 four digits":         {bad: true},
		"HTTP/1.1 200 OK\r\n":      {bad: true},
		"\x00\x00\x00 binary":      {bad: true},
		"250 caf\xc3\xa9 \xff\xfe": {250, true, "caf\xc3\xa9 \xff\xfe", false},
	} {
		code, last, text, err := mta.ParseReplyLine([]byte(in))
		if w.bad {
			if err == nil {
				t.Errorf("ParseReplyLine(%q) accepted", in)
			}
			continue
		}
		if err != nil || code != w.code || last != w.last || string(text) != w.text {
			t.Errorf("ParseReplyLine(%q) = %d %v %q %v, want %+v", in, code, last, text, err, w)
		}
	}
}

func TestParseEnhancedStatus(t *testing.T) {
	for in, w := range map[string][3]string{
		"5.1.1 User unknown":     {"5.1.1", "User unknown", "ok"},
		"2.0.0 OK":               {"2.0.0", "OK", "ok"},
		"4.7.0":                  {"4.7.0", "", "ok"},
		"5.7.26 Unauthenticated": {"5.7.26", "Unauthenticated", "ok"},
		"5.255.255 big":          {"5.255.255", "big", "ok"},
		"3.0.0 not a class":      {"", "3.0.0 not a class", ""},
		"5.1 short":              {"", "5.1 short", ""},
		"5.1.1x glued":           {"", "5.1.1x glued", ""},
		"5.1.1000 too long":      {"", "5.1.1000 too long", ""},
		"hello":                  {"", "hello", ""},
		"":                       {"", "", ""},
		"5..1 empty":             {"", "5..1 empty", ""},
	} {
		s, rest, ok := mta.ParseEnhancedStatus(in)
		if s != w[0] || rest != w[1] || (ok != (w[2] == "ok")) {
			t.Errorf("ParseEnhancedStatus(%q) = %q %q %v, want %q %q %q", in, s, rest, ok, w[0], w[1], w[2])
		}
	}
}

func TestParseEHLO(t *testing.T) {
	c := mta.ParseEHLO("mx.example.com Hello there\nPIPELINING\n8BITMIME\nSIZE 35882577\nSTARTTLS\nENHANCEDSTATUSCODES\nSMTPUTF8\nchunking\nAUTH PLAIN\nX-UNKNOWN 1")
	if c.Greeting != "mx.example.com" || !c.Pipelining || !c.EightBitMIME || c.Size != 35882577 || !c.STARTTLS || !c.EnhancedStatusCodes || !c.SMTPUTF8 || !c.Chunking {
		t.Fatalf("caps = %+v", c)
	}
	if c := mta.ParseEHLO("mx\nSIZE\nSIZE abc\nSIZE -5\nSIZE 0"); c.Size != 0 {
		t.Fatalf("malformed SIZE parsed as %d", c.Size)
	}
	if c := mta.ParseEHLO(""); c != (mta.Capabilities{}) {
		t.Fatalf("empty = %+v", c)
	}
}

func TestClassifier(t *testing.T) {
	type want struct {
		perm     bool
		typ      mta.BounceType
		sub      mta.BounceSubType
		throttle bool
	}
	P, T := mta.BouncePermanent, mta.BounceTransient
	for _, tc := range []struct {
		code int
		enh  string
		text string
		w    want
	}{
		{550, "5.1.1", "user unknown", want{true, P, mta.SubNoEmail, false}},
		{550, "5.1.2", "bad destination system address", want{true, P, mta.SubNoEmail, false}},
		{550, "", "No such user here", want{true, P, mta.SubNoEmail, false}},
		{554, "5.7.1", "message rejected as spam", want{true, P, mta.SubContentRejected, false}},
		{550, "5.7.1", "Service unavailable; Client host blocked using Spamhaus", want{true, P, mta.SubContentRejected, false}},
		{550, "5.7.26", "Unauthenticated email is not accepted", want{true, P, mta.SubGeneral, false}},
		{552, "5.2.2", "mailbox full", want{true, T, mta.SubMailboxFull, false}},
		{552, "", "Mailbox is full", want{true, T, mta.SubMailboxFull, false}},
		{552, "5.3.4", "message too big", want{true, T, mta.SubMessageTooLarge, false}},
		{552, "", "message size exceeds fixed maximum", want{true, T, mta.SubMessageTooLarge, false}},
		{554, "5.6.0", "attachment type not allowed", want{true, P, mta.SubAttachmentRejected, false}},
		{554, "5.7.1", "virus found in attachment", want{true, P, mta.SubAttachmentRejected, false}},
		{554, "5.6.1", "media not supported", want{true, P, mta.SubContentRejected, false}},
		{550, "", "something else entirely", want{true, P, mta.SubGeneral, false}},
		{421, "4.7.0", "Try again later", want{false, T, mta.SubGeneral, true}},
		{421, "", "service not available", want{false, T, mta.SubGeneral, true}},
		{451, "4.7.1", "rate limited", want{false, T, mta.SubGeneral, true}},
		{451, "", "temporary local problem", want{false, T, mta.SubGeneral, true}},
		{450, "4.2.1", "mailbox temporarily unavailable", want{false, T, mta.SubGeneral, false}},
		{450, "4.7.1", "greylisted, try again later", want{false, T, mta.SubGeneral, false}},
		{450, "4.2.0", "greylisted", want{false, T, mta.SubGeneral, false}},
		{452, "", "too many recipients, slow down", want{false, T, mta.SubGeneral, true}},
		{452, "4.2.2", "over quota", want{false, T, mta.SubMailboxFull, false}},
		{250, "2.0.0", "queued", want{false, mta.BounceUndetermined, mta.SubGeneral, false}},
		{0, "", "", want{false, mta.BounceUndetermined, mta.SubGeneral, false}},
		{999, "", "nonsense", want{false, mta.BounceUndetermined, mta.SubGeneral, false}},
	} {
		got := mta.DefaultClassifier{}.Classify(tc.code, tc.enh, tc.text)
		if got.Permanent != tc.w.perm || got.Type != tc.w.typ || got.SubType != tc.w.sub || got.Throttle != tc.w.throttle {
			t.Errorf("Classify(%d, %q, %q) = %+v, want %+v", tc.code, tc.enh, tc.text, got, tc.w)
		}
	}
}

func TestBackoffScheduleAndJitter(t *testing.T) {
	b := mta.Backoff{Jitter: -1}
	want := []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour, 4 * time.Hour, 4 * time.Hour, 4 * time.Hour}
	for i, w := range want {
		if got := b.Delay(i + 1); got != w {
			t.Errorf("Delay(%d) = %s, want %s", i+1, got, w)
		}
	}
	if b.Delay(0) != time.Minute || b.Delay(-3) != time.Minute {
		t.Error("an attempt below 1 is treated as the first")
	}
	j := mta.Backoff{Schedule: []time.Duration{time.Minute}, Jitter: 0.2}
	lo, hi := time.Hour, time.Duration(0)
	for i := 0; i < 2000; i++ {
		d := j.Delay(1)
		lo, hi = min(lo, d), max(hi, d)
	}
	if lo < 48*time.Second || hi > 72*time.Second || hi-lo < 10*time.Second {
		t.Fatalf("20%% jitter on 1m gave [%s, %s]", lo, hi)
	}
	def := mta.Backoff{Schedule: []time.Duration{time.Minute}}
	if d := def.Delay(1); d < 54*time.Second || d > 66*time.Second {
		t.Fatalf("default jitter is 10%%: %s", d)
	}
}

func TestTokenBucket(t *testing.T) {
	b := mta.NewTokenBucket(10, 3)
	now := time.Now()
	for i := 0; i < 3; i++ {
		if ok, _ := b.Take(now, 1); !ok {
			t.Fatalf("take %d refused from a full bucket", i)
		}
	}
	ok, wait := b.Take(now, 1)
	if ok || wait < 90*time.Millisecond || wait > 110*time.Millisecond {
		t.Fatalf("empty bucket: %v %s", ok, wait)
	}
	if ok, _ := b.Take(now.Add(250*time.Millisecond), 2); !ok {
		t.Fatal("250ms at 10/s should refill 2 tokens")
	}
	if ok, _ := b.Take(now.Add(time.Hour), 3); !ok {
		t.Fatal("bucket should refill to its burst")
	}
	if ok, _ := b.Take(now.Add(time.Hour), 0.5); ok {
		t.Fatal("a refill never exceeds the burst")
	}
}

func TestParseWarmupSchedule(t *testing.T) {
	w, err := mta.ParseWarmupSchedule(" 50, 100 ,200,*")
	if err != nil || len(w.Days) != 3 || w.Days[2] != 200 || !w.Unlimited {
		t.Fatalf("%+v %v", w, err)
	}
	if w, err := mta.ParseWarmupSchedule(""); err != nil || len(w.Days) != 0 {
		t.Fatalf("empty: %+v %v", w, err)
	}
	for _, bad := range []string{"abc", "0", "-1", "50,,100", "unlimited", "50,unlimited,100", "99999999999", "1.5"} {
		if _, err := mta.ParseWarmupSchedule(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestAddressHelpers(t *testing.T) {
	for in, want := range map[string]string{"A@Example.COM": "example.com", "a@b.c.": "b.c", "x@y@z.test": "z.test"} {
		if got, ok := mta.DomainOf(in); !ok || got != want {
			t.Errorf("DomainOf(%q) = %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "a", "@b.c", "a@", "a@."} {
		if d, ok := mta.DomainOf(in); ok {
			t.Errorf("DomainOf(%q) = %q, want none", in, d)
		}
	}
	for _, in := range []string{"a@b.c", "a+tag@sub.example.co.uk", "josé@example.com", "a@b.c."} {
		if err := mta.ValidAddress(in); err != nil {
			t.Errorf("ValidAddress(%q) = %v", in, err)
		}
	}
	long := strings.Repeat("a", 65) + "@b.c"
	for _, in := range []string{"", "a", "a@", "@b.c", "a b@c.d", "a@b.c\r\n", "a@b..c", "a@.b", "<a@b.c>", "a@b.c>", "a\"@b.c", "a@[1.2.3.4]", long, strings.Repeat("a", 250) + "@b.cd", "a@b\x00.c", "a@-b.c"} {
		if err := mta.ValidAddress(in); err == nil {
			t.Errorf("ValidAddress(%q) accepted", in)
		}
	}
	if !mta.ValidID("abc-1.2_3") || mta.ValidID("") || mta.ValidID(".hidden") || mta.ValidID("a/b") || mta.ValidID("a b") || mta.ValidID(strings.Repeat("a", 129)) {
		t.Error("ValidID")
	}
}

func TestPriority(t *testing.T) {
	for in, want := range map[string]mta.Priority{"": mta.PriorityTransactional, "Transactional": mta.PriorityTransactional, " MARKETING ": mta.PriorityMarketing} {
		if got, err := mta.ParsePriority(in); err != nil || got != want {
			t.Errorf("ParsePriority(%q) = %v %v", in, got, err)
		}
	}
	if _, err := mta.ParsePriority("urgent"); err == nil {
		t.Error("unknown priority accepted")
	}
	if mta.PriorityTransactional.String() != "transactional" || mta.PriorityMarketing.String() != "marketing" {
		t.Error("String")
	}
}

func TestMetaRoundTripAndCorruption(t *testing.T) {
	m := sample("meta-1")
	b, err := mta.EncodeMeta(m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := mta.DecodeMeta(b)
	if err != nil || got.ID != "meta-1" || len(got.Recipients) != 2 {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	for name, mut := range map[string]func([]byte) []byte{
		"flip a body byte": func(b []byte) []byte { c := bytes.Clone(b); c[len(c)-5] ^= 1; return c },
		"truncate":         func(b []byte) []byte { return b[:len(b)-3] },
		"wrong magic":      func(b []byte) []byte { c := bytes.Clone(b); c[0] = 'X'; return c },
		"empty":            func([]byte) []byte { return nil },
		"header only":      func(b []byte) []byte { return b[:14] },
	} {
		if _, err := mta.DecodeMeta(mut(b)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestWriteDataNormalizesAndStuffs(t *testing.T) {
	for in, want := range map[string]string{
		"":                  ".\r\n",
		"a":                 "a\r\n.\r\n",
		"a\r\n":             "a\r\n.\r\n",
		"a\nb\n":            "a\r\nb\r\n.\r\n",
		".\r\n":             "..\r\n.\r\n",
		"a\r\n.b\r\n..c":    "a\r\n..b\r\n...c\r\n.\r\n",
		"\r\n\r\n":          "\r\n\r\n.\r\n",
		"a\rb\r\n":          "a\rb\r\n.\r\n",
		"x\r\n.\r\ny\r\n":   "x\r\n..\r\ny\r\n.\r\n",
		"no newline at end": "no newline at end\r\n.\r\n",
	} {
		var buf bytes.Buffer
		w := bufio.NewWriter(&buf)
		if err := mta.WriteData(w, []byte(in)); err != nil {
			t.Fatal(err)
		}
		w.Flush()
		if buf.String() != want {
			t.Errorf("WriteData(%q) = %q, want %q", in, buf.String(), want)
		}
	}
}
