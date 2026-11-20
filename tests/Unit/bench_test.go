package unit_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mta "github.com/hyz-is/arandu-mta"
	"github.com/hyz-is/arandu-mta/mtatest"
)

// countingSink counts events and signals when the expected number has arrived.
type countingSink struct {
	n atomic.Int64
}

func (c *countingSink) Emit(context.Context, mta.Event) error { c.n.Add(1); return nil }

func benchBody(size int) []byte {
	var b bytes.Buffer
	b.WriteString("From: Sender <hello@sender.test>\r\nTo: user@example.com\r\nSubject: benchmark\r\nMessage-ID: <bench@sender.test>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
	line := strings.Repeat("The quick brown fox jumps over the lazy dog. ", 1) + "\r\n"
	for b.Len() < size {
		b.WriteString(line)
	}
	return b.Bytes()
}

// BenchmarkEngineThroughput measures a message from Submit to the 250 of a fake
// exchanger on loopback, with the spool in memory or on disk.
func BenchmarkEngineThroughput(b *testing.B) {
	for _, tc := range []struct {
		name    string
		domains int
		rcpts   int
		size    int
		spool   string
	}{
		{"memory/1domain/1rcpt/1KB", 1, 1, 1 << 10, "memory"},
		{"memory/50domains/1rcpt/1KB", 50, 1, 1 << 10, "memory"},
		{"memory/50domains/1rcpt/50KB", 50, 1, 50 << 10, "memory"},
		{"memory/1domain/5rcpt/1KB", 1, 5, 1 << 10, "memory"},
		{"disk-nosync/50domains/1rcpt/1KB", 50, 1, 1 << 10, "disk-nosync"},
		{"disk-fsync/50domains/1rcpt/1KB", 50, 1, 1 << 10, "disk-fsync"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			srv, err := mtatest.Start(mtatest.Config{Discard: true})
			if err != nil {
				b.Fatal(err)
			}
			defer srv.Close()
			res := mtatest.NewResolver()
			domains := make([]string, tc.domains)
			for i := range domains {
				domains[i] = fmt.Sprintf("d%d.example", i)
				res.Route(domains[i], "mx."+domains[i])
			}
			var spool mta.Spool = mta.NewMemorySpool()
			switch tc.spool {
			case "disk-nosync":
				s, err := mta.OpenDiskSpool(tempDir(b), mta.DiskSpoolOptions{NoSync: true})
				if err != nil {
					b.Fatal(err)
				}
				defer s.Close()
				spool = s
			case "disk-fsync":
				s, err := mta.OpenDiskSpool(tempDir(b), mta.DiskSpoolOptions{})
				if err != nil {
					b.Fatal(err)
				}
				defer s.Close()
				spool = s
			}
			sink := &countingSink{}
			eng, err := mta.New(mta.Config{
				Spool: spool, Resolver: res, Events: sink, Port: srv.Port(), EHLOName: "mta.test",
				Workers: 256, MaxConnsPerDomain: max(2, 128/tc.domains), MaxIdleTotal: 4096,
				MaxRecipients: 100,
			})
			if err != nil {
				b.Fatal(err)
			}
			if err := eng.Start(context.Background()); err != nil {
				b.Fatal(err)
			}
			defer eng.Shutdown(context.Background())
			body := benchBody(tc.size)
			ctx := context.Background()

			b.ReportAllocs()
			b.ResetTimer()
			start := time.Now()
			var wg sync.WaitGroup
			const submitters = 8
			per := b.N / submitters
			rem := b.N % submitters
			for s := 0; s < submitters; s++ {
				n := per
				if s < rem {
					n++
				}
				wg.Add(1)
				go func(s, n int) {
					defer wg.Done()
					for i := 0; i < n; i++ {
						d := domains[(s+i*submitters)%len(domains)]
						m := &mta.Message{ID: fmt.Sprintf("b%d-%d", s, i), Tenant: "t", MailFrom: "bounce@sender.test", Data: body}
						for r := 0; r < tc.rcpts; r++ {
							m.Recipients = append(m.Recipients, mta.Recipient{Address: fmt.Sprintf("u%d@%s", r, d)})
						}
						if err := eng.Submit(ctx, m); err != nil {
							b.Error(err)
							return
						}
					}
				}(s, n)
			}
			wg.Wait()
			dctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			if err := eng.Drain(dctx); err != nil {
				b.Fatal(err)
			}
			// Drain returns when the queue empties; the last events follow it.
			for sink.n.Load() < int64(b.N*tc.rcpts) {
				time.Sleep(time.Millisecond)
			}
			elapsed := time.Since(start)
			b.StopTimer()
			b.ReportMetric(float64(b.N)/elapsed.Seconds(), "msg/s")
			// A run that had to defer anything measured the retry schedule, not the
			// engine: loopback ports ran out, or the exchanger failed.
			if m := eng.Metrics(); m.Deferred.Load() != 0 || m.ConnectionsFailed.Load() != 0 {
				b.Fatalf("run polluted: %d deferrals, %d failed connections", m.Deferred.Load(), m.ConnectionsFailed.Load())
			}
			b.ReportMetric(float64(eng.Metrics().ConnectionsOpened.Load()), "conns")
			if got := srv.Stats().Messages; got != int64(b.N*boolToInt(tc.rcpts > 0)) {
				b.Fatalf("server accepted %d messages, want %d", got, b.N)
			}
		})
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func BenchmarkParseReplyLine(b *testing.B) {
	line := []byte("250-SIZE 35882577\r\n")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, _, err := mta.ParseReplyLine(line); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseEnhancedStatus(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		mta.ParseEnhancedStatus("5.1.1 The email account that you tried to reach does not exist")
	}
}

func BenchmarkParseEHLO(b *testing.B) {
	text := "mx.example.com at your service\nSIZE 35882577\n8BITMIME\nSTARTTLS\nENHANCEDSTATUSCODES\nPIPELINING\nCHUNKING\nSMTPUTF8"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		mta.ParseEHLO(text)
	}
}

func BenchmarkWriteData(b *testing.B) {
	for _, size := range []int{1 << 10, 64 << 10, 1 << 20} {
		body := benchBody(size)
		b.Run(fmt.Sprintf("%dKB", size>>10), func(b *testing.B) {
			w := bufio.NewWriterSize(io.Discard, 16<<10)
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if err := mta.WriteData(w, body); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkClassify(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		mta.ClassifyReply(550, "5.7.1", "Message rejected due to local policy; sender reputation is poor")
	}
}

func BenchmarkIPPoolReserve(b *testing.B) {
	pools, _ := mta.NewIPPools(mta.IPPoolConfig{Name: "p", IPs: []mta.PoolIP{
		{Addr: netip.MustParseAddr("192.0.2.1"), Weight: 3},
		{Addr: netip.MustParseAddr("192.0.2.2"), Weight: 1},
		{Addr: netip.MustParseAddr("192.0.2.3"), Weight: 1, Warmup: mta.WarmupSchedule{Days: []int{1 << 30}}},
	}})
	now := time.Now()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			l, _ := pools.Reserve("p", 1, now)
			_ = l
		}
	})
}

func BenchmarkTenantLimiter(b *testing.B) {
	l := mta.NewTenantLimiter(mta.TenantLimit{Rate: 1e9, Burst: 1 << 30}, nil)
	now := time.Now()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = l.Allow("tenant-1", 1, now)
		}
	})
}

func BenchmarkMetaEncodeDecode(b *testing.B) {
	m := sample("bench-meta")
	b.Run("encode", func(b *testing.B) {
		b.ReportAllocs()
		var buf []byte
		for i := 0; i < b.N; i++ {
			buf, _ = mta.AppendMeta(buf[:0], m)
		}
	})
	enc, _ := mta.EncodeMeta(m)
	b.Run("decode", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := mta.DecodeMeta(enc); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkBackoffDelay(b *testing.B) {
	bo := mta.Backoff{}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		bo.Delay(i%10 + 1)
	}
}
