package unit_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	mta "github.com/hyz-is/arandu-mta"
	"github.com/hyz-is/arandu-mta/mtatest"
)

func sample(id string) *mta.Message {
	now := time.Now().UTC().Truncate(time.Millisecond)
	return &mta.Message{
		ID: id, Tenant: "org_1", MailFrom: "b@sender.test", Priority: mta.PriorityMarketing, IPPool: "default",
		Data:      []byte("Subject: " + id + "\r\n\r\nbody of " + id + "\r\n"),
		CreatedAt: now, ExpiresAt: now.Add(72 * time.Hour), NextAttempt: now,
		Recipients: []mta.Recipient{
			{Address: "a@example.com", Domain: "example.com", NextAttempt: now},
			{Address: "b@example.org", Domain: "example.org", State: mta.StateDeferred, Attempts: 2, LastCode: 451, LastText: "later", NextAttempt: now.Add(time.Minute)},
		},
	}
}

// spoolContract is what every Spool has to do.
func spoolContract(t *testing.T, s mta.Spool) {
	ctx := context.Background()
	m := sample("msg-1")
	if err := s.Put(ctx, m); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, m); !errors.Is(err, mta.ErrDuplicate) {
		t.Fatalf("second Put = %v, want ErrDuplicate", err)
	}
	if err := s.Put(ctx, &mta.Message{ID: "../x", Data: []byte("x")}); err == nil {
		t.Fatal("Put accepted an id that is not a safe file name")
	}
	data, err := s.ReadData(ctx, "msg-1", []byte("prefix:"))
	if err != nil || string(data) != "prefix:"+string(m.Data) {
		t.Fatalf("ReadData = %q, %v", data, err)
	}
	if _, err := s.ReadData(ctx, "absent", nil); !errors.Is(err, mta.ErrNotFound) {
		t.Fatalf("ReadData of an unknown id = %v", err)
	}

	// Update changes metadata and leaves the data alone.
	upd := m.Clone()
	upd.Data = nil
	upd.Recipients[0].State = mta.StateDelivered
	upd.Recipients[0].LastCode = 250
	if err := s.Update(ctx, upd); err != nil {
		t.Fatal(err)
	}
	if err := s.Update(ctx, &mta.Message{ID: "absent", Recipients: []mta.Recipient{{Address: "a@b.c"}}}); !errors.Is(err, mta.ErrNotFound) {
		t.Fatalf("Update of an unknown id = %v", err)
	}
	if data, _ := s.ReadData(ctx, "msg-1", nil); !bytes.Equal(data, m.Data) {
		t.Fatalf("data changed by Update: %q", data)
	}
	if err := s.Put(ctx, sample("msg-2")); err != nil {
		t.Fatal(err)
	}

	var got []*mta.Message
	if err := s.Load(ctx, func(x *mta.Message) error { got = append(got, x); return nil }); err != nil {
		t.Fatal(err)
	}
	sort.Slice(got, func(i, j int) bool { return got[i].ID < got[j].ID })
	if len(got) != 2 || got[0].ID != "msg-1" || got[1].ID != "msg-2" {
		t.Fatalf("Load returned %d messages", len(got))
	}
	l := got[0]
	if l.Data != nil || l.Tenant != "org_1" || l.MailFrom != "b@sender.test" || l.Priority != mta.PriorityMarketing || l.IPPool != "default" ||
		l.Size != len(m.Data) || !l.ExpiresAt.Equal(m.ExpiresAt) || len(l.Recipients) != 2 {
		t.Fatalf("loaded %+v", l)
	}
	if r := l.Recipients[0]; r.State != mta.StateDelivered || r.LastCode != 250 {
		t.Fatalf("recipient 0 = %+v", r)
	}
	if r := l.Recipients[1]; r.State != mta.StateDeferred || r.Attempts != 2 || r.LastText != "later" || !r.NextAttempt.Equal(m.Recipients[1].NextAttempt) {
		t.Fatalf("recipient 1 = %+v", r)
	}

	stop := errors.New("stop")
	if err := s.Load(ctx, func(*mta.Message) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("Load must stop at the first error from fn: %v", err)
	}

	if err := s.Delete(ctx, "msg-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "msg-1"); err != nil {
		t.Fatalf("deleting twice must not fail: %v", err)
	}
	if _, err := s.ReadData(ctx, "msg-1", nil); !errors.Is(err, mta.ErrNotFound) {
		t.Fatalf("data survived Delete: %v", err)
	}
	if err := s.Put(ctx, m); err != nil {
		t.Fatalf("an id is reusable after Delete: %v", err)
	}
}

func TestMemorySpoolContract(t *testing.T) { spoolContract(t, mta.NewMemorySpool()) }

func TestDiskSpoolContract(t *testing.T) {
	for _, noSync := range []bool{false, true} {
		t.Run(fmt.Sprintf("nosync=%v", noSync), func(t *testing.T) {
			s, err := mta.OpenDiskSpool(tempDir(t), mta.DiskSpoolOptions{NoSync: noSync})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			spoolContract(t, s)
		})
	}
}

func TestDiskSpoolSurvivesReopen(t *testing.T) {
	dir := tempDir(t)
	s, _ := mta.OpenDiskSpool(dir, mta.DiskSpoolOptions{})
	for i := 0; i < 20; i++ {
		if err := s.Put(context.Background(), sample(fmt.Sprintf("r%02d", i))); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	s2, err := mta.OpenDiskSpool(dir, mta.DiskSpoolOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	n := 0
	if err := s2.Load(context.Background(), func(*mta.Message) error { n++; return nil }); err != nil || n != 20 {
		t.Fatalf("Load after reopen: %d messages, %v", n, err)
	}
}

func TestDiskSpoolCleansUpWhatACrashLeaves(t *testing.T) {
	dir := tempDir(t)
	s, _ := mta.OpenDiskSpool(dir, mta.DiskSpoolOptions{})
	ctx := context.Background()
	for _, id := range []string{"good-1", "good-2", "torn", "nodata", "badsize"} {
		if err := s.Put(ctx, sample(id)); err != nil {
			t.Fatal(err)
		}
	}
	find := func(id, ext string) string {
		m, _ := filepath.Glob(filepath.Join(dir, "*", id+ext))
		if len(m) != 1 {
			t.Fatalf("cannot find %s%s", id, ext)
		}
		return m[0]
	}
	// A metadata file cut in half: a torn write that rename should have made
	// impossible, or a disk that lied about fsync.
	meta, _ := os.ReadFile(find("torn", ".meta"))
	if err := os.WriteFile(find("torn", ".meta"), meta[:len(meta)/2], 0o640); err != nil {
		t.Fatal(err)
	}
	// Metadata whose data file vanished.
	os.Remove(find("nodata", ".eml"))
	// A data file that does not have the length the metadata recorded.
	if err := os.WriteFile(find("badsize", ".eml"), []byte("short"), 0o640); err != nil {
		t.Fatal(err)
	}
	// A temporary file and a data file whose metadata never got renamed in.
	shard := filepath.Dir(find("good-1", ".meta"))
	os.WriteFile(filepath.Join(shard, ".good-1.tmp-abc"), []byte("partial"), 0o640)
	os.WriteFile(filepath.Join(shard, "orphan.eml"), []byte("data without metadata"), 0o640)
	// The process never closed or synced anything else: the next open is the
	// recovery.
	s2, err := mta.OpenDiskSpool(dir, mta.DiskSpoolOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if s2.Swept() != 2 {
		t.Fatalf("open removed %d leftovers, want 2 (the temporary file and the orphan data file)", s2.Swept())
	}
	var ids []string
	if err := s2.Load(ctx, func(m *mta.Message) error { ids = append(ids, m.ID); return nil }); err != nil {
		t.Fatal(err)
	}
	sort.Strings(ids)
	if strings.Join(ids, ",") != "good-1,good-2" {
		t.Fatalf("Load returned %v, want only the intact messages", ids)
	}
	if s2.Quarantined() != 3 {
		t.Fatalf("quarantined = %d, want 3", s2.Quarantined())
	}
	moved, _ := filepath.Glob(filepath.Join(dir, "corrupt", "*"))
	if len(moved) < 3 {
		t.Fatalf("corrupt directory holds %v", moved)
	}
	if _, err := os.Stat(filepath.Join(shard, "orphan.eml")); err == nil {
		t.Fatal("orphan data file survived the open")
	}
}

func TestEngineRecoversTheSpoolAfterACrash(t *testing.T) {
	dir := tempDir(t)
	ctx := context.Background()
	// The first process accepts three messages and dies: it never calls Close.
	s1, _ := mta.OpenDiskSpool(dir, mta.DiskSpoolOptions{})
	now := time.Now()
	for i := 0; i < 3; i++ {
		m := sample(fmt.Sprintf("crash%d", i))
		m.Recipients = []mta.Recipient{
			{Address: "a@example.com", Domain: "example.com", NextAttempt: now},
			{Address: "done@example.com", Domain: "example.com", State: mta.StateDelivered, LastCode: 250},
		}
		m.ExpiresAt = now.Add(time.Hour)
		if err := s1.Put(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	// One message was settled but its delete did not reach the disk.
	done := sample("settled")
	done.Recipients = []mta.Recipient{{Address: "x@example.com", Domain: "example.com", State: mta.StateBounced}}
	s1.Put(ctx, done)
	// One was mid-delivery when the process died.
	mid := sample("mid")
	mid.ExpiresAt = now.Add(time.Hour)
	mid.Recipients = []mta.Recipient{{Address: "m@example.com", Domain: "example.com", State: mta.StateSending, Attempts: 1}}
	s1.Put(ctx, mid)

	s2, err := mta.OpenDiskSpool(dir, mta.DiskSpoolOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	h := newHarness(t, mtatest.Config{}, func(c *mta.Config) { c.Spool = s2 })
	h.events.waitType(t, mta.EventDelivered, 4)
	got := map[string]bool{}
	for _, e := range h.events.all() {
		got[e.MessageID+"/"+e.Recipient] = true
		if e.MessageID == "mid" && e.Attempt != 2 {
			t.Fatalf("attempt counter was lost across the crash: %+v", e)
		}
	}
	for _, want := range []string{"crash0/a@example.com", "crash1/a@example.com", "crash2/a@example.com", "mid/m@example.com"} {
		if !got[want] {
			t.Fatalf("%s was not delivered after recovery; got %v", want, got)
		}
	}
	if got["crash0/done@example.com"] || got["settled/x@example.com"] {
		t.Fatalf("a recipient that was already settled was delivered again: %v", got)
	}
	if err := h.eng.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	left := 0
	s2.Load(ctx, func(*mta.Message) error { left++; return nil })
	if left != 0 {
		t.Fatalf("%d messages left in the spool after recovery and delivery", left)
	}
	if n := h.srv.Stats().Messages; n != 4 {
		t.Fatalf("server received %d messages, want 4", n)
	}
}

func TestDeferredStateSurvivesARestart(t *testing.T) {
	dir := tempDir(t)
	var fail atomicBool
	fail.set(true)
	srvCfg := mtatest.Config{OnData: func(*mtatest.Received) *mtatest.Reply {
		if fail.get() {
			return rep(451, "4.0.0", "later")
		}
		return nil
	}}
	s1, _ := mta.OpenDiskSpool(dir, mta.DiskSpoolOptions{NoSync: true})
	h := newHarness(t, srvCfg, func(c *mta.Config) {
		c.Spool = s1
		c.Backoff = mta.Backoff{Schedule: []time.Duration{300 * time.Millisecond}, Jitter: -1}
		c.Expiry = time.Hour
	})
	h.submit(msg("rs1", "a@example.com"))
	h.events.waitType(t, mta.EventDeferred, 1)
	h.eng.Shutdown(context.Background())
	s1.Close()

	fail.set(false)
	s2, _ := mta.OpenDiskSpool(dir, mta.DiskSpoolOptions{NoSync: true})
	defer s2.Close()
	h2 := newHarness(t, mtatest.Config{}, func(c *mta.Config) { c.Spool = s2 })
	start := time.Now()
	ev := h2.events.waitType(t, mta.EventDelivered, 1)[0]
	if ev.Attempt != 2 || ev.MessageID != "rs1" {
		t.Fatalf("event = %+v", ev)
	}
	_ = start
}

// TestKilledWriterLeavesOnlyWholeMessages kills a process in the middle of a
// stream of Put calls with SIGKILL and checks what the spool holds afterwards:
// every message the child acknowledged is there, whole, and nothing half-written
// is ever loaded.
func TestKilledWriterLeavesOnlyWholeMessages(t *testing.T) {
	if os.Getenv("MTA_CRASH_CHILD") != "" {
		return
	}
	dir := tempDir(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChild$", "-test.v=false")
	cmd.Env = append(os.Environ(), "MTA_CRASH_CHILD="+dir)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var acked []string
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		if id, ok := strings.CutPrefix(sc.Text(), "put "); ok {
			acked = append(acked, id)
		}
		if len(acked) == 40 {
			_ = cmd.Process.Signal(syscall.SIGKILL)
			break
		}
	}
	for sc.Scan() { // what the child managed to print before it died
		if id, ok := strings.CutPrefix(sc.Text(), "put "); ok {
			acked = append(acked, id)
		}
	}
	_ = cmd.Wait()
	if len(acked) < 40 {
		t.Fatalf("child acknowledged only %d messages", len(acked))
	}

	s, err := mta.OpenDiskSpool(dir, mta.DiskSpoolOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	loaded := map[string]bool{}
	if err := s.Load(context.Background(), func(m *mta.Message) error {
		loaded[m.ID] = true
		data, err := s.ReadData(context.Background(), m.ID, nil)
		if err != nil || len(data) != m.Size || !bytes.HasSuffix(data, []byte("END\r\n")) || !strings.Contains(string(data), m.ID) {
			t.Errorf("message %s is not whole: %d bytes (metadata says %d), %v", m.ID, len(data), m.Size, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, id := range acked {
		if !loaded[id] {
			t.Fatalf("message %s was acknowledged by Put and lost", id)
		}
	}
	if s.Quarantined() != 0 {
		t.Fatalf("%d messages were unreadable after the kill; atomic renames should make that impossible", s.Quarantined())
	}
}

// TestCrashChild is the process TestKilledWriterLeavesOnlyWholeMessages kills.
func TestCrashChild(t *testing.T) {
	dir := os.Getenv("MTA_CRASH_CHILD")
	if dir == "" {
		t.Skip("only runs as a child process")
	}
	s, err := mta.OpenDiskSpool(dir, mta.DiskSpoolOptions{})
	if err != nil {
		fmt.Println("error", err)
		os.Exit(2)
	}
	filler := strings.Repeat("x", 20000)
	for i := 0; ; i++ {
		id := fmt.Sprintf("kill-%05d", i)
		m := sample(id)
		m.Data = []byte("Subject: " + id + "\r\n\r\n" + filler + "\r\nEND\r\n")
		if err := s.Put(context.Background(), m); err != nil {
			fmt.Println("error", err)
			os.Exit(2)
		}
		fmt.Println("put " + id)
	}
}

func TestAnIDThatLooksLikeATemporaryFileIsNotSwept(t *testing.T) {
	dir := tempDir(t)
	s, _ := mta.OpenDiskSpool(dir, mta.DiskSpoolOptions{})
	ctx := context.Background()
	if err := s.Put(ctx, sample("report.tmp-final")); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2, err := mta.OpenDiskSpool(dir, mta.DiskSpoolOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	n := 0
	s2.Load(ctx, func(m *mta.Message) error { n++; return nil })
	if n != 1 || s2.Swept() != 0 {
		t.Fatalf("loaded %d messages, swept %d files; a valid id must survive the cleanup", n, s2.Swept())
	}
}
