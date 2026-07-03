package collector

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/willianpsouza/ConfigurationCollector/internal/config"
	"github.com/willianpsouza/ConfigurationCollector/internal/storage"
	"github.com/willianpsouza/ConfigurationCollector/internal/transport"
	"github.com/willianpsouza/ConfigurationCollector/internal/vendor"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// --- fakes -------------------------------------------------------------------

// fakeTransport implements transport.Transport. It returns `out` on success,
// or fails the first `failN` calls (then succeeds) to exercise retry, or always
// errors if `err` is set.
type fakeTransport struct {
	out   string
	err   error
	failN int32
	calls int32
}

func (f *fakeTransport) Collect(_ context.Context, _ transport.Session, _ vendor.Driver, _ *slog.Logger) (string, error) {
	n := atomic.AddInt32(&f.calls, 1)
	if f.err != nil {
		return "", f.err
	}
	if n <= f.failN {
		return "", errors.New("transient failure")
	}
	return f.out, nil
}

type savedRec struct {
	meta storage.Meta
	data string
}

// fakeStore implements storage.Store, recording saves. If err is set every Save
// fails; if failOnce is set only the first Save fails.
type fakeStore struct {
	mu       sync.Mutex
	saved    []savedRec
	err      error
	failOnce bool
}

func (f *fakeStore) Save(_ context.Context, m storage.Meta, data []byte) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return "", f.err
	}
	if f.failOnce {
		f.failOnce = false
		return "", errors.New("save failed once")
	}
	f.saved = append(f.saved, savedRec{meta: m, data: string(data)})
	return "id-" + m.Asset, nil
}

func (f *fakeStore) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.saved)
}

func target(name, addr, proto string) config.Target {
	return config.Target{
		Vendor:   "huawei",
		Protocol: proto,
		Username: "admin",
		Password: "secret",
		Address:  addr,
		Port:     0,
		Name:     name,
		Timeout:  2 * time.Second,
	}
}

// --- tests -------------------------------------------------------------------

func TestNewDefaultConcurrency(t *testing.T) {
	c := New(Options{Concurrency: 0, Logger: discardLogger()})
	if c.concurrency != 5 {
		t.Fatalf("default concurrency = %d, want 5", c.concurrency)
	}
	c2 := New(Options{Concurrency: -3, Logger: discardLogger()})
	if c2.concurrency != 5 {
		t.Fatalf("negative concurrency should default to 5, got %d", c2.concurrency)
	}
	c3 := New(Options{Concurrency: 8, Logger: discardLogger()})
	if c3.concurrency != 8 {
		t.Fatalf("explicit concurrency = %d, want 8", c3.concurrency)
	}
}

func TestTransportFor(t *testing.T) {
	ssh := &fakeTransport{}
	tel := &fakeTransport{}

	full := New(Options{SSH: ssh, Telnet: tel, Logger: discardLogger()})
	if tr, err := full.transportFor("ssh"); err != nil || tr != ssh {
		t.Errorf("transportFor(ssh) = %v, %v", tr, err)
	}
	if tr, err := full.transportFor("telnet"); err != nil || tr != tel {
		t.Errorf("transportFor(telnet) = %v, %v", tr, err)
	}
	if _, err := full.transportFor("carrier-pigeon"); err == nil {
		t.Error("unknown protocol should error")
	}

	empty := New(Options{Logger: discardLogger()})
	if _, err := empty.transportFor("ssh"); err == nil {
		t.Error("nil ssh transport should error")
	}
	if _, err := empty.transportFor("telnet"); err == nil {
		t.Error("nil telnet transport should error")
	}
}

func TestRunSuccess(t *testing.T) {
	ssh := &fakeTransport{out: "ssh-config-data"}
	tel := &fakeTransport{out: "telnet-config-data"}
	store := &fakeStore{}
	c := New(Options{
		Concurrency: 2,
		SSH:         ssh,
		Telnet:      tel,
		Store:       store,
		Logger:      discardLogger(),
	})

	targets := []config.Target{
		target("SW-01", "10.0.0.1", "ssh"),
		target("SW-02", "10.0.0.2", "telnet"),
	}
	sum := c.Run(context.Background(), targets)

	if sum.Total != 2 || sum.OK != 2 || sum.Failed != 0 {
		t.Fatalf("summary = %+v, want Total2 OK2 Failed0", sum)
	}
	if store.count() != 2 {
		t.Fatalf("store recorded %d, want 2", store.count())
	}
	// Verify the collected payload reached the store.
	store.mu.Lock()
	defer store.mu.Unlock()
	seen := map[string]string{}
	for _, r := range store.saved {
		seen[r.meta.Protocol] = r.data
	}
	if seen["ssh"] != "ssh-config-data" {
		t.Errorf("ssh data = %q", seen["ssh"])
	}
	if seen["telnet"] != "telnet-config-data" {
		t.Errorf("telnet data = %q", seen["telnet"])
	}
}

func TestRunStoreError(t *testing.T) {
	c := New(Options{
		Concurrency: 1,
		SSH:         &fakeTransport{out: "data"},
		Store:       &fakeStore{err: errors.New("disk full")},
		Logger:      discardLogger(),
	})
	sum := c.Run(context.Background(), []config.Target{target("SW-01", "10.0.0.1", "ssh")})
	if sum.OK != 0 || sum.Failed != 1 {
		t.Fatalf("summary = %+v, want OK0 Failed1", sum)
	}
}

func TestRunUnknownVendor(t *testing.T) {
	tgt := target("SW-01", "10.0.0.1", "ssh")
	tgt.Vendor = "not-a-real-vendor"
	c := New(Options{
		Concurrency: 1,
		SSH:         &fakeTransport{out: "data"},
		Store:       &fakeStore{},
		Logger:      discardLogger(),
	})
	sum := c.Run(context.Background(), []config.Target{tgt})
	if sum.Failed != 1 {
		t.Fatalf("summary = %+v, want Failed1", sum)
	}
}

func TestRunUnknownProtocol(t *testing.T) {
	tgt := target("SW-01", "10.0.0.1", "gopher")
	c := New(Options{
		Concurrency: 1,
		SSH:         &fakeTransport{out: "data"},
		Store:       &fakeStore{},
		Logger:      discardLogger(),
	})
	sum := c.Run(context.Background(), []config.Target{tgt})
	if sum.Failed != 1 {
		t.Fatalf("summary = %+v, want Failed1", sum)
	}
}

func TestRunRetrySucceeds(t *testing.T) {
	// Fails the first attempt, succeeds on the retry. MaxRetries=1 -> one backoff
	// (~2s) then success.
	ssh := &fakeTransport{out: "data", failN: 1}
	store := &fakeStore{}
	c := New(Options{
		Concurrency: 1,
		MaxRetries:  1,
		SSH:         ssh,
		Store:       store,
		Logger:      discardLogger(),
	})
	sum := c.Run(context.Background(), []config.Target{target("SW-01", "10.0.0.1", "ssh")})
	if sum.OK != 1 || sum.Failed != 0 {
		t.Fatalf("summary = %+v, want OK1 Failed0", sum)
	}
	if got := atomic.LoadInt32(&ssh.calls); got != 2 {
		t.Fatalf("Collect calls = %d, want 2 (1 fail + 1 retry)", got)
	}
	if store.count() != 1 {
		t.Fatalf("store recorded %d, want 1", store.count())
	}
}

func TestRunRetryExhausted(t *testing.T) {
	// MaxRetries=0: a single attempt, transport always fails -> Failed, no backoff.
	ssh := &fakeTransport{err: errors.New("always down")}
	c := New(Options{
		Concurrency: 1,
		MaxRetries:  0,
		SSH:         ssh,
		Store:       &fakeStore{},
		Logger:      discardLogger(),
	})
	sum := c.Run(context.Background(), []config.Target{target("SW-01", "10.0.0.1", "ssh")})
	if sum.Failed != 1 {
		t.Fatalf("summary = %+v, want Failed1", sum)
	}
	if got := atomic.LoadInt32(&ssh.calls); got != 1 {
		t.Fatalf("Collect calls = %d, want 1", got)
	}
}

func TestRunCtxCancelledBeforeStart(t *testing.T) {
	ssh := &fakeTransport{out: "data"}
	store := &fakeStore{}
	c := New(Options{
		Concurrency: 2,
		SSH:         ssh,
		Store:       store,
		Logger:      discardLogger(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run dispatches anything

	targets := []config.Target{
		target("SW-01", "10.0.0.1", "ssh"),
		target("SW-02", "10.0.0.2", "ssh"),
	}
	done := make(chan Summary, 1)
	go func() { done <- c.Run(ctx, targets) }()

	select {
	case sum := <-done:
		if sum.Total != 2 {
			t.Errorf("Total = %d, want 2", sum.Total)
		}
		if sum.OK != 0 || sum.Failed != 0 {
			t.Errorf("cancelled run processed jobs: %+v", sum)
		}
		if store.count() != 0 {
			t.Errorf("store should be untouched, got %d", store.count())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return promptly after ctx cancel")
	}
}

func TestRunStoreFailOncePartial(t *testing.T) {
	// One target's Save fails, another succeeds. Concurrency 1 keeps it ordered.
	store := &fakeStore{failOnce: true}
	c := New(Options{
		Concurrency: 1,
		SSH:         &fakeTransport{out: "data"},
		Store:       store,
		Logger:      discardLogger(),
	})
	sum := c.Run(context.Background(), []config.Target{
		target("SW-01", "10.0.0.1", "ssh"),
		target("SW-02", "10.0.0.2", "ssh"),
	})
	if sum.OK != 1 || sum.Failed != 1 {
		t.Fatalf("summary = %+v, want OK1 Failed1", sum)
	}
}
