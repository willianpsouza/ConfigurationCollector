package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// --- pure helpers -----------------------------------------------------------

func TestSessionAddr(t *testing.T) {
	s := Session{Address: "10.0.0.1", Port: 22}
	if got := s.Addr(); got != "10.0.0.1:22" {
		t.Fatalf("Addr() = %q, want %q", got, "10.0.0.1:22")
	}
	s2 := Session{Address: "host.example", Port: 2323}
	if got := s2.Addr(); got != "host.example:2323" {
		t.Fatalf("Addr() = %q, want %q", got, "host.example:2323")
	}
}

func TestHeader(t *testing.T) {
	var buf bytes.Buffer
	now := time.Date(2026, 7, 2, 10, 30, 0, 0, time.UTC)
	s := Session{Name: "SW-01", Address: "10.0.0.9", Vendor: "huawei"}
	header(&buf, s, "ssh", now)
	out := buf.String()
	for _, want := range []string{"ASSET=SW-01", "IP=10.0.0.9", "VENDOR=huawei", "PROTOCOL=ssh", "TIME=2026-07-02T10:30:00Z", "###"} {
		if !strings.Contains(out, want) {
			t.Errorf("header missing %q in:\n%s", want, out)
		}
	}
	if !strings.HasSuffix(out, "###\n\n") {
		t.Errorf("header should end with separator, got:\n%q", out)
	}
}

func TestCmdBanner(t *testing.T) {
	var buf bytes.Buffer
	cmdBanner(&buf, "display version")
	if got, want := buf.String(), "\n\n==== CMD: display version ====\n"; got != want {
		t.Fatalf("cmdBanner = %q, want %q", got, want)
	}
}

func TestContainsAny(t *testing.T) {
	tests := []struct {
		name    string
		hay     string
		needles []string
		want    bool
	}{
		{"match", "hello world", []string{"world"}, true},
		{"no match", "hello world", []string{"xyz"}, false},
		{"empty needle skipped", "hello world", []string{""}, false},
		{"empty needle then match", "hello world", []string{"", "hello"}, true},
		{"no needles", "hello", nil, false},
		{"prompt bracket", "foo <HOST>", []string{"<", ">"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsAny([]byte(tt.hay), tt.needles); got != tt.want {
				t.Fatalf("containsAny(%q,%v) = %v, want %v", tt.hay, tt.needles, got, tt.want)
			}
		})
	}
}

func TestScanErrors(t *testing.T) {
	transcript := strings.Join([]string{
		"system-view",
		"Error: bla bla",
		"some ok line",
		"% Invalid input detected at '^' position.",
		"Unrecognized command found at '^'",
		"   ", // whitespace-only, skipped
		"another normal line",
	}, "\n")

	got := scanErrors(transcript)
	if len(got) != 3 {
		t.Fatalf("scanErrors returned %d lines, want 3: %v", len(got), got)
	}
	for _, want := range []string{"Error: bla bla", "% Invalid input detected at '^' position.", "Unrecognized command found at '^'"} {
		found := false
		for _, g := range got {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("scanErrors missing %q, got %v", want, got)
		}
	}

	if got := scanErrors("all good\ninterface up\nvlan 10"); got != nil {
		t.Fatalf("clean transcript should return nil, got %v", got)
	}
}

func TestReCfgErrorMatches(t *testing.T) {
	markers := []string{
		"error: nope", "unrecognized command", "wrong parameter", "incomplete command",
		"ambiguous command", "% invalid", "% unrecognized", "too many parameters",
		"permission denied", "command not found",
	}
	for _, m := range markers {
		if !reCfgError.MatchString(m) {
			t.Errorf("reCfgError should match %q", m)
		}
	}
	if reCfgError.MatchString("configuration applied successfully") {
		t.Error("reCfgError should not match a clean line")
	}
}

func TestEndsWithPrompt(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"angle prompt", "banner text\n<HOST>", true},
		{"bracket prompt", "foo\n[HOST]", true},
		{"hash prompt", "Router#", true},
		{"gt prompt", "Router>", true},
		{"prompt with trailing spaces", "   <HOST>  ", true},
		{"trailing newline breaks anchor", "banner\n<HOST>\n", false},
		{"mid config no prompt", "interface GigabitEthernet0/0/1\n ip address 10.0.0.1", false},
		{"plain text", "just some output", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := endsWithPrompt([]byte(tt.in)); got != tt.want {
				t.Fatalf("endsWithPrompt(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestEndsWithPromptTail(t *testing.T) {
	// Prompt within the last 256 bytes: matches even behind a long prefix.
	long := strings.Repeat("a", 1000) + "\n<HOST>"
	if !endsWithPrompt([]byte(long)) {
		t.Error("prompt at end should match despite long prefix (256-byte tail)")
	}
	// Prompt more than 256 bytes before the end is outside the tail window.
	buried := "<HOST>" + strings.Repeat("b", 300)
	if endsWithPrompt([]byte(buried)) {
		t.Error("prompt buried before the 256-byte tail must not match")
	}
}

func TestMoreRe(t *testing.T) {
	for _, s := range []string{"---- More ----", "-- More --", "  ---- more ----  ", "----MORE----"} {
		if !moreRe.MatchString(s) {
			t.Errorf("moreRe should match %q", s)
		}
	}
	if moreRe.MatchString("no pager marker here") {
		t.Error("moreRe should not match plain text")
	}
}

// --- readUntilPrompt ---------------------------------------------------------

// scriptConn is an io.Reader that also implements SetReadDeadline (deadliner),
// driven by a fixed script of read results.
type scriptConn struct {
	steps         []readStep
	i             int
	deadlineCalls int
}

type readStep struct {
	data string
	err  error
}

func (c *scriptConn) SetReadDeadline(time.Time) error { c.deadlineCalls++; return nil }

func (c *scriptConn) Read(p []byte) (int, error) {
	if c.i >= len(c.steps) {
		return 0, io.EOF
	}
	s := c.steps[c.i]
	c.i++
	n := copy(p, []byte(s.data))
	return n, s.err
}

// zeroReader always returns (0, nil): forces readUntilPrompt to spin until the
// timeout deadline (never EOF, never a prompt).
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { return 0, nil }

// netTimeoutErr satisfies net.Error with Timeout()==true.
type netTimeoutErr struct{}

func (netTimeoutErr) Error() string   { return "i/o timeout" }
func (netTimeoutErr) Timeout() bool   { return true }
func (netTimeoutErr) Temporary() bool { return true }

func TestReadUntilPromptMatch(t *testing.T) {
	r := strings.NewReader("some output>")
	got, err := readUntilPrompt(context.Background(), r, 2*time.Second, []string{">"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, ">") {
		t.Fatalf("expected prompt in output, got %q", got)
	}
}

func TestReadUntilPromptEOF(t *testing.T) {
	// No prompt present -> strings.Reader hits EOF -> returns what it read, nil.
	r := strings.NewReader("clean output no prompt substring")
	got, err := readUntilPrompt(context.Background(), r, 2*time.Second, []string{"ZZZ"})
	if err != nil {
		t.Fatalf("EOF should return nil error, got %v", err)
	}
	if got != "clean output no prompt substring" {
		t.Fatalf("got %q", got)
	}
}

func TestReadUntilPromptCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := readUntilPrompt(ctx, strings.NewReader("data"), 2*time.Second, []string{"none"})
	if err == nil {
		t.Fatal("expected ctx error")
	}
	if got != "" {
		t.Fatalf("expected empty output on immediate cancel, got %q", got)
	}
}

func TestReadUntilPromptTimeout(t *testing.T) {
	_, err := readUntilPrompt(context.Background(), zeroReader{}, 40*time.Millisecond, []string{"never"})
	if err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func TestReadUntilPromptDeadlinerAndNetTimeout(t *testing.T) {
	c := &scriptConn{steps: []readStep{
		{"", netTimeoutErr{}},   // net timeout -> continue
		{"login prompt>", nil},  // then real data with a prompt
	}}
	got, err := readUntilPrompt(context.Background(), c, 2*time.Second, []string{">"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, ">") {
		t.Fatalf("expected prompt, got %q", got)
	}
	if c.deadlineCalls == 0 {
		t.Error("expected SetReadDeadline to be called on a deadliner reader")
	}
}

func TestReadUntilPromptGenericError(t *testing.T) {
	boom := io.ErrClosedPipe
	c := &scriptConn{steps: []readStep{{"partial", boom}}}
	got, err := readUntilPrompt(context.Background(), c, 2*time.Second, []string{"none"})
	if err != boom {
		t.Fatalf("expected boom error, got %v", err)
	}
	if got != "partial" {
		t.Fatalf("expected partial output, got %q", got)
	}
}

// --- newStreamer / readStream ------------------------------------------------

func TestNewStreamer(t *testing.T) {
	ch := newStreamer(strings.NewReader("hello world"))
	var got []byte
	for c := range ch {
		got = append(got, c...)
	}
	if string(got) != "hello world" {
		t.Fatalf("streamer delivered %q", string(got))
	}
}

func TestReadStreamPromptViaStreamer(t *testing.T) {
	ch := newStreamer(strings.NewReader("output line\n<HOST>"))
	got, err := readStream(context.Background(), ch, nil, 2*time.Second, 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "<HOST>") {
		t.Fatalf("expected prompt, got %q", got)
	}
}

func TestReadStreamEOFNoPrompt(t *testing.T) {
	// strings.Reader hits EOF (channel closes) with no prompt -> returns data.
	ch := newStreamer(strings.NewReader("data with no prompt"))
	got, err := readStream(context.Background(), ch, nil, 2*time.Second, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "data with no prompt" {
		t.Fatalf("got %q", got)
	}
}

func TestReadStreamIdle(t *testing.T) {
	// Buffered channel that is never closed: after the first chunk with no
	// prompt, the idle timer fires and returns the partial buffer.
	ch := make(chan []byte, 1)
	ch <- []byte("partial data")
	got, err := readStream(context.Background(), ch, nil, 5*time.Second, 30*time.Millisecond)
	if err != nil {
		t.Fatalf("idle should return nil error, got %v", err)
	}
	if got != "partial data" {
		t.Fatalf("got %q", got)
	}
}

func TestReadStreamCtxCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	ch := make(chan []byte) // never sends, never closes
	got, err := readStream(ctx, ch, nil, 5*time.Second, 5*time.Second)
	if err == nil {
		t.Fatal("expected ctx error")
	}
	if got != "" {
		t.Fatalf("expected empty output, got %q", got)
	}
}

func TestReadStreamTotalTimeoutEmpty(t *testing.T) {
	ch := make(chan []byte) // never sends
	got, err := readStream(context.Background(), ch, nil, 30*time.Millisecond, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "timeout total") {
		t.Fatalf("expected total-timeout error, got %v (%q)", err, got)
	}
}

func TestReadStreamTotalTimeoutPartial(t *testing.T) {
	// Data arrives (no prompt), idle is long, total fires first -> partial, nil.
	ch := make(chan []byte, 1)
	ch <- []byte("some partial output")
	got, err := readStream(context.Background(), ch, nil, 40*time.Millisecond, 10*time.Second)
	if err != nil {
		t.Fatalf("partial-on-total should be nil error, got %v", err)
	}
	if got != "some partial output" {
		t.Fatalf("got %q", got)
	}
}

func TestReadStreamPager(t *testing.T) {
	ch := make(chan []byte, 2)
	ch <- []byte("page one\n---- More ----")
	ch <- []byte("page two\n<HOST>")
	var pager bytes.Buffer
	got, err := readStream(context.Background(), ch, &pager, 5*time.Second, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pager.String() != " " {
		t.Fatalf("expected a single space written to pager, got %q", pager.String())
	}
	if strings.Contains(got, "More") {
		t.Errorf("pager marker should be stripped from output, got %q", got)
	}
	if !strings.Contains(got, "page one") || !strings.Contains(got, "page two") || !strings.Contains(got, "<HOST>") {
		t.Errorf("unexpected assembled output: %q", got)
	}
}

// --- SSH options / host key --------------------------------------------------

func TestDefaultSSHOptions(t *testing.T) {
	o := DefaultSSHOptions()
	if o == nil {
		t.Fatal("DefaultSSHOptions returned nil")
	}
	if len(o.KexAlgorithms) == 0 || len(o.Ciphers) == 0 || len(o.MACs) == 0 || len(o.HostKeyAlgorithms) == 0 {
		t.Fatalf("expected non-empty algorithm lists: %+v", o)
	}
}

func TestApplyLegacy(t *testing.T) {
	log := discardLogger()

	// nil legacy: config untouched.
	s := NewSSH(ssh.InsecureIgnoreHostKey(), nil)
	cfg := &ssh.ClientConfig{}
	s.applyLegacy(cfg, log)
	if len(cfg.Ciphers) != 0 {
		t.Errorf("nil legacy should not set ciphers, got %v", cfg.Ciphers)
	}

	// with legacy: config populated.
	s2 := NewSSH(ssh.InsecureIgnoreHostKey(), DefaultSSHOptions())
	cfg2 := &ssh.ClientConfig{}
	s2.applyLegacy(cfg2, log)
	if len(cfg2.Ciphers) == 0 || len(cfg2.KeyExchanges) == 0 || len(cfg2.MACs) == 0 || len(cfg2.HostKeyAlgorithms) == 0 {
		t.Fatalf("legacy options not applied: %+v", cfg2)
	}
}

func TestNewSSHAndTelnetConstructors(t *testing.T) {
	if NewSSH(ssh.InsecureIgnoreHostKey(), nil) == nil {
		t.Error("NewSSH returned nil")
	}
	if NewTelnet() == nil {
		t.Error("NewTelnet returned nil")
	}
}

func TestHostKeyCallbackEmptyPath(t *testing.T) {
	cb := HostKeyCallback("", discardLogger())
	if cb == nil {
		t.Fatal("empty path should return a (insecure) non-nil callback")
	}
}

func TestHostKeyCallbackMissingFile(t *testing.T) {
	cb := HostKeyCallback(filepath.Join(t.TempDir(), "does-not-exist"), discardLogger())
	if cb == nil {
		t.Fatal("missing file should return a (insecure) non-nil callback")
	}
}

func TestHostKeyCallbackValidFile(t *testing.T) {
	// Build a real, parseable known_hosts entry so knownhosts.New succeeds.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	line := knownhosts.Line([]string{"localhost:22"}, signer.PublicKey())

	dir := t.TempDir()
	khPath := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(khPath, []byte(line+"\n"), 0o644); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	cb := HostKeyCallback(khPath, discardLogger())
	if cb == nil {
		t.Fatal("valid known_hosts should return a non-nil callback")
	}
}

func TestHostKeyCallbackInvalidFile(t *testing.T) {
	dir := t.TempDir()
	khPath := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(khPath, []byte("this is not a valid known_hosts entry !!!\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cb := HostKeyCallback(khPath, discardLogger())
	if cb == nil {
		t.Fatal("invalid file should fall back to a non-nil insecure callback")
	}
}
