package transport

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ziutek/telnet"
)

// telnetPipe wires a *telnet.Conn to an in-process TCP loopback. The returned
// server net.Conn plays the "device" side. This exercises the real parsing
// logic of readTelnetRobust/waitForCI without any live device.
func telnetPipe(t *testing.T) (server net.Conn, tc *telnet.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	type accepted struct {
		c net.Conn
		e error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, e := ln.Accept()
		ch <- accepted{c, e}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	a := <-ch
	if a.e != nil {
		t.Fatalf("accept: %v", a.e)
	}
	tc, err = telnet.NewConn(client)
	if err != nil {
		t.Fatalf("telnet.NewConn: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = a.c.Close()
	})
	return a.c, tc
}

func TestReadTelnetRobustPrompt(t *testing.T) {
	server, tc := telnetPipe(t)
	go func() { _, _ = server.Write([]byte("some config output\n<HOST>")) }()

	got, err := readTelnetRobust(context.Background(), tc, 3*time.Second, 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "<HOST>") {
		t.Fatalf("expected prompt in output, got %q", got)
	}
}

func TestReadTelnetRobustPager(t *testing.T) {
	server, tc := telnetPipe(t)
	go func() {
		_, _ = server.Write([]byte("page one\n---- More ----"))
		// Wait for the pager-advance (a space) sent by readTelnetRobust.
		buf := make([]byte, 8)
		_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte("page two\n<HOST>"))
	}()

	got, err := readTelnetRobust(context.Background(), tc, 4*time.Second, 3*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(got, "More") {
		t.Errorf("pager marker should be stripped, got %q", got)
	}
	if !strings.Contains(got, "page one") || !strings.Contains(got, "page two") || !strings.Contains(got, "<HOST>") {
		t.Errorf("unexpected assembled output: %q", got)
	}
}

func TestReadTelnetRobustIdle(t *testing.T) {
	server, tc := telnetPipe(t)
	go func() { _, _ = server.Write([]byte("partial data no prompt")) }()

	got, err := readTelnetRobust(context.Background(), tc, 5*time.Second, 120*time.Millisecond)
	if err != nil {
		t.Fatalf("idle should return nil error, got %v", err)
	}
	if !strings.Contains(got, "partial data no prompt") {
		t.Fatalf("got %q", got)
	}
}

func TestReadTelnetRobustCtxCancel(t *testing.T) {
	_, tc := telnetPipe(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := readTelnetRobust(ctx, tc, 3*time.Second, 2*time.Second)
	if err == nil {
		t.Fatal("expected ctx error")
	}
	if got != "" {
		t.Fatalf("expected empty output, got %q", got)
	}
}

func TestReadTelnetRobustTotalTimeoutEmpty(t *testing.T) {
	_, tc := telnetPipe(t) // server never writes
	got, err := readTelnetRobust(context.Background(), tc, 150*time.Millisecond, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "timeout total") {
		t.Fatalf("expected total-timeout error, got %v (%q)", err, got)
	}
}

func TestWaitForCIMatch(t *testing.T) {
	server, tc := telnetPipe(t)
	go func() { _, _ = server.Write([]byte("\r\nLogin: ")) }()

	if err := waitForCI(tc, 2*time.Second, "sername:", "ogin:"); err != nil {
		t.Fatalf("waitForCI should match 'ogin:', got %v", err)
	}
}

func TestWaitForCITimeout(t *testing.T) {
	server, tc := telnetPipe(t)
	go func() { _, _ = server.Write([]byte("banner text without the pattern")) }()

	if err := waitForCI(tc, 150*time.Millisecond, "password:"); err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestWaitForCIConnClosed(t *testing.T) {
	server, tc := telnetPipe(t)
	_ = server.Close() // EOF on the client side

	if err := waitForCI(tc, 2*time.Second, "never"); err == nil {
		t.Fatal("expected error when connection is closed")
	}
}
