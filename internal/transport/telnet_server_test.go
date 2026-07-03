package transport

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/willianpsouza/ConfigurationCollector/internal/vendor"
)

// startTelnetServer boots a raw-TCP "telnet" server on a random loopback port.
// It emits no IAC negotiation, so the ziutek/telnet client on the transport
// side reads/writes plain bytes (verified against the library source). Closed
// via t.Cleanup.
func startTelnetServer(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveTelnetConn(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// serveTelnetConn performs the login handshake and then a command loop that
// mirrors serveSSHShell (pager / Error / save-[Y/N]).
func serveTelnetConn(server net.Conn) {
	defer server.Close()
	br := bufio.NewReader(server)

	// Login: prompt for username, read it; prompt for password, read it.
	_, _ = io.WriteString(server, "\r\nWelcome to TESTSW\r\nUsername: ")
	if _, err := br.ReadString('\n'); err != nil {
		return
	}
	_, _ = io.WriteString(server, "Password: ")
	if _, err := br.ReadString('\n'); err != nil {
		return
	}

	// Initial prompt (no trailing newline so endsWithPrompt matches).
	_, _ = io.WriteString(server, "\r\n<TESTSW>")

	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimRight(line, "\r\n")
		switch {
		case cmd == cmdPager:
			_, _ = io.WriteString(server, "page one of config\r\n---- More ----")
			if _, err := br.ReadByte(); err != nil { // pager-advance byte (a space)
				return
			}
			_, _ = io.WriteString(server, "page two of config\r\n<TESTSW>")
		case cmd == cmdError:
			_, _ = io.WriteString(server, "Error: invalid input detected at line 3\r\n<TESTSW>")
		case cmd == "save":
			_, _ = io.WriteString(server, "The current configuration will be saved.\r\n[Y/N]")
		case strings.EqualFold(cmd, "y"):
			_, _ = io.WriteString(server, "\r\nInfo: save operation complete.\r\n<TESTSW>")
		default:
			_, _ = io.WriteString(server, "output: "+cmd+"\r\n<TESTSW>")
		}
	}
}

func telnetSession(port int) Session {
	return Session{
		Vendor:   "faketest",
		Name:     "TESTSW",
		Address:  "127.0.0.1",
		Port:     port,
		Username: "admin",
		Password: "secret",
		Timeout:  3 * time.Second,
	}
}

func TestTelnetCollect(t *testing.T) {
	port := startTelnetServer(t)
	tr := NewTelnet()
	d := fakeDriver{
		mode:     vendor.ModeShell,
		setup:    []string{"screen-length 0 temporary"},
		commands: []string{"display version", cmdPager},
		exit:     "quit",
	}

	out, err := tr.Collect(context.Background(), telnetSession(port), d, discardLogger())
	if err != nil {
		t.Fatalf("Collect(telnet): %v", err)
	}
	for _, want := range []string{
		"### ASSET=TESTSW",
		"IP=127.0.0.1",
		"PROTOCOL=telnet",
		"==== CMD: display version ====",
		"==== CMD: " + cmdPager + " ====",
		"output: display version",
		"page one of config",
		"page two of config",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("telnet transcript missing %q\n---\n%s", want, out)
		}
	}
	if strings.Contains(out, "More") {
		t.Errorf("pager marker should have been stripped:\n%s", out)
	}
}

func TestTelnetRunConfig(t *testing.T) {
	port := startTelnetServer(t)
	tr := NewTelnet()
	cmds := []string{"system-view", "sysname NEWNAME", cmdError, "return"}

	res, err := tr.RunConfig(context.Background(), telnetSession(port), cmds, true, discardLogger())
	if err != nil {
		t.Fatalf("RunConfig(telnet): %v", err)
	}
	if res.Transcript == "" {
		t.Fatal("expected a non-empty transcript")
	}
	if !strings.Contains(res.Transcript, "Info: save operation complete.") {
		t.Errorf("save/confirm flow not reflected in transcript:\n%s", res.Transcript)
	}
	if len(res.Errors) == 0 {
		t.Fatalf("expected scanErrors to flag the Error line, transcript:\n%s", res.Transcript)
	}
	foundErr := false
	for _, e := range res.Errors {
		if strings.Contains(e, "Error: invalid input") {
			foundErr = true
		}
	}
	if !foundErr {
		t.Errorf("scanErrors did not capture the emitted error: %v", res.Errors)
	}
}

func TestTelnetCollectDialError(t *testing.T) {
	tr := NewTelnet()
	sess := Session{Address: "127.0.0.1", Port: 1, Username: "x", Password: "y", Timeout: 500 * time.Millisecond}
	_, err := tr.Collect(context.Background(), sess, fakeDriver{mode: vendor.ModeShell}, discardLogger())
	if err == nil {
		t.Fatal("expected dial error to a closed port")
	}
}
