package transport

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/willianpsouza/ConfigurationCollector/internal/vendor"
	"golang.org/x/crypto/ssh"
)

// Special command markers the in-process servers react to. Shared by the SSH
// and Telnet server test files (same package).
const (
	cmdPager = "PAGERCMD"
	cmdError = "ERRORCMD"
)

// fakeDriver implements vendor.Driver for driving Collect in both shell and
// exec modes without a real device.
type fakeDriver struct {
	mode     vendor.Mode
	setup    []string
	commands []string
	exit     string
}

func (d fakeDriver) Name() string        { return "faketest" }
func (d fakeDriver) Mode() vendor.Mode    { return d.mode }
func (d fakeDriver) Setup() []string      { return d.setup }
func (d fakeDriver) Commands() []string   { return d.commands }
func (d fakeDriver) Prompts() []string    { return []string{"<", ">", "]"} }
func (d fakeDriver) Exit() string         { return d.exit }

// --- in-process SSH server ---------------------------------------------------

// startSSHServer boots a minimal SSH server on a random loopback port and
// returns that port. It accepts any password and serves interactive shells and
// exec requests. The listener is closed via t.Cleanup.
func startSSHServer(t *testing.T) int {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			nConn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSSHConn(nConn, cfg)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func serveSSHConn(nConn net.Conn, cfg *ssh.ServerConfig) {
	sconn, chans, reqs, err := ssh.NewServerConn(nConn, cfg)
	if err != nil {
		_ = nConn.Close()
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "only session supported")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		go handleSSHSession(ch, creqs)
	}
}

func handleSSHSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			_ = req.Reply(true, nil)
		case "shell":
			_ = req.Reply(true, nil)
			serveSSHShell(ch)
			return
		case "exec":
			var m struct{ Command string }
			_ = ssh.Unmarshal(req.Payload, &m)
			_ = req.Reply(true, nil)
			serveSSHExec(ch, m.Command)
			return
		default:
			_ = req.Reply(false, nil)
		}
	}
}

// serveSSHShell drives a fake CLI: emits a "<TESTSW>" prompt (no trailing
// newline so endsWithPrompt matches), then reacts to each command line.
func serveSSHShell(ch ssh.Channel) {
	defer ch.Close()
	_, _ = io.WriteString(ch, "<TESTSW>")
	br := bufio.NewReader(ch)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimRight(line, "\r\n")
		switch {
		case cmd == cmdPager:
			_, _ = io.WriteString(ch, "page one of config\n---- More ----")
			if _, err := br.ReadByte(); err != nil { // pager-advance byte (a space)
				return
			}
			_, _ = io.WriteString(ch, "page two of config\n<TESTSW>")
		case cmd == cmdError:
			_, _ = io.WriteString(ch, "Error: invalid input detected at line 3\n<TESTSW>")
		case cmd == "save":
			_, _ = io.WriteString(ch, "The current configuration will be saved.\n[Y/N]")
		case strings.EqualFold(cmd, "y"):
			_, _ = io.WriteString(ch, "\nInfo: save operation complete.\n<TESTSW>")
		default:
			_, _ = io.WriteString(ch, "output: "+cmd+"\n<TESTSW>")
		}
	}
}

func serveSSHExec(ch ssh.Channel, cmd string) {
	defer ch.Close()
	if strings.Contains(cmd, "FAIL") {
		_, _ = io.WriteString(ch.Stderr(), "stderr: exec command failed\n")
		sendExitStatus(ch, 1)
		return
	}
	_, _ = io.WriteString(ch, "exec-output for: "+cmd+"\n")
	sendExitStatus(ch, 0)
}

func sendExitStatus(ch ssh.Channel, code uint32) {
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
}

func sshSession(port int) Session {
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

// --- tests -------------------------------------------------------------------

func TestSSHCollectShell(t *testing.T) {
	port := startSSHServer(t)
	tr := NewSSH(ssh.InsecureIgnoreHostKey(), nil)
	d := fakeDriver{
		mode:     vendor.ModeShell,
		setup:    []string{"screen-length 0 temporary"},
		commands: []string{"display version", cmdPager, "display interface brief"},
		exit:     "quit",
	}

	out, err := tr.Collect(context.Background(), sshSession(port), d, discardLogger())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, want := range []string{
		"### ASSET=TESTSW",
		"IP=127.0.0.1",
		"PROTOCOL=ssh",
		"==== CMD: display version ====",
		"==== CMD: " + cmdPager + " ====",
		"output: display version",
		"page one of config",
		"page two of config",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("shell transcript missing %q\n---\n%s", want, out)
		}
	}
	if strings.Contains(out, "More") {
		t.Errorf("pager marker should have been stripped:\n%s", out)
	}
}

func TestSSHCollectExec(t *testing.T) {
	port := startSSHServer(t)
	tr := NewSSH(ssh.InsecureIgnoreHostKey(), nil)
	d := fakeDriver{
		mode:     vendor.ModeExec,
		commands: []string{"show version", "show FAIL"},
	}

	out, err := tr.Collect(context.Background(), sshSession(port), d, discardLogger())
	if err != nil {
		t.Fatalf("Collect(exec): %v", err)
	}
	for _, want := range []string{
		"### ASSET=TESTSW",
		"==== CMD: show version ====",
		"exec-output for: show version",
		"stderr: exec command failed", // exercises the failed-exec/stderr branch
	} {
		if !strings.Contains(out, want) {
			t.Errorf("exec transcript missing %q\n---\n%s", want, out)
		}
	}
}

func TestSSHRunConfig(t *testing.T) {
	port := startSSHServer(t)
	tr := NewSSH(ssh.InsecureIgnoreHostKey(), nil)
	cmds := []string{"system-view", "sysname NEWNAME", cmdError, "return"}

	res, err := tr.RunConfig(context.Background(), sshSession(port), cmds, true, discardLogger())
	if err != nil {
		t.Fatalf("RunConfig: %v", err)
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

func TestSSHCollectDialError(t *testing.T) {
	// Port with no listener -> dial fails fast. Exercises the dial error path.
	tr := NewSSH(ssh.InsecureIgnoreHostKey(), nil)
	sess := Session{Address: "127.0.0.1", Port: 1, Username: "x", Password: "y", Timeout: 500 * time.Millisecond}
	_, err := tr.Collect(context.Background(), sess, fakeDriver{mode: vendor.ModeShell}, discardLogger())
	if err == nil {
		t.Fatal("expected dial error to a closed port")
	}
}
