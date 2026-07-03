package apply

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/willianpsouza/ConfigurationCollector/internal/config"
	"github.com/willianpsouza/ConfigurationCollector/internal/transport"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// --- fake ConfigRunner -------------------------------------------------------

type runCall struct {
	addr string
	cmds []string
	save bool
}

type fakeRunner struct {
	mu    sync.Mutex
	calls []runCall
	fn    func(addr string, cmds []string, save bool) (transport.ConfigResult, error)
}

func (f *fakeRunner) RunConfig(_ context.Context, s transport.Session, cmds []string, save bool, _ *slog.Logger) (transport.ConfigResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, runCall{addr: s.Address, cmds: append([]string(nil), cmds...), save: save})
	f.mu.Unlock()
	if f.fn != nil {
		return f.fn(s.Address, cmds, save)
	}
	return transport.ConfigResult{Transcript: "ok"}, nil
}

func isBackupCmds(cmds []string) bool {
	return len(cmds) == 1 && cmds[0] == "display current-configuration"
}

// applyCall returns the recorded non-backup (wrapped) call for an address.
func (f *fakeRunner) applyCall(addr string) (runCall, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c.addr == addr && !isBackupCmds(c.cmds) {
			return c, true
		}
	}
	return runCall{}, false
}

func tgt(name, addr, proto, mode string) config.Target {
	_ = mode
	return config.Target{
		Vendor:   "huawei",
		Protocol: proto,
		Username: "admin",
		Password: "pw",
		Address:  addr,
		Port:     22,
		Name:     name,
		Timeout:  2 * time.Second,
	}
}

// --- LoadChangeSet -----------------------------------------------------------

func TestLoadChangeSet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cs.json")
	content := `{
		"name": "mudanca-1",
		"changes": [
			{"address": "10.0.0.1", "comment": "add bgp", "commands": ["bgp 100", "peer 1.1.1.1"]},
			{"address": "10.0.0.2", "mode": "immediate", "commands": ["vlan 10"]}
		]
	}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cs, err := LoadChangeSet(path)
	if err != nil {
		t.Fatalf("LoadChangeSet: %v", err)
	}
	if cs.Name != "mudanca-1" {
		t.Errorf("Name = %q", cs.Name)
	}
	if len(cs.Changes) != 2 {
		t.Fatalf("Changes = %d, want 2", len(cs.Changes))
	}
	if cs.Changes[0].Address != "10.0.0.1" || len(cs.Changes[0].Commands) != 2 {
		t.Errorf("change[0] = %+v", cs.Changes[0])
	}
	if cs.Changes[1].Mode != "immediate" {
		t.Errorf("change[1].Mode = %q", cs.Changes[1].Mode)
	}
}

func TestLoadChangeSetBadJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadChangeSet(path); err == nil {
		t.Fatal("expected error on malformed json")
	}
}

func TestLoadChangeSetMissingFile(t *testing.T) {
	if _, err := LoadChangeSet(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("expected error on missing file")
	}
}

// --- wrap --------------------------------------------------------------------

func TestWrap(t *testing.T) {
	tests := []struct {
		name     string
		cfg      []string
		router   bool
		userView bool
		want     []string
	}{
		{
			name:   "switch immediate",
			cfg:    []string{"vlan 10", "quit"},
			router: false,
			want:   []string{"system-view", "vlan 10", "quit", "return"},
		},
		{
			name:     "user-view raw (timezone)",
			cfg:      []string{"clock timezone BRT minus 03:00:00"},
			router:   true,
			userView: true,
			want:     []string{"clock timezone BRT minus 03:00:00"},
		},
		{
			name:   "router commit",
			cfg:    []string{"bgp 100"},
			router: true,
			want:   []string{"system-view", "bgp 100", "commit", "return"},
		},
		{
			name:   "empty commands switch",
			cfg:    nil,
			router: false,
			want:   []string{"system-view", "return"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := wrap(tt.cfg, tt.router, tt.userView); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("wrap = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- isRouter ----------------------------------------------------------------

func TestIsRouter(t *testing.T) {
	tests := []struct {
		mode string
		name string
		want bool
	}{
		{"commit", "SW-ACC-01", true},
		{"COMMIT", "SW-ACC-01", true},
		{"immediate", "NE40-EDGE-01", false},
		{"  Immediate ", "NE40-EDGE-01", false},
		{"", "NE40-CORE-01", true},
		{"", "EDGE-01", true},
		{"", "SP-BNG-02", true},
		{"", "core-router-1", true},
		{"", "DC1-NE-01", true},
		{"", "SW-ACC-01", false},
		{"", "leaf-switch-99", false},
	}
	for _, tt := range tests {
		t.Run(tt.mode+"/"+tt.name, func(t *testing.T) {
			if got := isRouter(tt.mode, tt.name); got != tt.want {
				t.Fatalf("isRouter(%q,%q) = %v, want %v", tt.mode, tt.name, got, tt.want)
			}
		})
	}
}

// --- sanitize ----------------------------------------------------------------

func TestSanitize(t *testing.T) {
	tests := []struct{ in, want string }{
		{"a/b c:d\\e", "a_b_c_d_e"},
		{"  trimmed  ", "trimmed"},
		{"NE40/EDGE 01", "NE40_EDGE_01"},
		{"plain", "plain"},
	}
	for _, tt := range tests {
		if got := sanitize(tt.in); got != tt.want {
			t.Errorf("sanitize(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// --- Run: dry-run ------------------------------------------------------------

func TestRunDryRun(t *testing.T) {
	runner := &fakeRunner{}
	targets := map[string]config.Target{
		"10.0.0.1": tgt("NE40-EDGE-01", "10.0.0.1", "ssh", ""),
		"10.0.0.2": tgt("SW-ACC-01", "10.0.0.2", "ssh", ""),
	}
	cs := ChangeSet{
		Name: "dry",
		Changes: []Change{
			{Address: "10.0.0.1", Commands: []string{"bgp 100"}},
			{Address: "10.0.0.2", Commands: []string{"vlan 10"}},
			{Address: "10.0.0.9", Commands: []string{"x"}}, // not in targets
		},
	}
	results := Run(context.Background(), cs, Options{
		Targets: targets,
		SSH:     runner,
		Logger:  discardLogger(),
		DoApply: false,
	})

	if len(results) != 3 {
		t.Fatalf("results = %d, want 3", len(results))
	}
	if results[0].Mode != "commit" {
		t.Errorf("router dry-run Mode = %q, want commit", results[0].Mode)
	}
	if results[0].Applied {
		t.Error("dry-run must not mark Applied")
	}
	if results[1].Mode != "immediate" {
		t.Errorf("switch dry-run Mode = %q, want immediate", results[1].Mode)
	}
	if results[2].Err == nil {
		t.Error("missing target should set Err")
	}
	if len(runner.calls) != 0 {
		t.Errorf("dry-run must not connect, got %d calls", len(runner.calls))
	}
	// NumCmds reflects the raw command count.
	if results[0].NumCmds != 1 {
		t.Errorf("NumCmds = %d, want 1", results[0].NumCmds)
	}
}

// --- Run: apply --------------------------------------------------------------

func TestRunApplyRouterCommitAndErrors(t *testing.T) {
	backupDir := t.TempDir()
	outDir := t.TempDir()

	runner := &fakeRunner{
		fn: func(addr string, cmds []string, save bool) (transport.ConfigResult, error) {
			if isBackupCmds(cmds) {
				return transport.ConfigResult{Transcript: "running-config dump"}, nil
			}
			return transport.ConfigResult{Transcript: "apply transcript", Errors: []string{"% Invalid input"}}, nil
		},
	}
	targets := map[string]config.Target{
		"10.0.0.1": tgt("NE40-EDGE-01", "10.0.0.1", "ssh", ""),
	}
	cs := ChangeSet{Changes: []Change{{Address: "10.0.0.1", Commands: []string{"bgp 100"}}}}

	results := Run(context.Background(), cs, Options{
		Targets:   targets,
		SSH:       runner,
		Logger:    discardLogger(),
		BackupDir: backupDir,
		OutDir:    outDir,
		DoApply:   true,
		Save:      true,
	})
	if len(results) != 1 {
		t.Fatalf("results = %d", len(results))
	}
	r := results[0]
	if !r.Applied {
		t.Fatalf("expected Applied, got %+v", r)
	}
	if r.Mode != "commit" {
		t.Errorf("Mode = %q, want commit", r.Mode)
	}
	if len(r.CfgErrors) == 0 {
		t.Error("expected CfgErrors from runner result")
	}
	if r.Err != nil {
		t.Errorf("unexpected Err: %v", r.Err)
	}
	// Backup file written.
	if r.BackupPath == "" {
		t.Fatal("expected BackupPath set")
	}
	if _, err := os.Stat(r.BackupPath); err != nil {
		t.Errorf("backup file missing: %v", err)
	}
	// Transcript is rewritten to a file path that exists.
	if r.Transcript == "" {
		t.Fatal("expected transcript path")
	}
	if _, err := os.Stat(r.Transcript); err != nil {
		t.Errorf("transcript file missing: %v", err)
	}
	// Wrapped commands include commit (router) and save passthrough is true.
	call, ok := runner.applyCall("10.0.0.1")
	if !ok {
		t.Fatal("no apply call recorded")
	}
	want := []string{"system-view", "bgp 100", "commit", "return"}
	if !reflect.DeepEqual(call.cmds, want) {
		t.Errorf("apply cmds = %v, want %v", call.cmds, want)
	}
	if !call.save {
		t.Error("Save=true should be passed through to RunConfig")
	}
}

func TestRunApplySwitchImmediateNoCommit(t *testing.T) {
	runner := &fakeRunner{}
	targets := map[string]config.Target{
		"10.0.0.2": tgt("SW-ACC-01", "10.0.0.2", "ssh", ""),
	}
	cs := ChangeSet{Changes: []Change{{Address: "10.0.0.2", Commands: []string{"vlan 10", "quit"}}}}

	results := Run(context.Background(), cs, Options{
		Targets: targets,
		SSH:     runner,
		Logger:  discardLogger(),
		DoApply: true,
		Save:    false,
	})
	r := results[0]
	if !r.Applied || r.Mode != "immediate" {
		t.Fatalf("switch apply = %+v", r)
	}
	call, ok := runner.applyCall("10.0.0.2")
	if !ok {
		t.Fatal("no apply call")
	}
	want := []string{"system-view", "vlan 10", "quit", "return"}
	if !reflect.DeepEqual(call.cmds, want) {
		t.Errorf("apply cmds = %v, want %v (no commit)", call.cmds, want)
	}
	if call.save {
		t.Error("Save=false should not be passed as true")
	}
}

func TestRunApplyRunnerError(t *testing.T) {
	runner := &fakeRunner{
		fn: func(addr string, cmds []string, save bool) (transport.ConfigResult, error) {
			if isBackupCmds(cmds) {
				return transport.ConfigResult{Transcript: "cfg"}, nil
			}
			return transport.ConfigResult{}, errors.New("device refused")
		},
	}
	targets := map[string]config.Target{
		"10.0.0.3": tgt("SW-ERR-01", "10.0.0.3", "ssh", ""),
	}
	cs := ChangeSet{Changes: []Change{{Address: "10.0.0.3", Commands: []string{"x"}}}}
	results := Run(context.Background(), cs, Options{
		Targets:   targets,
		SSH:       runner,
		Logger:    discardLogger(),
		BackupDir: t.TempDir(),
		DoApply:   true,
	})
	r := results[0]
	if r.Err == nil {
		t.Fatal("expected Err on runner failure")
	}
	if r.Applied {
		t.Error("must not be Applied on error")
	}
}

func TestRunApplyBackupFailureContinues(t *testing.T) {
	runner := &fakeRunner{
		fn: func(addr string, cmds []string, save bool) (transport.ConfigResult, error) {
			if isBackupCmds(cmds) {
				return transport.ConfigResult{}, errors.New("backup unreachable")
			}
			return transport.ConfigResult{Transcript: "applied"}, nil
		},
	}
	targets := map[string]config.Target{
		"10.0.0.4": tgt("SW-ACC-04", "10.0.0.4", "ssh", ""),
	}
	cs := ChangeSet{Changes: []Change{{Address: "10.0.0.4", Commands: []string{"vlan 5"}}}}
	results := Run(context.Background(), cs, Options{
		Targets:   targets,
		SSH:       runner,
		Logger:    discardLogger(),
		BackupDir: t.TempDir(),
		DoApply:   true,
	})
	r := results[0]
	if !r.Applied {
		t.Fatalf("apply should continue after backup failure: %+v", r)
	}
	if r.BackupPath != "" {
		t.Errorf("BackupPath should stay empty on backup failure, got %q", r.BackupPath)
	}
}

func TestRunApplyTransportNotConfigured(t *testing.T) {
	// Telnet target but no Telnet runner provided.
	runner := &fakeRunner{}
	targets := map[string]config.Target{
		"10.0.0.5": tgt("SW-TEL-05", "10.0.0.5", "telnet", ""),
	}
	cs := ChangeSet{Changes: []Change{{Address: "10.0.0.5", Commands: []string{"vlan 5"}}}}
	results := Run(context.Background(), cs, Options{
		Targets: targets,
		SSH:     runner, // only SSH set
		Logger:  discardLogger(),
		DoApply: true,
	})
	r := results[0]
	if r.Err == nil {
		t.Fatal("expected Err for unconfigured telnet transport")
	}
	if len(runner.calls) != 0 {
		t.Errorf("SSH runner must not be used for a telnet target, got %d calls", len(runner.calls))
	}
}

func TestRunApplyTelnetRunnerUsed(t *testing.T) {
	sshRunner := &fakeRunner{}
	telRunner := &fakeRunner{}
	targets := map[string]config.Target{
		"10.0.0.6": tgt("SW-TEL-06", "10.0.0.6", "telnet", ""),
	}
	cs := ChangeSet{Changes: []Change{{Address: "10.0.0.6", Commands: []string{"vlan 6"}}}}
	results := Run(context.Background(), cs, Options{
		Targets: targets,
		SSH:     sshRunner,
		Telnet:  telRunner,
		Logger:  discardLogger(),
		DoApply: true,
	})
	if !results[0].Applied {
		t.Fatalf("telnet apply = %+v", results[0])
	}
	if len(telRunner.calls) == 0 {
		t.Error("telnet runner should have been used")
	}
	if len(sshRunner.calls) != 0 {
		t.Error("ssh runner should not have been used for telnet target")
	}
}

func TestRunApplyNoBackupNoOut(t *testing.T) {
	// BackupDir and OutDir empty: no backup call, transcript stays inline.
	runner := &fakeRunner{
		fn: func(addr string, cmds []string, save bool) (transport.ConfigResult, error) {
			return transport.ConfigResult{Transcript: "inline transcript"}, nil
		},
	}
	targets := map[string]config.Target{
		"10.0.0.7": tgt("SW-ACC-07", "10.0.0.7", "ssh", ""),
	}
	cs := ChangeSet{Changes: []Change{{Address: "10.0.0.7", Commands: []string{"vlan 7"}}}}
	results := Run(context.Background(), cs, Options{
		Targets: targets,
		SSH:     runner,
		Logger:  discardLogger(),
		DoApply: true,
	})
	r := results[0]
	if r.BackupPath != "" {
		t.Errorf("no BackupDir -> BackupPath should be empty, got %q", r.BackupPath)
	}
	if r.Transcript != "inline transcript" {
		t.Errorf("no OutDir -> transcript stays inline, got %q", r.Transcript)
	}
	// Only the apply call, no backup call.
	for _, c := range runner.calls {
		if isBackupCmds(c.cmds) {
			t.Error("backup call should not happen without BackupDir")
		}
	}
}

func TestRunMissingTargetOnly(t *testing.T) {
	runner := &fakeRunner{}
	cs := ChangeSet{Changes: []Change{{Address: "10.9.9.9", Commands: []string{"x"}}}}
	results := Run(context.Background(), cs, Options{
		Targets: map[string]config.Target{},
		SSH:     runner,
		Logger:  discardLogger(),
		DoApply: true,
	})
	if results[0].Err == nil {
		t.Fatal("expected Err for address not in targets")
	}
	if len(runner.calls) != 0 {
		t.Error("runner must not be called for missing target")
	}
}
