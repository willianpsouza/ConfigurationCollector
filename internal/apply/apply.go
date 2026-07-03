// Package apply aplica change-sets de configuracao nos devices, reusando o
// transport (SSH/telnet) do coletor.
//
// Seguranca: dry-run e o padrao no CLI; aqui, Run so conecta se DoApply=true.
// Antes de aplicar, faz backup do running-config. Envolve a sequencia conforme
// o tipo de equipamento:
//   - switch (VRP5): comandos valem na hora (immediate);
//   - router (VRP8/NE): so valem apos "commit";
//   - se Save=true, "save" roda na sequencia (persiste).
package apply

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/willianpsouza/ConfigurationCollector/internal/config"
	"github.com/willianpsouza/ConfigurationCollector/internal/transport"
)

// Change e a mudanca para um device.
type Change struct {
	Address  string   `json:"address"`
	Comment  string   `json:"comment,omitempty"`
	Mode     string   `json:"mode,omitempty"` // "commit"|"immediate"|"" (auto por nome)
	Commands []string `json:"commands"`       // comandos crus de config (sem system-view/return)
}

// ChangeSet e um conjunto de mudancas.
type ChangeSet struct {
	Name    string   `json:"name"`
	Changes []Change `json:"changes"`
}

// LoadChangeSet le um change-set de arquivo JSON.
func LoadChangeSet(path string) (*ChangeSet, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cs ChangeSet
	if err := json.Unmarshal(b, &cs); err != nil {
		return nil, fmt.Errorf("parse changeset: %w", err)
	}
	return &cs, nil
}

// Options configura a aplicacao.
type Options struct {
	Targets   map[string]config.Target // por endereco
	SSH       transport.ConfigRunner
	Telnet    transport.ConfigRunner
	Logger    *slog.Logger
	BackupDir string
	OutDir    string
	DoApply   bool // false = dry-run (nao conecta)
	Save      bool
}

// Result e o resultado por device.
type Result struct {
	Address    string
	Name       string
	Mode       string
	NumCmds    int
	Applied    bool
	CfgErrors  []string
	BackupPath string
	Transcript string
	Err        error
}

// Run processa o change-set. Em dry-run, apenas resolve e devolve (sem conexao).
func Run(ctx context.Context, cs ChangeSet, o Options) []Result {
	var results []Result
	for _, ch := range cs.Changes {
		r := Result{Address: ch.Address, NumCmds: len(ch.Commands)}
		tgt, ok := o.Targets[ch.Address]
		if !ok {
			r.Err = fmt.Errorf("device %s nao esta no targets.json", ch.Address)
			results = append(results, r)
			continue
		}
		r.Name = tgt.Name
		router := isRouter(ch.Mode, tgt.Name)
		if router {
			r.Mode = "commit"
		} else {
			r.Mode = "immediate"
		}

		if !o.DoApply {
			results = append(results, r) // dry-run: sem conexao
			continue
		}

		runner := o.SSH
		if tgt.Protocol == "telnet" {
			runner = o.Telnet
		}
		if runner == nil {
			r.Err = fmt.Errorf("transporte %q nao configurado", tgt.Protocol)
			results = append(results, r)
			continue
		}
		sess := transport.Session{
			Vendor: tgt.Vendor, Name: tgt.Name, Address: tgt.Address, Port: tgt.Port,
			Username: tgt.Username, Password: tgt.Password, Timeout: tgt.Timeout,
		}

		// Backup do running-config antes de aplicar.
		if o.BackupDir != "" {
			if p, err := backup(ctx, runner, sess, o); err != nil {
				o.Logger.Warn("backup falhou (seguindo)", "device", tgt.Name, "error", err)
			} else {
				r.BackupPath = p
			}
		}

		cmds := wrap(ch.Commands, router)
		res, err := runner.RunConfig(ctx, sess, cmds, o.Save, o.Logger)
		r.Transcript = res.Transcript
		r.CfgErrors = res.Errors
		if err != nil {
			r.Err = err
			results = append(results, r)
			continue
		}
		r.Applied = true
		if o.OutDir != "" {
			r.Transcript = writeTranscript(o.OutDir, tgt.Name, res.Transcript)
		}
		results = append(results, r)
	}
	return results
}

// wrap monta a sequencia completa: system-view, comandos, commit (router), return.
func wrap(cfg []string, router bool) []string {
	out := make([]string, 0, len(cfg)+3)
	out = append(out, "system-view")
	out = append(out, cfg...)
	if router {
		out = append(out, "commit")
	}
	out = append(out, "return")
	return out
}

// isRouter decide se aplica commit. Mode explicito vence; senao heuristica por
// nome (NE/EDGE/BNG/router = VRP8).
func isRouter(mode, name string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "commit":
		return true
	case "immediate":
		return false
	}
	n := strings.ToUpper(name)
	for _, k := range []string{"NE40", "NE80", "NE8000", "NE20", "EDGE", "BNG", "-NE-", "ROUTER"} {
		if strings.Contains(n, k) {
			return true
		}
	}
	return false
}

func backup(ctx context.Context, runner transport.ConfigRunner, s transport.Session, o Options) (string, error) {
	res, err := runner.RunConfig(ctx, s, []string{"display current-configuration"}, false, o.Logger)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(o.BackupDir, 0o755); err != nil {
		return "", err
	}
	ts := time.Now().Format("20060102-150405")
	path := filepath.Join(o.BackupDir, fmt.Sprintf("%s__%s__pre-apply.txt", sanitize(s.Name), ts))
	if err := os.WriteFile(path, []byte(res.Transcript), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func writeTranscript(dir, name, transcript string) string {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ""
	}
	ts := time.Now().Format("20060102-150405")
	path := filepath.Join(dir, fmt.Sprintf("%s__%s__apply.txt", sanitize(name), ts))
	if err := os.WriteFile(path, []byte(transcript), 0o644); err != nil {
		return ""
	}
	return path
}

func sanitize(s string) string {
	r := strings.NewReplacer("/", "_", " ", "_", ":", "_", "\\", "_")
	return r.Replace(strings.TrimSpace(s))
}
