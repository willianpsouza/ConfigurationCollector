// Command apply aplica um change-set de configuracao nos devices.
//
// SEGURANCA: dry-run e o PADRAO. Nada e enviado sem -apply. Antes de aplicar,
// faz backup do running-config de cada device.
//
// Uso:
//
//	apply -targets targets.json -changeset changeset.json            # dry-run
//	apply -targets targets.json -changeset changeset.json -apply     # aplica (running)
//	apply ... -apply -save                                           # aplica e persiste
//	apply ... -apply -only 10.99.99.1                                # so 1 device
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/willianpsouza/ConfigurationCollector/internal/apply"
	"github.com/willianpsouza/ConfigurationCollector/internal/config"
	"github.com/willianpsouza/ConfigurationCollector/internal/transport"
)

func main() {
	targetsPath := flag.String("targets", "", "targets.json (credenciais/porta/protocolo por device)")
	changesetPath := flag.String("changeset", "", "changeset.json (comandos por device)")
	doApply := flag.Bool("apply", false, "APLICA de verdade (sem esta flag = dry-run)")
	save := flag.Bool("save", false, "persiste a config (save) apos aplicar")
	only := flag.String("only", "", "aplicar apenas ao device com este endereco")
	backupDir := flag.String("backup-dir", "./apply-backups", "onde salvar o backup do running-config")
	outDir := flag.String("out", "./apply-transcripts", "onde salvar os transcripts da aplicacao")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if *targetsPath == "" || *changesetPath == "" {
		fmt.Fprintln(os.Stderr, "uso: apply -targets targets.json -changeset changeset.json [-apply] [-save] [-only X]")
		os.Exit(2)
	}

	cfg, err := config.Load(*targetsPath)
	if err != nil {
		logger.Error("erro lendo targets", "error", err)
		os.Exit(1)
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		logger.Error("targets invalido", "error", err)
		os.Exit(1)
	}
	targets, _ := cfg.Targets(nil)
	byAddr := map[string]config.Target{}
	for _, t := range targets {
		byAddr[t.Address] = t
	}

	cs, err := apply.LoadChangeSet(*changesetPath)
	if err != nil {
		logger.Error("erro lendo changeset", "error", err)
		os.Exit(1)
	}
	if *only != "" {
		var filtered []apply.Change
		for _, c := range cs.Changes {
			if c.Address == *only {
				filtered = append(filtered, c)
			}
		}
		cs.Changes = filtered
	}

	// Transportes.
	hostKey := transport.HostKeyCallback(cfg.KnownHostsFile, logger)
	var legacy *transport.SSHOptions
	if cfg.SSHLegacy != nil && cfg.SSHLegacy.Enabled {
		legacy = transport.DefaultSSHOptions()
	}
	sshRunner := transport.NewSSH(hostKey, legacy)
	telnetRunner := transport.NewTelnet()

	mode := "DRY-RUN (nada enviado)"
	if *doApply {
		mode = "APLICANDO"
		if *save {
			mode += " + SAVE"
		}
	}
	fmt.Printf("=== %s | changeset=%q | devices=%d ===\n", mode, cs.Name, len(cs.Changes))

	results := apply.Run(context.Background(), *cs, apply.Options{
		Targets:   byAddr,
		SSH:       sshRunner,
		Telnet:    telnetRunner,
		Logger:    logger,
		BackupDir: *backupDir,
		OutDir:    *outDir,
		DoApply:   *doApply,
		Save:      *save,
	})

	ok, fail := 0, 0
	for _, r := range results {
		if !*doApply {
			fmt.Printf("[dry-run] %-34s %-13s modo=%s cmds=%d\n", short(r.Name), r.Address, r.Mode, r.NumCmds)
			continue
		}
		switch {
		case r.Err != nil:
			fail++
			fmt.Printf("[ERRO]  %-34s %-13s %v\n", short(r.Name), r.Address, r.Err)
		case len(r.CfgErrors) > 0:
			fail++
			fmt.Printf("[ERRO]  %-34s %-13s erros CLI: %s\n", short(r.Name), r.Address, strings.Join(r.CfgErrors, " | "))
			if r.BackupPath != "" {
				fmt.Printf("        backup: %s\n", r.BackupPath)
			}
		default:
			ok++
			fmt.Printf("[OK]    %-34s %-13s modo=%s cmds=%d backup=%s\n", short(r.Name), r.Address, r.Mode, r.NumCmds, r.BackupPath)
		}
	}
	if *doApply {
		fmt.Printf("=== resultado: OK=%d FALHA=%d ===\n", ok, fail)
		if fail > 0 {
			os.Exit(1)
		}
	} else {
		fmt.Println("=== dry-run: rode com -apply para enviar (backup automatico antes) ===")
	}
}

func short(name string) string {
	if i := strings.Index(name, "-10-99-99-"); i > 0 {
		return name[:i]
	}
	if len(name) > 34 {
		return name[:34]
	}
	return name
}
