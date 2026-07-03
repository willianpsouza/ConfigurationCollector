// Command collector coleta as configuracoes dos equipamentos descritos no
// arquivo de alvos e as persiste em disco.
//
// Uso:
//
//	collector [-only <substr>] [-dry-run] <targets.json>
//
// -only    coleta apenas alvos cujo nome ou endereco contem <substr> (util para
//          validar 1 device por vez).
// -dry-run resolve e lista os alvos sem conectar.
//
// O modo daemon (scheduler + API) sera adicionado numa fase seguinte via
// subcomando "serve".
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/willianpsouza/ConfigurationCollector/internal/collector"
	"github.com/willianpsouza/ConfigurationCollector/internal/config"
	"github.com/willianpsouza/ConfigurationCollector/internal/storage"
	"github.com/willianpsouza/ConfigurationCollector/internal/transport"
)

func main() {
	only := flag.String("only", "", "coletar apenas alvos cujo nome/endereco contenha esta substring")
	dryRun := flag.Bool("dry-run", false, "resolver e listar alvos sem conectar")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Uso: collector [-only <substr>] [-dry-run] <targets.json>")
		flag.PrintDefaults()
	}
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(2)
	}
	cfgPath := flag.Arg(0)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		logger.Error("erro lendo config", "path", cfgPath, "error", err)
		os.Exit(1)
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		logger.Error("config invalida", "error", err)
		os.Exit(1)
	}

	if cfg.SSHLegacy != nil && cfg.SSHLegacy.Enabled {
		logger.Warn("SSH legacy habilitado — algoritmos antigos/inseguros permitidos")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go handleSignals(cancel, logger)

	// Transportes.
	hostKey := transport.HostKeyCallback(cfg.KnownHostsFile, logger)
	sshTransport := transport.NewSSH(hostKey, legacyOptions(cfg.SSHLegacy))
	telnetTransport := transport.NewTelnet()

	// Store (arquivos datados; git/API entram atras da mesma interface depois).
	store := storage.NewTimestamped(cfg.BaseDir)

	targets, stats := cfg.Targets(logger)
	if *only != "" {
		targets = filterTargets(targets, *only)
		logger.Info("filtro -only aplicado", "substr", *only, "alvos", len(targets))
	}
	logger.Info("alvos resolvidos",
		"total", stats.Total, "ativos", stats.Active,
		"inativos", stats.Inactive, "pulados_sem_senha", stats.Skipped,
		"a_coletar", len(targets))

	if len(targets) == 0 {
		logger.Warn("nenhum alvo a coletar")
		return
	}

	if *dryRun {
		for _, t := range targets {
			logger.Info("alvo (dry-run)",
				"asset", t.Name, "vendor", t.Vendor, "protocol", t.Protocol,
				"address", t.Address, "port", t.Port, "user", t.Username)
		}
		return
	}

	col := collector.New(collector.Options{
		Concurrency: cfg.Concurrency,
		MaxRetries:  cfg.MaxRetries,
		SSH:         sshTransport,
		Telnet:      telnetTransport,
		Store:       store,
		Logger:      logger,
	})

	logger.Info("iniciando coleta",
		"base_dir", cfg.BaseDir, "concurrency", cfg.Concurrency,
		"timeout_s", cfg.TimeoutSeconds, "max_retries", cfg.MaxRetries)

	sum := col.Run(ctx, targets)
	logger.Info("coleta finalizada",
		"total", sum.Total, "ok", sum.OK, "falhas", sum.Failed, "duracao", sum.Elapsed.String())

	if sum.Failed > 0 {
		os.Exit(1)
	}
}

func filterTargets(in []config.Target, substr string) []config.Target {
	s := strings.ToLower(substr)
	var out []config.Target
	for _, t := range in {
		// Endereco: match exato (evita "10.99.99.1" casar .10/.100/.16).
		// Nome: match por substring (conveniencia).
		if strings.EqualFold(t.Address, substr) || strings.Contains(strings.ToLower(t.Name), s) {
			out = append(out, t)
		}
	}
	return out
}

func handleSignals(cancel context.CancelFunc, logger *slog.Logger) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	logger.Warn("sinal de interrupcao recebido, cancelando...")
	cancel()
}

// legacyOptions converte a config de SSH legacy em opcoes do transporte. Quando
// habilitado sem listas explicitas, usa um conjunto ADITIVO (algoritmos modernos
// + legados) para funcionar tanto em equipamentos antigos (Huawei VRP antigo)
// quanto modernos (Mikrotik) sem excluir a negociacao segura.
func legacyOptions(l *config.SSHLegacy) *transport.SSHOptions {
	if l == nil || !l.Enabled {
		return nil
	}
	opt := &transport.SSHOptions{
		KexAlgorithms:     l.KexAlgorithms,
		Ciphers:           l.Ciphers,
		MACs:              l.MACs,
		HostKeyAlgorithms: l.HostKeyAlgorithms,
	}
	if len(opt.KexAlgorithms) == 0 {
		opt.KexAlgorithms = []string{
			"curve25519-sha256", "curve25519-sha256@libssh.org",
			"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
			"diffie-hellman-group14-sha256",
			// legados:
			"diffie-hellman-group-exchange-sha256",
			"diffie-hellman-group-exchange-sha1",
			"diffie-hellman-group14-sha1",
			"diffie-hellman-group1-sha1",
		}
	}
	if len(opt.Ciphers) == 0 {
		opt.Ciphers = []string{
			"chacha20-poly1305@openssh.com",
			"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
			"aes128-ctr", "aes192-ctr", "aes256-ctr",
			// legados:
			"aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc",
		}
	}
	if len(opt.MACs) == 0 {
		opt.MACs = []string{
			"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
			"hmac-sha2-256", "hmac-sha2-512",
			// legados:
			"hmac-sha1", "hmac-sha1-96",
		}
	}
	if len(opt.HostKeyAlgorithms) == 0 {
		opt.HostKeyAlgorithms = []string{
			"ssh-ed25519", "rsa-sha2-256", "rsa-sha2-512",
			"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
			// legados:
			"ssh-rsa", "ssh-dss",
		}
	}
	return opt
}
