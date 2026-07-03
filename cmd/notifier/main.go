// Command notifier (LogBot) segue o syslog central, classifica os eventos de
// rede que importam (optico/link/BGP-OSPF/hardware) e envia alertas a um bot do
// Telegram, com rate-limit para nao inundar o time de infra.
//
// Config: /etc/provengo/logbot/logbot.conf (ou -config).
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/willianpsouza/ConfigurationCollector/internal/logwatch"
	"github.com/willianpsouza/ConfigurationCollector/internal/telegram"
)

func main() {
	confPath := flag.String("config", "/etc/provengo/logbot/logbot.conf", "arquivo de configuracao")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := logwatch.LoadConfig(*confPath)
	if err != nil {
		logger.Error("erro lendo config", "path", *confPath, "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		<-ch
		logger.Info("encerrando...")
		cancel()
	}()

	tg := telegram.New(cfg.Token)
	w := logwatch.New(*cfg, tg, logger)
	if err := w.Run(ctx); err != nil && ctx.Err() == nil {
		logger.Error("logbot parou", "error", err)
		os.Exit(1)
	}
}
