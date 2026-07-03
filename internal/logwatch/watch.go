package logwatch

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/willianpsouza/ConfigurationCollector/internal/telegram"
)

// Watcher segue o syslog, classifica, faz rate-limit e despacha pro Telegram.
type Watcher struct {
	cfg    Config
	tg     *telegram.Client
	logger *slog.Logger
	store  *ConfigStore // enriquecimento com descricao da porta (opcional)

	mu   sync.Mutex
	last map[string]sentState // dedup por Event.Key()
}

type sentState struct {
	at    time.Time
	count int // eventos suprimidos desde o ultimo envio
}

// New cria o Watcher.
func New(cfg Config, tg *telegram.Client, logger *slog.Logger) *Watcher {
	w := &Watcher{cfg: cfg, tg: tg, logger: logger, last: map[string]sentState{},
		store: NewConfigStore(cfg.ColetasDir)}
	return w
}

// Run inicia o poller de comandos, o reload das coletas e o tail do log
// (bloqueia ate ctx cancelar).
func (w *Watcher) Run(ctx context.Context) error {
	go w.commandLoop(ctx)
	if w.store.Enabled() {
		if err := w.store.Reload(); err != nil {
			w.logger.Warn("falha carregando coletas", "error", err, "dir", w.cfg.ColetasDir)
		}
		go w.reloadLoop(ctx)
	}
	w.logger.Info("logbot iniciado", "provider", w.cfg.Provider, "log", w.cfg.LogPath,
		"dedup", w.cfg.DedupWindow.String(), "enriquece", w.store.Enabled())
	return w.tail(ctx)
}

// reloadLoop recarrega o indice das coletas periodicamente (collector roda diario).
func (w *Watcher) reloadLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := w.store.Reload(); err != nil {
				w.logger.Warn("falha recarregando coletas", "error", err)
			}
		}
	}
}

// onLine processa uma linha do log.
func (w *Watcher) onLine(line string) {
	ev, ok := Parse(line)
	if !ok {
		return
	}
	count, send := w.rateLimit(ev)
	if !send {
		return
	}
	if w.store.Enabled() {
		info := w.store.Info(ev.Addr, ev.Iface)
		ev.Desc, ev.IP, ev.VLAN = info.Desc, info.IP, info.VLAN
	}
	chat := w.cfg.CriticalChat
	if ev.Category == Warning {
		chat = w.cfg.WarningChat
	}
	text := "[" + w.cfg.Provider + "] " + ev.Format(count)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := w.tg.Send(ctx, chat, text); err != nil {
		w.logger.Warn("falha enviando telegram", "error", err, "device", ev.Device, "iface", ev.Iface)
	}
}

// rateLimit aplica 1 envio por Key a cada DedupWindow. Devolve a contagem
// acumulada e se deve enviar agora.
func (w *Watcher) rateLimit(ev Event) (int, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	st, seen := w.last[ev.Key()]
	if seen && now.Sub(st.at) < w.cfg.DedupWindow {
		st.count++
		w.last[ev.Key()] = st
		return 0, false
	}
	count := st.count + 1
	w.last[ev.Key()] = sentState{at: now, count: 0}
	return count, true
}

// tail segue o arquivo de log a partir do fim, resistente a rotacao (offset
// menor que o atual = arquivo truncado/rotacionado -> reabre do inicio).
func (w *Watcher) tail(ctx context.Context) error {
	f, err := os.Open(w.cfg.LogPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	off, _ := f.Seek(0, io.SeekEnd)

	var partial []byte
	buf := make([]byte, 64*1024)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}

		st, err := os.Stat(w.cfg.LogPath)
		if err != nil {
			continue
		}
		if st.Size() < off { // rotacionado/truncado
			_ = f.Close()
			nf, err := os.Open(w.cfg.LogPath)
			if err != nil {
				continue
			}
			f = nf
			off = 0
			partial = nil
		}

		for {
			if _, err := f.Seek(off, io.SeekStart); err != nil {
				break
			}
			n, err := f.Read(buf)
			if n > 0 {
				off += int64(n)
				data := append(partial, buf[:n]...)
				lines := bytes.Split(data, []byte("\n"))
				partial = append([]byte(nil), lines[len(lines)-1]...)
				for _, ln := range lines[:len(lines)-1] {
					w.onLine(strings.TrimRight(string(ln), "\r"))
				}
			}
			if err == io.EOF || n == 0 {
				break
			}
		}
	}
}

// commandLoop responde /start e /status via getUpdates (long-poll).
func (w *Watcher) commandLoop(ctx context.Context) {
	var offset int64
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		ups, err := w.tg.GetUpdates(ctx, offset, 30)
		if err != nil {
			time.Sleep(3 * time.Second)
			continue
		}
		for _, u := range ups {
			offset = u.UpdateID + 1
			cmd := strings.TrimSpace(strings.ToLower(u.Text))
			switch {
			case strings.HasPrefix(cmd, "/start"):
				reply := "🤖 LogBot ativo — provedor: " + w.cfg.Provider +
					"\nAlertas de rede (optico/link/BGP-OSPF/hardware) deste parque." +
					"\nchat_id deste chat: " + u.ChatID +
					"\n(use este id em critical_chat/warning_chat no logbot.conf)"
				sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				_ = w.tg.Send(sctx, u.ChatID, reply)
				cancel()
			case strings.HasPrefix(cmd, "/status"):
				sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				_ = w.tg.Send(sctx, u.ChatID, "✅ "+w.cfg.Provider+" LogBot rodando. Monitorando "+w.cfg.LogPath)
				cancel()
			}
		}
	}
}
