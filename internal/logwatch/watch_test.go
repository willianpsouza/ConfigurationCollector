package logwatch

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/willianpsouza/ConfigurationCollector/internal/telegram"
)

func TestTailAndSend(t *testing.T) {
	sent := make(chan string, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "getUpdates") {
			time.Sleep(30 * time.Millisecond) // evita busy-loop do commandLoop no teste
			_, _ = io.WriteString(w, `{"ok":true,"result":[]}`)
			return
		}
		_ = r.ParseForm()
		sent <- r.FormValue("chat_id") + "|" + r.FormValue("text")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	logPath := filepath.Join(t.TempDir(), "skynet.log")
	if err := os.WriteFile(logPath, []byte("linha pre-existente ignorada\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{Provider: "skynet", LogPath: logPath, DedupWindow: 5 * time.Minute,
		CriticalChat: "CRIT", WarningChat: "WARN"}
	w := New(cfg, telegram.NewWithBaseURL("T", srv.URL), discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = w.Run(ctx) }()

	time.Sleep(1300 * time.Millisecond) // deixa o tail abrir + posicionar no fim

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(optLine + "\n")
	_ = f.Close()

	select {
	case got := <-sent:
		if !strings.HasPrefix(got, "CRIT|") {
			t.Errorf("evento critico deveria ir p/ CRIT: %s", got)
		}
		if !strings.Contains(got, "skynet") || !strings.Contains(got, "OPTPWRABNORMAL") {
			t.Errorf("texto inesperado: %s", got)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("nao recebeu o alerta do tail")
	}
}

func TestCommandStart(t *testing.T) {
	reply := make(chan string, 4)
	var served atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "getUpdates") {
			if served.CompareAndSwap(false, true) {
				_, _ = io.WriteString(w, `{"ok":true,"result":[{"update_id":7,"message":{"text":"/start","chat":{"id":98765}}}]}`)
			} else {
				time.Sleep(30 * time.Millisecond)
				_, _ = io.WriteString(w, `{"ok":true,"result":[]}`)
			}
			return
		}
		_ = r.ParseForm()
		reply <- r.FormValue("chat_id") + "|" + r.FormValue("text")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	cfg := Config{Provider: "skynet", DedupWindow: time.Minute}
	w := New(cfg, telegram.NewWithBaseURL("T", srv.URL), discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.commandLoop(ctx)

	select {
	case got := <-reply:
		if !strings.HasPrefix(got, "98765|") || !strings.Contains(got, "LogBot") || !strings.Contains(got, "skynet") {
			t.Errorf("resposta /start inesperada: %s", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bot nao respondeu /start")
	}
}
