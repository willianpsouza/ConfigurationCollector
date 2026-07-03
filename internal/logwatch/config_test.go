package logwatch

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeConf(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "logbot.conf")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadConfig(t *testing.T) {
	p := writeConf(t, `# comentario
provider = skynet
log_path = /var/log/skynet.log
dedup_minutes = 5
telegram_token = "123:ABC"
critical_chat = -100111
warning_chat  = -100222
`)
	c, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if c.Provider != "skynet" || c.Token != "123:ABC" || c.CriticalChat != "-100111" || c.WarningChat != "-100222" {
		t.Errorf("config = %+v", c)
	}
	if c.DedupWindow != 5*time.Minute {
		t.Errorf("dedup = %v", c.DedupWindow)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	// sem provider/log_path/dedup -> usa defaults; token presente.
	p := writeConf(t, "telegram_token = T\n")
	c, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if c.LogPath != "/var/log/skynet.log" || c.DedupWindow != 5*time.Minute {
		t.Errorf("defaults errados: %+v", c)
	}
}

func TestLoadConfigErrors(t *testing.T) {
	if _, err := LoadConfig("/nao/existe.conf"); err == nil {
		t.Error("arquivo inexistente deveria dar erro")
	}
	p := writeConf(t, "provider = skynet\n") // sem token
	if _, err := LoadConfig(p); err == nil {
		t.Error("token vazio deveria dar erro")
	}
}
