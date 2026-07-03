package logwatch

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config e a configuracao do logbot (arquivo key=value em
// /etc/provengo/logbot/logbot.conf).
type Config struct {
	Provider     string        // nome do provedor (ex.: skynet) — usado no /start e no prefixo dos alertas
	LogPath      string        // caminho do syslog central
	DedupWindow  time.Duration // janela de rate-limit por (device+iface+evento)
	Token        string        // token do bot Telegram
	CriticalChat string        // chat_id p/ CRITICO (optico/peer-down/hardware)
	WarningChat  string        // chat_id p/ AVISO (link)
}

// LoadConfig le o arquivo key=value. Linhas: "chave = valor"; "#" e comentario.
func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	kv := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		kv[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	c := &Config{
		Provider:     firstNonEmpty(kv["provider"], "provedor"),
		LogPath:      firstNonEmpty(kv["log_path"], "/var/log/skynet.log"),
		Token:        kv["telegram_token"],
		CriticalChat: kv["critical_chat"],
		WarningChat:  kv["warning_chat"],
	}
	mins := 5
	if v := kv["dedup_minutes"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			mins = n
		}
	}
	c.DedupWindow = time.Duration(mins) * time.Minute

	if c.Token == "" {
		return nil, fmt.Errorf("config: telegram_token vazio em %s", path)
	}
	return c, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
