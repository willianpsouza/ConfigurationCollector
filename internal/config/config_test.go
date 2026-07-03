package config

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func boolPtr(b bool) *bool { return &b }

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "targets.json")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("escrevendo temp: %v", err)
	}
	return p
}

func TestLoadOK(t *testing.T) {
	js := `{
	  "base_dir": "/data",
	  "timeout_seconds": 20,
	  "concurrency": 4,
	  "max_retries": 2,
	  "groups": [
	    {"vendor":"huawei","username":"admin","password":"p",
	     "assets":[{"name":"r1","address":"127.0.0.1"}]}
	  ]
	}`
	p := writeTemp(t, js)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load erro: %v", err)
	}
	if cfg.BaseDir != "/data" || cfg.TimeoutSeconds != 20 || cfg.Concurrency != 4 || cfg.MaxRetries != 2 {
		t.Errorf("campos incorretos: %+v", cfg)
	}
	if len(cfg.Groups) != 1 || len(cfg.Groups[0].Assets) != 1 {
		t.Fatalf("grupos/assets incorretos: %+v", cfg.Groups)
	}
	if cfg.Groups[0].Assets[0].Name != "r1" {
		t.Errorf("asset name = %q", cfg.Groups[0].Assets[0].Name)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "naoexiste.json")); err == nil {
		t.Fatal("Load de arquivo inexistente deveria falhar")
	}
}

func TestLoadBadJSON(t *testing.T) {
	p := writeTemp(t, `{ isto nao e json valido `)
	if _, err := Load(p); err == nil {
		t.Fatal("Load de json invalido deveria falhar")
	}
}

func TestLoadNoGroups(t *testing.T) {
	p := writeTemp(t, `{"groups":[]}`)
	if _, err := Load(p); err == nil {
		t.Fatal("Load sem grupos deveria falhar")
	}
}

func TestApplyDefaults(t *testing.T) {
	var c Config // tudo zero
	c.MaxRetries = -5
	c.ApplyDefaults()
	if c.TimeoutSeconds != defaultTimeoutSeconds {
		t.Errorf("timeout default = %d", c.TimeoutSeconds)
	}
	if c.Concurrency != defaultConcurrency {
		t.Errorf("concurrency default = %d", c.Concurrency)
	}
	if c.BaseDir != defaultBaseDir {
		t.Errorf("basedir default = %q", c.BaseDir)
	}
	if c.MaxRetries != 0 {
		t.Errorf("maxretries negativo deveria virar 0, veio %d", c.MaxRetries)
	}
}

func TestApplyDefaultsPreserva(t *testing.T) {
	c := Config{TimeoutSeconds: 10, Concurrency: 3, MaxRetries: 7, BaseDir: "/x"}
	c.ApplyDefaults()
	if c.TimeoutSeconds != 10 || c.Concurrency != 3 || c.MaxRetries != 7 || c.BaseDir != "/x" {
		t.Errorf("ApplyDefaults sobrescreveu valores validos: %+v", c)
	}
}

// baseValid produz uma config valida que passa em Validate().
func baseValid() *Config {
	return &Config{
		TimeoutSeconds: 30,
		Concurrency:    5,
		Groups: []Group{{
			Vendor:   "huawei",
			Username: "admin",
			Password: "secret",
			Assets: []Asset{{
				Name:     "r1",
				Address:  "127.0.0.1",
				Port:     22,
				Protocol: "ssh",
			}},
		}},
	}
}

func TestValidateOK(t *testing.T) {
	if err := baseValid().Validate(); err != nil {
		t.Fatalf("config valida falhou em Validate: %v", err)
	}
}

func TestValidateHostnameLookupOK(t *testing.T) {
	c := baseValid()
	c.Groups[0].Assets[0].Address = "localhost" // resolve sem rede
	if err := c.Validate(); err != nil {
		t.Fatalf("localhost deveria resolver: %v", err)
	}
}

func TestValidateAllAssetsHaveCreds(t *testing.T) {
	// grupo sem password/password_env, mas todos os assets tem credencial.
	c := baseValid()
	c.Groups[0].Password = ""
	c.Groups[0].PasswordEnv = ""
	c.Groups[0].Assets[0].Password = "asset-pw"
	if err := c.Validate(); err != nil {
		t.Fatalf("grupo sem senha mas com creds nos assets deveria passar: %v", err)
	}
}

func TestValidateErrors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(c *Config)
	}{
		{"concurrency alta", func(c *Config) { c.Concurrency = 51 }},
		{"timeout alto", func(c *Config) { c.TimeoutSeconds = 301 }},
		{"vendor invalido", func(c *Config) { c.Groups[0].Vendor = "naoexiste" }},
		{"username vazio", func(c *Config) { c.Groups[0].Username = "" }},
		{"sem senha e sem creds nos assets", func(c *Config) {
			c.Groups[0].Password = ""
			c.Groups[0].PasswordEnv = ""
		}},
		{"sem assets", func(c *Config) { c.Groups[0].Assets = nil }},
		{"name vazio", func(c *Config) { c.Groups[0].Assets[0].Name = "" }},
		{"address vazio", func(c *Config) { c.Groups[0].Assets[0].Address = "" }},
		{"address invalido", func(c *Config) {
			c.Groups[0].Assets[0].Address = "host-que-nao-existe.invalid"
		}},
		{"porta alta", func(c *Config) { c.Groups[0].Assets[0].Port = 70000 }},
		{"porta negativa", func(c *Config) { c.Groups[0].Assets[0].Port = -1 }},
		{"protocolo invalido", func(c *Config) { c.Groups[0].Assets[0].Protocol = "http" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := baseValid()
			tc.mutate(c)
			if err := c.Validate(); err == nil {
				t.Fatalf("caso %q: esperava erro, veio nil", tc.name)
			}
		})
	}
}

func TestTargetsResolucao(t *testing.T) {
	t.Setenv("CC_TEST_PW", "envpass")

	cfg := &Config{
		TimeoutSeconds: 30,
		Groups: []Group{
			{
				Vendor:   "Huawei", // maiuscula: deve ser normalizado para minuscula
				Username: "admin",
				Password: "gpass",
				Assets: []Asset{
					{Name: "a1", Address: "10.0.0.1"},                                              // default ssh:22, creds do grupo
					{Name: "a2", Address: "10.0.0.2", Username: "u2", Password: "p2", Protocol: "TELNET"}, // override + telnet:23
					{Name: "a3", Address: "10.0.0.3", Active: boolPtr(false)},                      // inativo
					{Name: "a5", Address: "10.0.0.5", PasswordEnv: "CC_TEST_PW"},                   // senha via env
					{Name: "a6", Address: "10.0.0.6", Port: 2222},                                  // porta explicita
				},
			},
			{
				Vendor:   "huawei",
				Username: "admin2", // sem senha no grupo nem no asset
				Assets: []Asset{
					{Name: "a4", Address: "10.0.0.4"}, // sem senha -> skipped
				},
			},
		},
	}

	// logger real para cobrir logInfo/logError (branch nao-nil)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	targets, stats := cfg.Targets(logger)

	if stats.Total != 6 {
		t.Errorf("Total = %d, quer 6", stats.Total)
	}
	if stats.Active != 5 {
		t.Errorf("Active = %d, quer 5", stats.Active)
	}
	if stats.Inactive != 1 {
		t.Errorf("Inactive = %d, quer 1", stats.Inactive)
	}
	if stats.Skipped != 1 {
		t.Errorf("Skipped = %d, quer 1", stats.Skipped)
	}
	if len(targets) != 4 {
		t.Fatalf("targets = %d, quer 4 (%+v)", len(targets), targets)
	}

	byName := map[string]Target{}
	for _, tg := range targets {
		byName[tg.Name] = tg
	}

	a1 := byName["a1"]
	if a1.Vendor != "huawei" {
		t.Errorf("a1.Vendor = %q, quer huawei (normalizado)", a1.Vendor)
	}
	if a1.Protocol != "ssh" || a1.Port != 22 {
		t.Errorf("a1 proto/porta = %s/%d, quer ssh/22", a1.Protocol, a1.Port)
	}
	if a1.Username != "admin" || a1.Password != "gpass" {
		t.Errorf("a1 creds = %s/%s, quer admin/gpass", a1.Username, a1.Password)
	}
	if a1.Timeout != 30*time.Second {
		t.Errorf("a1.Timeout = %v, quer 30s", a1.Timeout)
	}

	a2 := byName["a2"]
	if a2.Protocol != "telnet" || a2.Port != 23 {
		t.Errorf("a2 proto/porta = %s/%d, quer telnet/23", a2.Protocol, a2.Port)
	}
	if a2.Username != "u2" || a2.Password != "p2" {
		t.Errorf("a2 creds override = %s/%s", a2.Username, a2.Password)
	}

	a5 := byName["a5"]
	if a5.Password != "envpass" {
		t.Errorf("a5.Password = %q, quer envpass (via env)", a5.Password)
	}
	if a5.Username != "admin" {
		t.Errorf("a5.Username = %q, quer admin (fallback grupo)", a5.Username)
	}

	a6 := byName["a6"]
	if a6.Port != 2222 {
		t.Errorf("a6.Port = %d, quer 2222 (explicita)", a6.Port)
	}

	if _, ok := byName["a3"]; ok {
		t.Error("a3 inativo nao deveria estar nos targets")
	}
	if _, ok := byName["a4"]; ok {
		t.Error("a4 sem senha nao deveria estar nos targets")
	}
}

func TestTargetsLoggerNil(t *testing.T) {
	cfg := &Config{
		TimeoutSeconds: 10,
		Groups: []Group{{
			Vendor:   "huawei",
			Username: "admin",
			Assets: []Asset{
				{Name: "inativo", Address: "10.0.0.1", Active: boolPtr(false)},
				{Name: "semsenha", Address: "10.0.0.2"},
			},
		}},
	}
	// logger nil nao deve dar panic mesmo passando pelos caminhos de log.
	targets, stats := cfg.Targets(nil)
	if len(targets) != 0 {
		t.Errorf("targets = %d, quer 0", len(targets))
	}
	if stats.Inactive != 1 || stats.Skipped != 1 {
		t.Errorf("stats inesperado: %+v", stats)
	}
}

func TestResolvePassword(t *testing.T) {
	t.Setenv("CC_HAS_VAL", "fromenv")
	t.Setenv("CC_EMPTY", "")

	if got := resolvePassword("lit", "CC_HAS_VAL"); got != "fromenv" {
		t.Errorf("env com valor: got %q", got)
	}
	if got := resolvePassword("lit", "CC_EMPTY"); got != "lit" {
		t.Errorf("env vazia deveria cair no literal: got %q", got)
	}
	if got := resolvePassword("lit", ""); got != "lit" {
		t.Errorf("sem env: got %q", got)
	}
	if got := resolvePassword("", "CC_UNSET_XYZ"); got != "" {
		t.Errorf("env inexistente e literal vazio: got %q", got)
	}
}

func TestSmallHelpers(t *testing.T) {
	if defaultPort("telnet") != 23 {
		t.Error("defaultPort telnet != 23")
	}
	if defaultPort("ssh") != 22 || defaultPort("") != 22 {
		t.Error("defaultPort default != 22")
	}
	if normalizeProtocol("  SSH ") != "ssh" {
		t.Error("normalizeProtocol nao normalizou")
	}
	if !isActive(Asset{}) {
		t.Error("Active nil deveria ser ativo")
	}
	if isActive(Asset{Active: boolPtr(false)}) {
		t.Error("Active=false deveria ser inativo")
	}
	if !isActive(Asset{Active: boolPtr(true)}) {
		t.Error("Active=true deveria ser ativo")
	}
	if allAssetsHaveCreds(Group{Assets: []Asset{{Password: "x"}, {}}}) {
		t.Error("um asset sem cred -> allAssetsHaveCreds false")
	}
	if !allAssetsHaveCreds(Group{Assets: []Asset{{Password: "x"}, {PasswordEnv: "Y"}}}) {
		t.Error("todos com cred -> allAssetsHaveCreds true")
	}
}
