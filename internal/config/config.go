// Package config carrega e valida o arquivo de alvos (targets.json) e resolve os
// alvos efetivos de coleta (aplicando defaults e overrides por asset).
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/willianpsouza/ConfigurationCollector/internal/vendor"
)

// Config e o arquivo raiz de configuracao do coletor.
type Config struct {
	BaseDir        string     `json:"base_dir"`
	TimeoutSeconds int        `json:"timeout_seconds"`
	Concurrency    int        `json:"concurrency"`
	MaxRetries     int        `json:"max_retries"`
	KnownHostsFile string     `json:"known_hosts_file,omitempty"`
	SSHLegacy      *SSHLegacy `json:"ssh_legacy,omitempty"`
	// Schedule e uma expressao cron para o modo daemon (ex.: "0 3 * * *").
	// Ignorada no modo one-shot. Vazia = sem agendamento automatico.
	Schedule string  `json:"schedule,omitempty"`
	Groups   []Group `json:"groups"`
}

// SSHLegacy habilita algoritmos antigos/inseguros para equipamentos legados.
type SSHLegacy struct {
	Enabled           bool     `json:"enabled"`
	KexAlgorithms     []string `json:"kex_algorithms,omitempty"`
	Ciphers           []string `json:"ciphers,omitempty"`
	MACs              []string `json:"macs,omitempty"`
	HostKeyAlgorithms []string `json:"host_key_algorithms,omitempty"`
}

// Group agrupa assets que compartilham vendor e credenciais padrao.
type Group struct {
	Vendor      string  `json:"vendor"`
	Username    string  `json:"username"`
	Password    string  `json:"password,omitempty"`
	PasswordEnv string  `json:"password_env,omitempty"`
	Assets      []Asset `json:"assets"`
}

// Asset e um equipamento individual. Campos vazios herdam do Group.
type Asset struct {
	Name        string `json:"name"`
	Address     string `json:"address"`
	Port        int    `json:"port,omitempty"`
	Protocol    string `json:"protocol,omitempty"`     // "ssh" (default) | "telnet"
	Username    string `json:"username,omitempty"`     // override do group
	Password    string `json:"password,omitempty"`     // override do group
	PasswordEnv string `json:"password_env,omitempty"` // override do group
	Active      *bool  `json:"active,omitempty"`       // default: true
}

// Target e um alvo de coleta ja resolvido (credenciais, protocolo e porta
// definidos), pronto para ser executado.
type Target struct {
	Vendor   string
	Protocol string // "ssh" | "telnet"
	Username string
	Password string
	Address  string
	Port     int
	Name     string
	Timeout  time.Duration
}

// Stats resume a resolucao dos alvos.
type Stats struct {
	Total    int
	Active   int
	Inactive int
	Skipped  int // ativos porem sem senha resolvida
}

const (
	defaultTimeoutSeconds = 30
	defaultConcurrency    = 5
	defaultBaseDir        = "./coletas"
	maxConcurrency        = 50
	maxTimeoutSeconds     = 300
)

// Load le e faz o parse do arquivo de configuracao (sem validar semantica).
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse json: %w", err)
	}
	if len(cfg.Groups) == 0 {
		return nil, errors.New("nenhum grupo definido em groups[]")
	}
	return &cfg, nil
}

// ApplyDefaults preenche valores nao informados com os padroes.
func (c *Config) ApplyDefaults() {
	if c.TimeoutSeconds <= 0 {
		c.TimeoutSeconds = defaultTimeoutSeconds
	}
	if c.Concurrency <= 0 {
		c.Concurrency = defaultConcurrency
	}
	if c.MaxRetries < 0 {
		c.MaxRetries = 0
	}
	if c.BaseDir == "" {
		c.BaseDir = defaultBaseDir
	}
}

// Validate confere limites e integridade referencial (vendors registrados,
// enderecos resolviveis, portas e protocolos validos).
func (c *Config) Validate() error {
	if c.Concurrency > maxConcurrency {
		return fmt.Errorf("concurrency muito alta (max: %d)", maxConcurrency)
	}
	if c.TimeoutSeconds > maxTimeoutSeconds {
		return fmt.Errorf("timeout muito alto (max: %ds)", maxTimeoutSeconds)
	}

	for i, g := range c.Groups {
		if !vendor.IsRegistered(g.Vendor) {
			return fmt.Errorf("grupo[%d]: vendor invalido %q (registrados: %s)",
				i, g.Vendor, strings.Join(vendor.Names(), ", "))
		}
		if g.Username == "" {
			return fmt.Errorf("grupo[%d]: username nao pode ser vazio", i)
		}
		if g.Password == "" && g.PasswordEnv == "" {
			// Permitido se TODOS os assets do grupo tiverem credencial propria;
			// a checagem final de senha vazia ocorre em Targets().
			if !allAssetsHaveCreds(g) {
				return fmt.Errorf("grupo[%d]: configure password ou password_env (ou credencial em todos os assets)", i)
			}
		}
		if len(g.Assets) == 0 {
			return fmt.Errorf("grupo[%d]: nenhum asset definido", i)
		}
		for j, a := range g.Assets {
			if a.Name == "" {
				return fmt.Errorf("grupo[%d].assets[%d]: name nao pode ser vazio", i, j)
			}
			if a.Address == "" {
				return fmt.Errorf("grupo[%d].assets[%d] (%s): address nao pode ser vazio", i, j, a.Name)
			}
			if net.ParseIP(a.Address) == nil {
				if _, err := net.LookupHost(a.Address); err != nil {
					return fmt.Errorf("grupo[%d].assets[%d] (%s): endereco invalido %q", i, j, a.Name, a.Address)
				}
			}
			if a.Port < 0 || a.Port > 65535 {
				return fmt.Errorf("grupo[%d].assets[%d] (%s): porta invalida %d", i, j, a.Name, a.Port)
			}
			if p := normalizeProtocol(a.Protocol); p != "" && p != "ssh" && p != "telnet" {
				return fmt.Errorf("grupo[%d].assets[%d] (%s): protocolo invalido %q (use ssh ou telnet)", i, j, a.Name, a.Protocol)
			}
		}
	}
	return nil
}

func allAssetsHaveCreds(g Group) bool {
	for _, a := range g.Assets {
		if a.Password == "" && a.PasswordEnv == "" {
			return false
		}
	}
	return true
}

// Targets resolve os alvos ativos de coleta, aplicando overrides por asset e
// defaults de protocolo/porta. Alvos inativos ou sem senha sao contabilizados em
// Stats e registrados via logger (se nao-nil), mas nao retornados.
func (c *Config) Targets(logger *slog.Logger) ([]Target, Stats) {
	timeout := time.Duration(c.TimeoutSeconds) * time.Second
	var stats Stats
	var targets []Target

	for _, g := range c.Groups {
		groupVendor := strings.ToLower(strings.TrimSpace(g.Vendor))
		groupPass := resolvePassword(g.Password, g.PasswordEnv)

		for _, a := range g.Assets {
			stats.Total++

			if !isActive(a) {
				stats.Inactive++
				logInfo(logger, "asset inativo, ignorando", "asset", a.Name, "address", a.Address)
				continue
			}
			stats.Active++

			username := a.Username
			if username == "" {
				username = g.Username
			}
			password := resolvePassword(a.Password, a.PasswordEnv)
			if password == "" {
				password = groupPass
			}
			if password == "" {
				stats.Skipped++
				logError(logger, "senha nao resolvida, pulando asset",
					"asset", a.Name, "vendor", groupVendor, "username", username)
				continue
			}

			protocol := normalizeProtocol(a.Protocol)
			if protocol == "" {
				protocol = "ssh"
			}
			port := a.Port
			if port == 0 {
				port = defaultPort(protocol)
			}

			targets = append(targets, Target{
				Vendor:   groupVendor,
				Protocol: protocol,
				Username: username,
				Password: password,
				Address:  a.Address,
				Port:     port,
				Name:     a.Name,
				Timeout:  timeout,
			})
		}
	}
	return targets, stats
}

func defaultPort(protocol string) int {
	if protocol == "telnet" {
		return 23
	}
	return 22
}

func normalizeProtocol(p string) string { return strings.ToLower(strings.TrimSpace(p)) }

func isActive(a Asset) bool {
	if a.Active == nil {
		return true
	}
	return *a.Active
}

// resolvePassword devolve a senha da env var (se definida e nao-vazia) ou o
// literal. Prefere env var por seguranca.
func resolvePassword(literal, env string) string {
	if env != "" {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	return literal
}

func logInfo(l *slog.Logger, msg string, args ...any) {
	if l != nil {
		l.Info(msg, args...)
	}
}

func logError(l *slog.Logger, msg string, args ...any) {
	if l != nil {
		l.Error(msg, args...)
	}
}
