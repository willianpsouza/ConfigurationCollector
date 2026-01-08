package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ziutek/telnet"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type Config struct {
	BaseDir        string     `json:"base_dir"`
	TimeoutSeconds int        `json:"timeout_seconds"`
	Concurrency    int        `json:"concurrency"`
	MaxRetries     int        `json:"max_retries"`
	KnownHostsFile string     `json:"known_hosts_file,omitempty"`
	SSHLegacy      *SSHLegacy `json:"ssh_legacy,omitempty"`
	Groups         []Group    `json:"groups"`
}

type SSHLegacy struct {
	Enabled           bool     `json:"enabled"`
	KexAlgorithms     []string `json:"kex_algorithms,omitempty"`
	Ciphers           []string `json:"ciphers,omitempty"`
	MACs              []string `json:"macs,omitempty"`
	HostKeyAlgorithms []string `json:"host_key_algorithms,omitempty"`
}

type Group struct {
	Vendor      string  `json:"vendor"` // "huawei" | "zte"
	Username    string  `json:"username"`
	Password    string  `json:"password,omitempty"`
	PasswordEnv string  `json:"password_env,omitempty"`
	Assets      []Asset `json:"assets"`
}

type Asset struct {
	Name        string `json:"name"`
	Address     string `json:"address"`
	Port        int    `json:"port"`
	Protocol    string `json:"protocol,omitempty"`    // "ssh" | "telnet" (default: "ssh")
	Username    string `json:"username,omitempty"`    // Override group username
	Password    string `json:"password,omitempty"`    // Override group password
	PasswordEnv string `json:"password_env,omitempty"` // Override group password_env
	Active      *bool  `json:"active,omitempty"`      // true|false (default: true)
}

type Job struct {
	Vendor    string
	Username  string
	Password  string
	Asset     Asset
	Protocol  string
	Timeout   time.Duration
	BaseDir   string
	Logger    *slog.Logger
	SSHLegacy *SSHLegacy
}

func main() {
	// Configurar logger estruturado
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	if len(os.Args) < 2 {
		fmt.Println("Uso: collector <targets.json>")
		os.Exit(2)
	}

	cfgPath := os.Args[1]
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		logger.Error("erro lendo config", "error", err)
		os.Exit(1)
	}

	// Validar configuração
	if err := cfg.Validate(); err != nil {
		logger.Error("config inválida", "error", err)
		os.Exit(1)
	}

	// Defaults
	if cfg.TimeoutSeconds <= 0 {
		cfg.TimeoutSeconds = 30
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 5
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = 0
	}
	if cfg.BaseDir == "" {
		cfg.BaseDir = "./coletas"
	}

	// Avisar sobre SSH legacy
	if cfg.SSHLegacy != nil && cfg.SSHLegacy.Enabled {
		logger.Warn("SSH legacy mode habilitado - algoritmos antigos/inseguros permitidos",
			"kex", cfg.SSHLegacy.KexAlgorithms,
			"ciphers", cfg.SSHLegacy.Ciphers,
			"macs", cfg.SSHLegacy.MACs,
		)
	}

	// Criar diretório de saída com data
	dayDir := time.Now().Format("2006-01-02")
	outDir := filepath.Join(cfg.BaseDir, dayDir)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		logger.Error("erro criando diretório", "dir", outDir, "error", err)
		os.Exit(1)
	}

	logger.Info("iniciando coleta",
		"config", cfgPath,
		"output_dir", outDir,
		"concurrency", cfg.Concurrency,
		"timeout", cfg.TimeoutSeconds,
		"max_retries", cfg.MaxRetries,
		"ssh_legacy", cfg.SSHLegacy != nil && cfg.SSHLegacy.Enabled,
	)

	// Context com cancelamento (Ctrl+C)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Warn("sinal de interrupção recebido, cancelando...")
		cancel()
	}()

	// Preparar host key callback
	hostKeyCallback := createHostKeyCallback(cfg.KnownHostsFile, logger)

	// Criar jobs
	jobs := make(chan Job, len(cfg.Groups)*10)
	var wg sync.WaitGroup

	// Workers
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for job := range jobs {
				select {
				case <-ctx.Done():
					logger.Warn("worker cancelado", "worker_id", workerID)
					return
				default:
				}

				if err := runJobWithRetry(ctx, job, cfg.MaxRetries, hostKeyCallback); err != nil {
					logger.Error("job falhou",
						"asset", job.Asset.Name,
						"vendor", job.Vendor,
						"address", job.Asset.Address,
						"protocol", job.Protocol,
						"error", err,
					)
				} else {
					logger.Info("job concluído",
						"asset", job.Asset.Name,
						"vendor", job.Vendor,
						"address", job.Asset.Address,
						"protocol", job.Protocol,
					)
				}
			}
		}(i)
	}

	// Enfileirar jobs
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	totalAssets := 0
	activeAssets := 0
	inactiveAssets := 0

	for _, g := range cfg.Groups {
		v := strings.ToLower(strings.TrimSpace(g.Vendor))
		groupPassword := g.GetPassword()

		for _, a := range g.Assets {
			totalAssets++

			// Verificar se o asset está ativo
			if !a.IsActive() {
				inactiveAssets++
				logger.Info("asset inativo, ignorando",
					"asset", a.Name,
					"address", a.Address,
				)
				continue
			}

			activeAssets++

			// Determinar credenciais (asset override ou group)
			username := a.Username
			if username == "" {
				username = g.Username
			}

			password := a.GetPassword()
			if password == "" {
				password = groupPassword
			}

			if password == "" {
				logger.Error("senha não configurada",
					"asset", a.Name,
					"vendor", v,
					"username", username,
				)
				continue
			}

			// Determinar protocolo
			protocol := strings.ToLower(strings.TrimSpace(a.Protocol))
			if protocol == "" {
				protocol = "ssh" // default
			}

			// Determinar porta
			port := a.Port
			if port == 0 {
				if protocol == "telnet" {
					port = 23
				} else {
					port = 22
				}
			}

			// Criar asset com configurações resolvidas
			resolvedAsset := a
			resolvedAsset.Port = port

			jobs <- Job{
				Vendor:    v,
				Username:  username,
				Password:  password,
				Asset:     resolvedAsset,
				Protocol:  protocol,
				Timeout:   timeout,
				BaseDir:   outDir,
				Logger:    logger,
				SSHLegacy: cfg.SSHLegacy,
			}
		}
	}
	close(jobs)

	logger.Info("jobs enfileirados",
		"total_assets", totalAssets,
		"active", activeAssets,
		"inactive", inactiveAssets,
	)

	// Aguardar conclusão
	wg.Wait()
	logger.Info("coleta finalizada")
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	if len(cfg.Groups) == 0 {
		return nil, errors.New("nenhum grupo definido em groups[]")
	}
	return &cfg, nil
}

func (c *Config) Validate() error {
	if c.Concurrency > 50 {
		return errors.New("concurrency muito alta (max: 50)")
	}
	if c.TimeoutSeconds > 300 {
		return errors.New("timeout muito alto (max: 300s)")
	}

	for i, g := range c.Groups {
		vendor := strings.ToLower(strings.TrimSpace(g.Vendor))
		if vendor != "huawei" && vendor != "zte" {
			return fmt.Errorf("grupo[%d]: vendor inválido %q (use huawei ou zte)", i, g.Vendor)
		}

		if g.Username == "" {
			return fmt.Errorf("grupo[%d]: username não pode ser vazio", i)
		}

		if g.Password == "" && g.PasswordEnv == "" {
			return fmt.Errorf("grupo[%d]: configure password ou password_env", i)
		}

		if len(g.Assets) == 0 {
			return fmt.Errorf("grupo[%d]: nenhum asset definido", i)
		}

		for j, a := range g.Assets {
			if a.Name == "" {
				return fmt.Errorf("grupo[%d].assets[%d]: name não pode ser vazio", i, j)
			}
			if net.ParseIP(a.Address) == nil {
				// Tenta resolver como hostname
				if _, err := net.LookupHost(a.Address); err != nil {
					return fmt.Errorf("grupo[%d].assets[%d]: endereço inválido %q", i, j, a.Address)
				}
			}
			if a.Port < 0 || a.Port > 65535 {
				return fmt.Errorf("grupo[%d].assets[%d]: porta inválida %d", i, j, a.Port)
			}

			// Validar protocolo
			if a.Protocol != "" {
				proto := strings.ToLower(strings.TrimSpace(a.Protocol))
				if proto != "ssh" && proto != "telnet" {
					return fmt.Errorf("grupo[%d].assets[%d]: protocolo inválido %q (use ssh ou telnet)", i, j, a.Protocol)
				}
			}
		}
	}
	return nil
}

func (g *Group) GetPassword() string {
	if g.PasswordEnv != "" {
		if pass := os.Getenv(g.PasswordEnv); pass != "" {
			return pass
		}
	}
	return g.Password
}

func (a *Asset) GetPassword() string {
	if a.PasswordEnv != "" {
		if pass := os.Getenv(a.PasswordEnv); pass != "" {
			return pass
		}
	}
	return a.Password
}

func (a *Asset) IsActive() bool {
	if a.Active == nil {
		return true // default: ativo
	}
	return *a.Active
}

func createHostKeyCallback(knownHostsPath string, logger *slog.Logger) ssh.HostKeyCallback {
	if knownHostsPath != "" {
		if _, err := os.Stat(knownHostsPath); err == nil {
			callback, err := knownhosts.New(knownHostsPath)
			if err != nil {
				logger.Warn("erro carregando known_hosts, usando modo inseguro",
					"path", knownHostsPath,
					"error", err,
				)
				return ssh.InsecureIgnoreHostKey()
			}
			logger.Info("usando known_hosts", "path", knownHostsPath)
			return callback
		}
		logger.Warn("arquivo known_hosts não encontrado, usando modo inseguro",
			"path", knownHostsPath,
		)
	} else {
		logger.Warn("known_hosts_file não configurado, usando modo inseguro (não recomendado para produção)")
	}
	return ssh.InsecureIgnoreHostKey()
}

func runJobWithRetry(ctx context.Context, job Job, maxRetries int, hostKeyCallback ssh.HostKeyCallback) error {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if attempt > 0 {
			backoff := time.Duration(attempt) * 2 * time.Second
			job.Logger.Info("tentando novamente",
				"asset", job.Asset.Name,
				"attempt", attempt,
				"max_retries", maxRetries,
				"backoff", backoff,
			)
			time.Sleep(backoff)
		}

		err := runJob(ctx, job, hostKeyCallback)
		if err == nil {
			return nil
		}
		lastErr = err
	}

	return fmt.Errorf("falhou após %d tentativas: %w", maxRetries+1, lastErr)
}

func runJob(ctx context.Context, job Job, hostKeyCallback ssh.HostKeyCallback) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	cmds, err := commandsForVendor(job.Vendor)
	if err != nil {
		return err
	}

	prompts := promptsForVendor(job.Vendor)

	var out string

	// Escolher protocolo
	switch job.Protocol {
	case "telnet":
		out, err = collectTelnet(ctx, job, cmds, prompts)
	case "ssh":
		out, err = collectSSH(ctx, job, cmds, prompts, hostKeyCallback)
	default:
		return fmt.Errorf("protocolo desconhecido: %q (use ssh ou telnet)", job.Protocol)
	}

	if err != nil {
		return err
	}

	safeName := sanitize(job.Asset.Name)
	safeIP := sanitize(job.Asset.Address)
	timestamp := time.Now().Format("150405") // HHMMSS
	filename := fmt.Sprintf("%s__%s__%s__%s__%s.txt", safeName, safeIP, job.Vendor, job.Protocol, timestamp)
	path := filepath.Join(job.BaseDir, filename)

	return writeAtomic(path, []byte(out), 0o644)
}

func commandsForVendor(vendor string) ([]string, error) {
	switch vendor {
	case "huawei":
		return []string{
			"screen-length 0 temporary",
			"display version",
			"display license",
			"display current-configuration",
			"display interface brief",
			"display interface description",
			"display interface transceiver",
			"display eth-trunk brief",
			"display bgp peer",
			"display ospf peer",
			"display isis peer",
		}, nil
	case "zte":
		return []string{
			"terminal length 0",
			"show version",
			"show license",
			"show running-config",
			"show interface brief",
			"show interface description",
			"show interface transceiver",
			"show port-channel brief",
			"show bgp summary",
			"show ospf neighbor",
			"show isis neighbor",
		}, nil
	default:
		return nil, fmt.Errorf("vendor desconhecido: %q (use huawei/zte)", vendor)
	}
}

func promptsForVendor(vendor string) []string {
	switch vendor {
	case "huawei":
		return []string{"<", ">", "]"}
	case "zte":
		return []string{"#", ">"}
	default:
		return []string{">", "#", "$"}
	}
}

func collectTelnet(ctx context.Context, job Job, cmds []string, prompts []string) (string, error) {
	addr := fmt.Sprintf("%s:%d", job.Asset.Address, job.Asset.Port)

	job.Logger.Info("conectando via telnet", "address", addr)

	// Conectar
	conn, err := telnet.DialTimeout("tcp", addr, job.Timeout)
	if err != nil {
		return "", fmt.Errorf("dial telnet: %w", err)
	}
	defer conn.Close()

	var result bytes.Buffer

	// Cabeçalho
	fmt.Fprintf(&result, "### ASSET=%s IP=%s VENDOR=%s PROTOCOL=telnet TIME=%s ###\n\n",
		job.Asset.Name, job.Asset.Address, job.Vendor, time.Now().Format(time.RFC3339))

	// Aguardar prompt de login
	if err := waitForString(conn, job.Timeout, "sername:", "ogin:"); err != nil {
		return result.String(), fmt.Errorf("timeout aguardando login prompt: %w", err)
	}

	// Enviar username
	if _, err := conn.Write([]byte(job.Username + "\n")); err != nil {
		return result.String(), fmt.Errorf("erro enviando username: %w", err)
	}

	// Aguardar prompt de senha
	if err := waitForString(conn, job.Timeout, "assword:"); err != nil {
		return result.String(), fmt.Errorf("timeout aguardando password prompt: %w", err)
	}

	// Enviar senha
	if _, err := conn.Write([]byte(job.Password + "\n")); err != nil {
		return result.String(), fmt.Errorf("erro enviando password: %w", err)
	}

	// Aguardar prompt inicial do sistema
	time.Sleep(2 * time.Second)

	// Executar comandos
	for _, cmd := range cmds {
		select {
		case <-ctx.Done():
			return result.String(), ctx.Err()
		default:
		}

		cmd = strings.TrimSpace(cmd)
		if cmd == "" {
			continue
		}

		fmt.Fprintf(&result, "\n\n==== CMD: %s ====\n", cmd)

		// Enviar comando
		if _, err := conn.Write([]byte(cmd + "\n")); err != nil {
			job.Logger.Warn("erro enviando comando",
				"cmd", cmd,
				"error", err,
			)
			continue
		}

		// Ler output
		output, err := readTelnetOutput(conn, job.Timeout, prompts)
		if err != nil {
			job.Logger.Warn("erro lendo output do comando",
				"cmd", cmd,
				"error", err,
			)
		}

		result.WriteString(output)
	}

	// Sair
	_, _ = conn.Write([]byte("quit\n"))
	time.Sleep(300 * time.Millisecond)

	return result.String(), nil
}

func collectSSH(ctx context.Context, job Job, cmds []string, prompts []string, hostKeyCallback ssh.HostKeyCallback) (string, error) {
	addr := fmt.Sprintf("%s:%d", job.Asset.Address, job.Asset.Port)

	job.Logger.Info("conectando via ssh", "address", addr)

	sshCfg := &ssh.ClientConfig{
		User:            job.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(job.Password)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         job.Timeout,
	}

	// Aplicar configurações SSH legacy se habilitadas
	if job.SSHLegacy != nil && job.SSHLegacy.Enabled {
		applySSHLegacyConfig(sshCfg, job.SSHLegacy, job.Logger)
	}

	dialer := net.Dialer{Timeout: job.Timeout}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return "", fmt.Errorf("dial tcp: %w", err)
	}
	defer conn.Close()

	c, chans, reqs, err := ssh.NewClientConn(conn, addr, sshCfg)
	if err != nil {
		return "", fmt.Errorf("ssh handshake: %w", err)
	}
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()

	// PTY para network OS
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := sess.RequestPty("vt100", 200, 80, modes); err != nil {
		return "", fmt.Errorf("request pty: %w", err)
	}

	stdin, err := sess.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("stdin pipe: %w", err)
	}

	stdout, err := sess.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("stdout pipe: %w", err)
	}

	if err := sess.Shell(); err != nil {
		return "", fmt.Errorf("start shell: %w", err)
	}

	var result bytes.Buffer

	// Cabeçalho
	fmt.Fprintf(&result, "### ASSET=%s IP=%s VENDOR=%s PROTOCOL=ssh TIME=%s ###\n\n",
		job.Asset.Name, job.Asset.Address, job.Vendor, time.Now().Format(time.RFC3339))

	// Aguarda prompt inicial
	_, err = readUntilPrompt(ctx, stdout, 10*time.Second, prompts)
	if err != nil {
		job.Logger.Warn("timeout aguardando prompt inicial", "error", err)
	}

	// Executa comandos
	for _, cmd := range cmds {
		select {
		case <-ctx.Done():
			return result.String(), ctx.Err()
		default:
		}

		cmd = strings.TrimSpace(cmd)
		if cmd == "" {
			continue
		}

		fmt.Fprintf(&result, "\n\n==== CMD: %s ====\n", cmd)

		// Envia comando
		if _, err := stdin.Write([]byte(cmd + "\n")); err != nil {
			return result.String(), fmt.Errorf("write cmd %q: %w", cmd, err)
		}

		// Lê até encontrar prompt
		output, err := readUntilPrompt(ctx, stdout, job.Timeout, prompts)
		if err != nil {
			job.Logger.Warn("erro lendo output do comando",
				"cmd", cmd,
				"error", err,
			)
			result.WriteString(output) // Salva o que conseguiu ler
			continue
		}

		result.WriteString(output)
	}

	// Tenta sair limpo
	_, _ = stdin.Write([]byte("quit\n"))
	time.Sleep(300 * time.Millisecond)

	return result.String(), nil
}

func applySSHLegacyConfig(cfg *ssh.ClientConfig, legacy *SSHLegacy, logger *slog.Logger) {
	// Configurações padrão para equipamentos antigos se não especificadas
	if len(legacy.KexAlgorithms) == 0 {
		legacy.KexAlgorithms = []string{
			"diffie-hellman-group-exchange-sha256",
			"diffie-hellman-group-exchange-sha1",
			"diffie-hellman-group14-sha1",
			"diffie-hellman-group1-sha1",
		}
	}

	if len(legacy.Ciphers) == 0 {
		legacy.Ciphers = []string{
			"aes128-ctr",
			"aes192-ctr",
			"aes256-ctr",
			"aes128-cbc",
			"aes192-cbc",
			"aes256-cbc",
			"3des-cbc",
		}
	}

	if len(legacy.MACs) == 0 {
		legacy.MACs = []string{
			"hmac-sha2-256",
			"hmac-sha2-512",
			"hmac-sha1",
			"hmac-sha1-96",
		}
	}

	if len(legacy.HostKeyAlgorithms) == 0 {
		legacy.HostKeyAlgorithms = []string{
			"ssh-rsa",
			"ssh-dss",
		}
	}

	// Aplicar configurações
	cfg.Config.KeyExchanges = legacy.KexAlgorithms
	cfg.Config.Ciphers = legacy.Ciphers
	cfg.Config.MACs = legacy.MACs

	logger.Warn("configurações SSH legacy aplicadas",
		"kex", legacy.KexAlgorithms,
		"ciphers", legacy.Ciphers,
		"macs", legacy.MACs,
		"host_keys", legacy.HostKeyAlgorithms,
	)
}

func waitForString(conn *telnet.Conn, timeout time.Duration, patterns ...string) error {
	deadline := time.Now().Add(timeout)
	var buf bytes.Buffer

	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout aguardando padrão")
		}

		data := make([]byte, 4096)
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(data)

		if n > 0 {
			buf.Write(data[:n])
			output := buf.String()

			for _, pattern := range patterns {
				if strings.Contains(strings.ToLower(output), strings.ToLower(pattern)) {
					return nil
				}
			}
		}

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return err
		}

		time.Sleep(100 * time.Millisecond)
	}
}

func readTelnetOutput(conn *telnet.Conn, timeout time.Duration, prompts []string) (string, error) {
	deadline := time.Now().Add(timeout)
	var buf bytes.Buffer

	for {
		if time.Now().After(deadline) {
			return buf.String(), fmt.Errorf("timeout lendo output")
		}

		data := make([]byte, 4096)
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(data)

		if n > 0 {
			buf.Write(data[:n])
			output := buf.String()

			// Verificar se encontrou prompt
			for _, prompt := range prompts {
				if strings.Contains(output, prompt) {
					return output, nil
				}
			}
		}

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return buf.String(), nil
		}

		time.Sleep(100 * time.Millisecond)
	}
}

func readUntilPrompt(ctx context.Context, reader io.Reader, timeout time.Duration, prompts []string) (string, error) {
	var buf bytes.Buffer
	deadline := time.Now().Add(timeout)
	tmpBuf := make([]byte, 4096)

	for {
		select {
		case <-ctx.Done():
			return buf.String(), ctx.Err()
		default:
		}

		if time.Now().After(deadline) {
			return buf.String(), fmt.Errorf("timeout aguardando prompt")
		}

		// Define timeout de leitura
		if conn, ok := reader.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		}

		n, err := reader.Read(tmpBuf)
		if n > 0 {
			buf.Write(tmpBuf[:n])

			// Verifica se encontrou prompt
			output := buf.String()
			for _, prompt := range prompts {
				if strings.Contains(output, prompt) {
					return output, nil
				}
			}
		}

		if err != nil {
			if err == io.EOF {
				return buf.String(), nil
			}
			// Ignora timeout errors, continua tentando
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return buf.String(), err
		}

		time.Sleep(100 * time.Millisecond)
	}
}

func sanitize(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.ReplaceAll(s, " ", "_")
	return s
}

func writeAtomic(path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-collect-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr != nil {
		_ = os.Remove(tmpName)
		return werr
	}
	if cerr != nil {
		_ = os.Remove(tmpName)
		return cerr
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}
