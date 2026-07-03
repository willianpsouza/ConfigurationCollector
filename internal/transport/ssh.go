package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/willianpsouza/ConfigurationCollector/internal/vendor"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// SSHOptions carrega algoritmos legados para equipamentos antigos. Nil = usar
// apenas os padroes seguros da lib.
type SSHOptions struct {
	KexAlgorithms     []string
	Ciphers           []string
	MACs              []string
	HostKeyAlgorithms []string
}

// DefaultSSHOptions devolve o conjunto ADITIVO (algoritmos modernos + legados)
// usado quando ssh_legacy esta habilitado — funciona em equipamentos antigos
// (VRP antigo) e modernos sem excluir negociacao segura.
func DefaultSSHOptions() *SSHOptions {
	return &SSHOptions{
		KexAlgorithms: []string{
			"curve25519-sha256", "curve25519-sha256@libssh.org",
			"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
			"diffie-hellman-group14-sha256",
			"diffie-hellman-group-exchange-sha256", "diffie-hellman-group-exchange-sha1",
			"diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1",
		},
		Ciphers: []string{
			"chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
			"aes128-ctr", "aes192-ctr", "aes256-ctr",
			"aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc",
		},
		MACs: []string{
			"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
			"hmac-sha2-256", "hmac-sha2-512", "hmac-sha1", "hmac-sha1-96",
		},
		HostKeyAlgorithms: []string{
			"ssh-ed25519", "rsa-sha2-256", "rsa-sha2-512",
			"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ssh-rsa", "ssh-dss",
		},
	}
}

// SSH implementa Transport sobre golang.org/x/crypto/ssh.
type SSH struct {
	hostKey ssh.HostKeyCallback
	legacy  *SSHOptions
}

// NewSSH cria o transporte SSH. hostKey nao pode ser nil; use HostKeyCallback
// para construi-lo a partir de um known_hosts (ou modo inseguro).
func NewSSH(hostKey ssh.HostKeyCallback, legacy *SSHOptions) *SSH {
	return &SSH{hostKey: hostKey, legacy: legacy}
}

// HostKeyCallback devolve um callback de verificacao de host key. Se o arquivo
// known_hosts existir e for valido, verifica de verdade; caso contrario cai
// para modo inseguro (com aviso no log).
func HostKeyCallback(knownHostsPath string, logger *slog.Logger) ssh.HostKeyCallback {
	if knownHostsPath == "" {
		logger.Warn("known_hosts_file nao configurado, usando modo inseguro (nao recomendado em producao)")
		return ssh.InsecureIgnoreHostKey()
	}
	if _, err := os.Stat(knownHostsPath); err != nil {
		logger.Warn("known_hosts nao encontrado, usando modo inseguro", "path", knownHostsPath)
		return ssh.InsecureIgnoreHostKey()
	}
	cb, err := knownhosts.New(knownHostsPath)
	if err != nil {
		logger.Warn("erro carregando known_hosts, usando modo inseguro", "path", knownHostsPath, "error", err)
		return ssh.InsecureIgnoreHostKey()
	}
	logger.Info("usando known_hosts", "path", knownHostsPath)
	return cb
}

// Collect conecta via SSH e coleta conforme o modo do driver.
func (t *SSH) Collect(ctx context.Context, s Session, d vendor.Driver, logger *slog.Logger) (string, error) {
	logger.Info("conectando via ssh", "address", s.Addr(), "mode", d.Mode().String())

	cfg := &ssh.ClientConfig{
		User:            s.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(s.Password)},
		HostKeyCallback: t.hostKey,
		Timeout:         s.Timeout,
	}
	t.applyLegacy(cfg, logger)

	dialer := net.Dialer{Timeout: s.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", s.Addr())
	if err != nil {
		return "", fmt.Errorf("dial tcp: %w", err)
	}
	defer conn.Close()

	c, chans, reqs, err := ssh.NewClientConn(conn, s.Addr(), cfg)
	if err != nil {
		return "", fmt.Errorf("ssh handshake: %w", err)
	}
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()

	if d.Mode() == vendor.ModeExec {
		return collectExec(ctx, client, s, d, logger)
	}
	return collectShell(ctx, client, s, d, logger)
}

// collectExec roda cada comando como um exec SSH separado.
func collectExec(ctx context.Context, client *ssh.Client, s Session, d vendor.Driver, logger *slog.Logger) (string, error) {
	var out bytes.Buffer
	header(&out, s, "ssh", time.Now())

	for _, cmd := range d.Commands() {
		select {
		case <-ctx.Done():
			return out.String(), ctx.Err()
		default:
		}
		cmdBanner(&out, cmd)

		sess, err := client.NewSession()
		if err != nil {
			return out.String(), fmt.Errorf("new session: %w", err)
		}
		var stderr bytes.Buffer
		sess.Stderr = &stderr
		b, err := sess.Output(cmd)
		sess.Close()

		out.Write(b)
		if err != nil {
			logger.Warn("comando exec falhou", "cmd", cmd, "error", err, "stderr", stderr.String())
			if stderr.Len() > 0 {
				out.Write(stderr.Bytes())
			}
		}
	}
	return out.String(), nil
}

// collectShell abre um shell interativo com PTY e envia os comandos em sequencia.
func collectShell(ctx context.Context, client *ssh.Client, s Session, d vendor.Driver, logger *slog.Logger) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()

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

	var out bytes.Buffer
	header(&out, s, "ssh", time.Now())

	// Canais SSH nao honram SetReadDeadline; lemos numa goroutine dedicada e
	// aplicamos timeout total + idle via select para nunca bloquear.
	stream := newStreamer(stdout)
	const idle = 2500 * time.Millisecond

	// Aguarda o prompt inicial (best-effort).
	if _, err := readStream(ctx, stream, stdin, 10*time.Second, idle); err != nil {
		logger.Warn("timeout aguardando prompt inicial", "error", err)
	}

	// Setup (desabilitar paginacao etc.) — saida descartada.
	for _, cmd := range d.Setup() {
		if _, err := stdin.Write([]byte(cmd + "\n")); err != nil {
			return out.String(), fmt.Errorf("write setup %q: %w", cmd, err)
		}
		_, _ = readStream(ctx, stream, stdin, s.Timeout, idle)
	}

	for _, cmd := range d.Commands() {
		select {
		case <-ctx.Done():
			return out.String(), ctx.Err()
		default:
		}
		cmdBanner(&out, cmd)
		if _, err := stdin.Write([]byte(cmd + "\n")); err != nil {
			return out.String(), fmt.Errorf("write cmd %q: %w", cmd, err)
		}
		got, err := readStream(ctx, stream, stdin, s.Timeout, idle)
		out.WriteString(got)
		if err != nil {
			logger.Warn("erro lendo output do comando", "cmd", cmd, "error", err)
		}
	}

	if exit := d.Exit(); exit != "" {
		_, _ = stdin.Write([]byte(exit + "\n"))
		time.Sleep(300 * time.Millisecond)
	}
	return out.String(), nil
}

// newStreamer le continuamente de r numa goroutine, entregando os chunks por um
// channel (fechado no EOF/erro). Necessario porque canais SSH nao honram
// SetReadDeadline — sem isso um Read sem prompt trava indefinidamente.
func newStreamer(r io.Reader) <-chan []byte {
	ch := make(chan []byte, 256)
	go func() {
		defer close(ch)
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				c := make([]byte, n)
				copy(c, buf[:n])
				ch <- c
			}
			if err != nil {
				return
			}
		}
	}()
	return ch
}

// moreRe casa o marcador de paginacao "---- More ----" (Huawei/Cisco/etc.).
var moreRe = regexp.MustCompile(`(?i)-{2,}\s*more\s*-{2,}`)

// promptRe casa um prompt de CLI ANCORADO NO FIM do buffer: <HOST>, [HOST] ou
// HOST# / HOST>. Ancorar no fim evita casar um "<" ou ">" solto no meio da saida
// (que causava retorno prematuro e dessincronizacao comando/resposta).
var promptRe = regexp.MustCompile(`(?:^|\n)[ \t]*(?:<[^<>\r\n]{1,63}>|\[[^\[\]\r\n]{1,63}\]|[A-Za-z0-9][\w.\-]{0,63}[#>])[ \t]*$`)

// endsWithPrompt informa se a saida termina num prompt de CLI. Olha so a cauda
// do buffer por eficiencia.
func endsWithPrompt(b []byte) bool {
	const tail = 256
	if len(b) > tail {
		b = b[len(b)-tail:]
	}
	return promptRe.Match(b)
}

// readStream acumula chunks ate casar um prompt, ficar idle (sem dados novos por
// idleTimeout = fim provavel da saida) ou estourar o timeout total.
//
// O idle so e armado APOS o primeiro byte de resposta: equipamentos lentos
// (routers VRP8) podem demorar segundos para comecar a responder, e nesse
// intervalo vale apenas o timeout total — senao a saida voltaria vazia.
//
// Quando detecta o marcador de paginacao "---- More ----", envia um espaco por
// pager para avancar a pagina (fallback caso "screen-length 0" nao pegue) e
// remove o marcador do buffer para nao poluir a saida.
func readStream(ctx context.Context, ch <-chan []byte, pager io.Writer, total, idleTimeout time.Duration) (string, error) {
	var buf bytes.Buffer
	deadline := time.NewTimer(total)
	defer deadline.Stop()

	idle := time.NewTimer(idleTimeout)
	idle.Stop()
	defer idle.Stop()
	var idleC <-chan time.Time // nil ate chegar o primeiro chunk

	rearmIdle := func() {
		if !idle.Stop() {
			select {
			case <-idle.C:
			default:
			}
		}
		idle.Reset(idleTimeout)
		idleC = idle.C
	}

	for {
		select {
		case <-ctx.Done():
			return buf.String(), ctx.Err()
		case <-deadline.C:
			if buf.Len() > 0 {
				return buf.String(), nil // parcial: melhor que nada
			}
			return buf.String(), fmt.Errorf("timeout total sem resposta")
		case <-idleC:
			return buf.String(), nil // silencio apos dados: fim da saida
		case chunk, ok := <-ch:
			if !ok {
				return buf.String(), nil // EOF
			}
			buf.Write(chunk)
			// Paginacao: avanca a pagina antes de considerar prompt/idle.
			if pager != nil && moreRe.Match(buf.Bytes()) {
				_, _ = pager.Write([]byte(" "))
				b := moreRe.ReplaceAll(buf.Bytes(), nil)
				buf.Reset()
				buf.Write(b)
				rearmIdle()
				continue
			}
			if endsWithPrompt(buf.Bytes()) {
				return buf.String(), nil
			}
			rearmIdle()
		}
	}
}

// RunConfig aplica comandos de configuracao via shell interativo. Os comandos
// devem incluir a entrada/saida de contexto (ex.: system-view ... return). Se
// save=true, persiste a config no fim (save + confirmacao "y").
func (t *SSH) RunConfig(ctx context.Context, s Session, cmds []string, save bool, logger *slog.Logger) (ConfigResult, error) {
	logger.Info("apply ssh", "address", s.Addr(), "cmds", len(cmds), "save", save)

	cfg := &ssh.ClientConfig{
		User:            s.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(s.Password)},
		HostKeyCallback: t.hostKey,
		Timeout:         s.Timeout,
	}
	t.applyLegacy(cfg, logger)

	dialer := net.Dialer{Timeout: s.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", s.Addr())
	if err != nil {
		return ConfigResult{}, fmt.Errorf("dial tcp: %w", err)
	}
	defer conn.Close()

	c, chans, reqs, err := ssh.NewClientConn(conn, s.Addr(), cfg)
	if err != nil {
		return ConfigResult{}, fmt.Errorf("ssh handshake: %w", err)
	}
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return ConfigResult{}, fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()

	modes := ssh.TerminalModes{ssh.ECHO: 0, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := sess.RequestPty("vt100", 200, 80, modes); err != nil {
		return ConfigResult{}, fmt.Errorf("request pty: %w", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		return ConfigResult{}, err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return ConfigResult{}, err
	}
	if err := sess.Shell(); err != nil {
		return ConfigResult{}, fmt.Errorf("start shell: %w", err)
	}

	stream := newStreamer(stdout)
	const idle = 2000 * time.Millisecond
	var tr bytes.Buffer

	_, _ = readStream(ctx, stream, stdin, 8*time.Second, idle)
	// desabilita paginacao para nao truncar respostas
	_, _ = stdin.Write([]byte("screen-length 0 temporary\n"))
	_, _ = readStream(ctx, stream, stdin, s.Timeout, idle)

	for _, cmd := range cmds {
		if _, err := stdin.Write([]byte(cmd + "\n")); err != nil {
			return ConfigResult{Transcript: tr.String()}, fmt.Errorf("write %q: %w", cmd, err)
		}
		out, _ := readStream(ctx, stream, stdin, s.Timeout, idle)
		tr.WriteString(out)
		// Responde automaticamente prompts [Y/N] emitidos pelo comando.
		for i := 0; i < 3 && awaitsConfirm(out); i++ {
			_, _ = stdin.Write([]byte("y\n"))
			out, _ = readStream(ctx, stream, stdin, s.Timeout, idle)
			tr.WriteString(out)
		}
	}

	if save {
		// Assume-se que o chamador ja retornou a user-view (return). Persiste.
		_, _ = stdin.Write([]byte("save\n"))
		out, _ := readStream(ctx, stream, stdin, s.Timeout, idle)
		tr.WriteString(out)
		if strings.Contains(strings.ToUpper(out), "Y/N") || strings.Contains(strings.ToLower(out), "are you sure") {
			_, _ = stdin.Write([]byte("y\n"))
			out2, _ := readStream(ctx, stream, stdin, s.Timeout, idle)
			tr.WriteString(out2)
		}
	}

	res := ConfigResult{Transcript: tr.String()}
	res.Errors = scanErrors(res.Transcript)
	return res, nil
}

func (t *SSH) applyLegacy(cfg *ssh.ClientConfig, logger *slog.Logger) {
	if t.legacy == nil {
		return
	}
	if len(t.legacy.KexAlgorithms) > 0 {
		cfg.KeyExchanges = t.legacy.KexAlgorithms
	}
	if len(t.legacy.Ciphers) > 0 {
		cfg.Ciphers = t.legacy.Ciphers
	}
	if len(t.legacy.MACs) > 0 {
		cfg.MACs = t.legacy.MACs
	}
	if len(t.legacy.HostKeyAlgorithms) > 0 {
		cfg.HostKeyAlgorithms = t.legacy.HostKeyAlgorithms
	}
	logger.Warn("SSH legacy aplicado (algoritmos antigos/inseguros)",
		"kex", cfg.KeyExchanges, "ciphers", cfg.Ciphers, "macs", cfg.MACs)
}
