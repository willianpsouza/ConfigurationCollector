package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/willianpsouza/ConfigurationCollector/internal/vendor"
	"github.com/ziutek/telnet"
)

// Telnet implementa Transport sobre github.com/ziutek/telnet. Sempre opera em
// modo shell (Telnet nao tem "exec"); o Mode do driver e ignorado.
type Telnet struct{}

// NewTelnet cria o transporte Telnet.
func NewTelnet() *Telnet { return &Telnet{} }

// Collect conecta via Telnet, faz login e executa os comandos do driver.
func (t *Telnet) Collect(ctx context.Context, s Session, d vendor.Driver, logger *slog.Logger) (string, error) {
	logger.Info("conectando via telnet", "address", s.Addr())

	conn, err := telnet.DialTimeout("tcp", s.Addr(), s.Timeout)
	if err != nil {
		return "", fmt.Errorf("dial telnet: %w", err)
	}
	defer conn.Close()

	var out bytes.Buffer
	header(&out, s, "telnet", time.Now())

	// Login: usuario e senha.
	if err := waitForCI(conn, s.Timeout, "sername:", "ogin:"); err != nil {
		return out.String(), fmt.Errorf("timeout aguardando login prompt: %w", err)
	}
	if _, err := conn.Write([]byte(s.Username + "\n")); err != nil {
		return out.String(), fmt.Errorf("enviando username: %w", err)
	}
	if err := waitForCI(conn, s.Timeout, "assword:"); err != nil {
		return out.String(), fmt.Errorf("timeout aguardando password prompt: %w", err)
	}
	if _, err := conn.Write([]byte(s.Password + "\n")); err != nil {
		return out.String(), fmt.Errorf("enviando password: %w", err)
	}

	const idle = 2500 * time.Millisecond

	// Aguarda estabilizar o prompt inicial (best-effort).
	_, _ = readTelnetRobust(ctx, conn, 8*time.Second, idle)

	// Setup (desabilitar paginacao etc.).
	for _, cmd := range d.Setup() {
		if _, err := conn.Write([]byte(cmd + "\n")); err != nil {
			return out.String(), fmt.Errorf("enviando setup %q: %w", cmd, err)
		}
		_, _ = readTelnetRobust(ctx, conn, s.Timeout, idle)
	}

	for _, cmd := range d.Commands() {
		select {
		case <-ctx.Done():
			return out.String(), ctx.Err()
		default:
		}
		cmdBanner(&out, cmd)
		if _, err := conn.Write([]byte(cmd + "\n")); err != nil {
			logger.Warn("erro enviando comando", "cmd", cmd, "error", err)
			continue
		}
		got, err := readTelnetRobust(ctx, conn, s.Timeout, idle)
		out.WriteString(got)
		if err != nil {
			logger.Warn("erro lendo output do comando", "cmd", cmd, "error", err)
		}
	}

	if exit := d.Exit(); exit != "" {
		_, _ = conn.Write([]byte(exit + "\n"))
		time.Sleep(300 * time.Millisecond)
	}
	return out.String(), nil
}

// RunConfig aplica comandos de configuracao via Telnet (login + shell).
func (t *Telnet) RunConfig(ctx context.Context, s Session, cmds []string, save bool, logger *slog.Logger) (ConfigResult, error) {
	logger.Info("apply telnet", "address", s.Addr(), "cmds", len(cmds), "save", save)

	conn, err := telnet.DialTimeout("tcp", s.Addr(), s.Timeout)
	if err != nil {
		return ConfigResult{}, fmt.Errorf("dial telnet: %w", err)
	}
	defer conn.Close()

	if err := waitForCI(conn, s.Timeout, "sername:", "ogin:"); err != nil {
		return ConfigResult{}, fmt.Errorf("timeout login prompt: %w", err)
	}
	if _, err := conn.Write([]byte(s.Username + "\n")); err != nil {
		return ConfigResult{}, err
	}
	if err := waitForCI(conn, s.Timeout, "assword:"); err != nil {
		return ConfigResult{}, fmt.Errorf("timeout password prompt: %w", err)
	}
	if _, err := conn.Write([]byte(s.Password + "\n")); err != nil {
		return ConfigResult{}, err
	}

	const idle = 2000 * time.Millisecond
	var tr bytes.Buffer
	_, _ = readTelnetRobust(ctx, conn, 8*time.Second, idle)
	_, _ = conn.Write([]byte("screen-length 0 temporary\n"))
	_, _ = readTelnetRobust(ctx, conn, s.Timeout, idle)

	for _, cmd := range cmds {
		if _, err := conn.Write([]byte(cmd + "\n")); err != nil {
			return ConfigResult{Transcript: tr.String()}, fmt.Errorf("write %q: %w", cmd, err)
		}
		out, _ := readTelnetRobust(ctx, conn, s.Timeout, idle)
		tr.WriteString(out)
		// Responde automaticamente prompts [Y/N] emitidos pelo comando.
		for i := 0; i < 3 && awaitsConfirm(out); i++ {
			_, _ = conn.Write([]byte("y\n"))
			out, _ = readTelnetRobust(ctx, conn, s.Timeout, idle)
			tr.WriteString(out)
		}
	}

	if save {
		// Assume-se que o chamador ja retornou a user-view (return). Persiste.
		_, _ = conn.Write([]byte("save\n"))
		out, _ := readTelnetRobust(ctx, conn, s.Timeout, idle)
		tr.WriteString(out)
		if strings.Contains(strings.ToUpper(out), "Y/N") || strings.Contains(strings.ToLower(out), "are you sure") {
			_, _ = conn.Write([]byte("y\n"))
			out2, _ := readTelnetRobust(ctx, conn, s.Timeout, idle)
			tr.WriteString(out2)
		}
	}

	res := ConfigResult{Transcript: tr.String()}
	res.Errors = scanErrors(res.Transcript)
	return res, nil
}

// readTelnetRobust le a saida de um comando com a mesma robustez do caminho SSH:
// trata paginacao ("---- More ----" -> espaco), detecta prompt ancorado no fim
// e usa idle (silencio) como fim de saida. Telnet honra SetReadDeadline, entao
// nao precisa de goroutine.
func readTelnetRobust(ctx context.Context, conn *telnet.Conn, total, idleTimeout time.Duration) (string, error) {
	var buf bytes.Buffer
	deadline := time.Now().Add(total)
	lastData := time.Now()
	chunk := make([]byte, readChunk)

	for {
		select {
		case <-ctx.Done():
			return buf.String(), ctx.Err()
		default:
		}
		if time.Now().After(deadline) {
			if buf.Len() > 0 {
				return buf.String(), nil
			}
			return buf.String(), fmt.Errorf("timeout total sem resposta")
		}

		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, err := conn.Read(chunk)
		if n > 0 {
			buf.Write(chunk[:n])
			lastData = time.Now()
			if moreRe.Match(buf.Bytes()) {
				_, _ = conn.Write([]byte(" "))
				b := moreRe.ReplaceAll(buf.Bytes(), nil)
				buf.Reset()
				buf.Write(b)
				continue
			}
			if endsWithPrompt(buf.Bytes()) {
				return buf.String(), nil
			}
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if buf.Len() > 0 && time.Since(lastData) > idleTimeout {
					return buf.String(), nil // idle: fim da saida
				}
				continue
			}
			if err == io.EOF {
				return buf.String(), nil
			}
			return buf.String(), err
		}
	}
}

// waitForCI le do conn ate encontrar (case-insensitive) um dos padroes ou
// estourar o timeout.
func waitForCI(conn *telnet.Conn, timeout time.Duration, patterns ...string) error {
	deadline := time.Now().Add(timeout)
	var buf bytes.Buffer
	chunk := make([]byte, readChunk)

	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout aguardando padrao")
		}
		_ = conn.SetReadDeadline(time.Now().Add(readDeadline))
		n, err := conn.Read(chunk)
		if n > 0 {
			buf.Write(chunk[:n])
			low := strings.ToLower(buf.String())
			for _, p := range patterns {
				if strings.Contains(low, strings.ToLower(p)) {
					return nil
				}
			}
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		time.Sleep(pollInterval)
	}
}
