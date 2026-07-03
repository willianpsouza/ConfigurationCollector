// Package transport implementa os meios de conexao (SSH e Telnet) usados para
// coletar a configuracao de um equipamento, dado um vendor.Driver.
package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/willianpsouza/ConfigurationCollector/internal/vendor"
)

// ConfigResult e o resultado de aplicar comandos de configuracao num device.
type ConfigResult struct {
	Transcript string   // saida completa da sessao
	Errors     []string // linhas de erro detectadas na saida
}

// ConfigRunner aplica uma sequencia de comandos de configuracao (write) num
// device. Implementado por SSH e Telnet.
type ConfigRunner interface {
	RunConfig(ctx context.Context, s Session, cmds []string, save bool, logger *slog.Logger) (ConfigResult, error)
}

// reCfgError casa marcadores de erro tipicos de CLI (Huawei/Cisco). Para "Error:"
// exige que venha seguido de TEXTO ("Error: invalid...") e nao de um numero, para
// nao casar contadores de estatistica como "Total Error: 0" / "Input Error: 0" do
// 'display interface/eth-trunk'.
var reCfgError = regexp.MustCompile(`(?i)error:\s*[a-z]|unrecognized command|wrong parameter|incomplete command|ambiguous command|% invalid|% unrecognized|too many parameters|permission denied|command not found`)

// reConfirm casa prompts de confirmacao interativa ([Y/N], "Are you sure",
// "Continue?") que alguns comandos de config emitem no meio (ex.: transceiver
// non-certified-alarm disable). O runner responde "y" automaticamente.
var reConfirm = regexp.MustCompile(`(?i)\[y/n\]|\[yes/no\]|are you sure|continue\s*\?`)

// awaitsConfirm informa se a cauda da saida esta pedindo confirmacao Y/N.
func awaitsConfirm(out string) bool {
	const tail = 200
	if len(out) > tail {
		out = out[len(out)-tail:]
	}
	return reConfirm.MatchString(out)
}

// scanErrors extrai as linhas da saida que indicam erro.
func scanErrors(transcript string) []string {
	var errs []string
	for _, ln := range strings.Split(transcript, "\n") {
		l := strings.TrimSpace(ln)
		if l != "" && reCfgError.MatchString(l) {
			errs = append(errs, l)
		}
	}
	return errs
}

// Session sao os dados de conexao de um alvo ja resolvido.
type Session struct {
	Vendor   string
	Name     string
	Address  string
	Port     int
	Username string
	Password string
	Timeout  time.Duration
}

// Addr devolve "host:porta".
func (s Session) Addr() string { return fmt.Sprintf("%s:%d", s.Address, s.Port) }

// Transport coleta a saida bruta de um equipamento usando o driver do vendor.
type Transport interface {
	// Collect conecta, executa os comandos do driver e devolve a saida
	// concatenada. Deve respeitar o cancelamento do context.
	Collect(ctx context.Context, s Session, d vendor.Driver, logger *slog.Logger) (string, error)
}

const (
	readChunk    = 4096
	readDeadline = 500 * time.Millisecond
	pollInterval = 100 * time.Millisecond
)

// header escreve o cabecalho padrao de uma coleta no buffer.
func header(buf *bytes.Buffer, s Session, protocol string, now time.Time) {
	fmt.Fprintf(buf, "### ASSET=%s IP=%s VENDOR=%s PROTOCOL=%s TIME=%s ###\n\n",
		s.Name, s.Address, s.Vendor, protocol, now.Format(time.RFC3339))
}

// cmdBanner escreve o separador de um comando.
func cmdBanner(buf *bytes.Buffer, cmd string) {
	fmt.Fprintf(buf, "\n\n==== CMD: %s ====\n", cmd)
}

// deadliner e qualquer conexao que suporte SetReadDeadline (net.Conn e afins).
type deadliner interface {
	SetReadDeadline(time.Time) error
}

// readUntilPrompt le de reader ate encontrar um dos prompts ou estourar o
// timeout. Usa SetReadDeadline se disponivel para nao bloquear indefinidamente.
// Retorna o que conseguiu ler mesmo em caso de timeout/erro.
func readUntilPrompt(ctx context.Context, reader io.Reader, timeout time.Duration, prompts []string) (string, error) {
	var buf bytes.Buffer
	deadline := time.Now().Add(timeout)
	chunk := make([]byte, readChunk)

	for {
		select {
		case <-ctx.Done():
			return buf.String(), ctx.Err()
		default:
		}
		if time.Now().After(deadline) {
			return buf.String(), fmt.Errorf("timeout aguardando prompt")
		}

		if d, ok := reader.(deadliner); ok {
			_ = d.SetReadDeadline(time.Now().Add(readDeadline))
		}

		n, err := reader.Read(chunk)
		if n > 0 {
			buf.Write(chunk[:n])
			if containsAny(buf.Bytes(), prompts) {
				return buf.String(), nil
			}
		}
		if err != nil {
			if err == io.EOF {
				return buf.String(), nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return buf.String(), err
		}
		time.Sleep(pollInterval)
	}
}

func containsAny(haystack []byte, needles []string) bool {
	for _, n := range needles {
		if n != "" && bytes.Contains(haystack, []byte(n)) {
			return true
		}
	}
	return false
}
