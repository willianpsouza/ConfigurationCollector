// Package vendor define os drivers plugaveis por fabricante de equipamento.
//
// Cada fabricante (huawei, mikrotik, cisco, ...) implementa a interface Driver,
// que descreve como coletar a configuracao: em que modo de sessao operar, quais
// comandos rodar, como desabilitar paginacao e como sair de forma limpa.
//
// Para adicionar um vendor novo basta implementar Driver e chamar Register() num
// bloco init(). Nenhum outro pacote precisa ser tocado.
package vendor

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Mode define como a sessao remota executa os comandos do driver.
type Mode int

const (
	// ModeShell abre um shell interativo (PTY) e envia os comandos em sequencia,
	// lendo ate reencontrar o prompt. Necessario para NOS que exigem terminal
	// interativo (Huawei, ZTE, Cisco IOS).
	ModeShell Mode = iota
	// ModeExec roda cada comando como um "exec" SSH separado, capturando o stdout.
	// Mais robusto para equipamentos que suportam bem execucao nao-interativa
	// (Mikrotik RouterOS via "/comando"). Nao se aplica a Telnet.
	ModeExec
)

func (m Mode) String() string {
	if m == ModeExec {
		return "exec"
	}
	return "shell"
}

// Driver descreve o comportamento de coleta de um fabricante.
type Driver interface {
	// Name retorna o identificador do vendor em minusculo (ex.: "huawei").
	Name() string
	// Mode indica se a coleta usa shell interativo ou exec por comando.
	Mode() Mode
	// Setup sao comandos executados antes da coleta em ModeShell, tipicamente
	// para desabilitar paginacao (ex.: "screen-length 0 temporary"). No ModeExec
	// e ignorado. Pode ser vazio.
	Setup() []string
	// Commands sao os comandos de coleta, na ordem de execucao.
	Commands() []string
	// Prompts sao substrings que indicam que o equipamento terminou de responder
	// e voltou ao prompt (usado em ModeShell e Telnet).
	Prompts() []string
	// Exit e o comando para encerrar a sessao de forma limpa (ex.: "quit").
	// Pode ser vazio.
	Exit() string
}

var (
	mu      sync.RWMutex
	drivers = map[string]Driver{}
)

// Register adiciona um driver ao registro. Deve ser chamado em init(). Faz panic
// em caso de nome vazio ou duplicado — erro de programacao, nao de runtime.
func Register(d Driver) {
	mu.Lock()
	defer mu.Unlock()
	name := strings.ToLower(strings.TrimSpace(d.Name()))
	if name == "" {
		panic("vendor: driver com nome vazio")
	}
	if _, dup := drivers[name]; dup {
		panic(fmt.Sprintf("vendor: driver duplicado %q", name))
	}
	drivers[name] = d
}

// Get retorna o driver do vendor informado (case-insensitive) ou erro se nao
// registrado.
func Get(name string) (Driver, error) {
	mu.RLock()
	defer mu.RUnlock()
	d, ok := drivers[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return nil, fmt.Errorf("vendor desconhecido %q (registrados: %s)", name, strings.Join(names(), ", "))
	}
	return d, nil
}

// IsRegistered informa se ha driver para o vendor.
func IsRegistered(name string) bool {
	mu.RLock()
	defer mu.RUnlock()
	_, ok := drivers[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

// Names retorna os vendors registrados em ordem alfabetica.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	return names()
}

// names assume lock ja adquirido.
func names() []string {
	out := make([]string, 0, len(drivers))
	for k := range drivers {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
