package logwatch

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// ConfigStore indexa as configuracoes coletadas (coletas/<data>/<sysname>__<addr>__...txt)
// para enriquecer os alertas com a descricao da interface. Mantem, por endereco,
// o arquivo mais recente (mtime).
type ConfigStore struct {
	dir string

	mu     sync.RWMutex
	byAddr map[string]map[string]string // addr -> iface -> description
}

// NewConfigStore cria o store apontando para o diretorio de coletas (vazio =
// enriquecimento desabilitado).
func NewConfigStore(dir string) *ConfigStore {
	return &ConfigStore{dir: dir, byAddr: map[string]map[string]string{}}
}

// Enabled diz se ha diretorio configurado.
func (s *ConfigStore) Enabled() bool { return s.dir != "" }

var reAddrInName = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)

// Reload varre o diretorio e reconstroi o indice (arquivo mais novo por addr).
func (s *ConfigStore) Reload() error {
	if s.dir == "" {
		return nil
	}
	type pick struct {
		path string
		mod  int64
	}
	newest := map[string]pick{}

	err := filepath.WalkDir(s.dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".txt") {
			return nil
		}
		m := reAddrInName.FindString(filepath.Base(path))
		if m == "" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		mod := info.ModTime().UnixNano()
		if cur, ok := newest[m]; !ok || mod > cur.mod {
			newest[m] = pick{path: path, mod: mod}
		}
		return nil
	})
	if err != nil {
		return err
	}

	built := make(map[string]map[string]string, len(newest))
	for addr, p := range newest {
		if ifaces := parseInterfaces(p.path); len(ifaces) > 0 {
			built[addr] = ifaces
		}
	}

	s.mu.Lock()
	s.byAddr = built
	s.mu.Unlock()
	return nil
}

// Describe devolve a descricao da interface no device (addr). Vazio se nao achar.
func (s *ConfigStore) Describe(addr, iface string) string {
	if addr == "" || iface == "" {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	ifaces := s.byAddr[addr]
	if ifaces == nil {
		return ""
	}
	if d, ok := ifaces[iface]; ok {
		return d
	}
	// fallback: casa pelo "tail" numerico (0/0/100) se for unico.
	tail := ifaceTail(iface)
	if tail == "" {
		return ""
	}
	var hit string
	n := 0
	for name, d := range ifaces {
		if ifaceTail(name) == tail {
			hit = d
			n++
		}
	}
	if n == 1 {
		return hit
	}
	return ""
}

var reIfaceTail = regexp.MustCompile(`\d+(?:/\d+)+(?:\.\d+)?$`)

func ifaceTail(name string) string { return reIfaceTail.FindString(name) }

// parseInterfaces extrai interface -> description do config.
func parseInterfaces(path string) map[string]string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	out := map[string]string{}
	var cur string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "interface "):
			cur = strings.TrimSpace(strings.TrimPrefix(line, "interface "))
		case cur != "" && strings.HasPrefix(strings.TrimSpace(line), "description "):
			out[cur] = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "description "))
		case line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "interface "):
			cur = "" // saiu do bloco da interface
		}
	}
	return out
}

var reDevAddr = regexp.MustCompile(`(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})$`)

// DeviceAddr extrai o IP do nome de device do syslog (…-10-99-99-13 -> 10.99.99.13).
func DeviceAddr(name string) string {
	m := reDevAddr.FindStringSubmatch(name)
	if m == nil {
		return ""
	}
	return m[1] + "." + m[2] + "." + m[3] + "." + m[4]
}
