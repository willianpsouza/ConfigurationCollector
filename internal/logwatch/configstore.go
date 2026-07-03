package logwatch

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// IfaceInfo e a info util de uma interface extraida do config coletado.
type IfaceInfo struct {
	Desc string
	IP   string // A.B.C.D/prefix
	VLAN string // id dot1q / numero do Vlanif / port default / trunk
}

// Empty diz se nao ha nada util.
func (i IfaceInfo) Empty() bool { return i.Desc == "" && i.IP == "" && i.VLAN == "" }

// ConfigStore indexa as configuracoes coletadas (coletas/<data>/<sysname>__<addr>__...txt)
// para enriquecer os alertas com a descricao da interface. Mantem, por endereco,
// o arquivo mais recente (mtime).
type ConfigStore struct {
	dir string

	mu     sync.RWMutex
	byAddr map[string]map[string]IfaceInfo // addr -> iface -> info
}

// NewConfigStore cria o store apontando para o diretorio de coletas (vazio =
// enriquecimento desabilitado).
func NewConfigStore(dir string) *ConfigStore {
	return &ConfigStore{dir: dir, byAddr: map[string]map[string]IfaceInfo{}}
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

	built := make(map[string]map[string]IfaceInfo, len(newest))
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

// Info devolve a info util da interface no device (addr). Zero-value se nao achar.
func (s *ConfigStore) Info(addr, iface string) IfaceInfo {
	if addr == "" || iface == "" {
		return IfaceInfo{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	ifaces := s.byAddr[addr]
	if ifaces == nil {
		return IfaceInfo{}
	}
	if info, ok := ifaces[iface]; ok {
		return info
	}
	// fallback: casa pelo "tail" numerico (0/0/100) se for unico.
	tail := ifaceTail(iface)
	if tail == "" {
		return IfaceInfo{}
	}
	var hit IfaceInfo
	n := 0
	for name, info := range ifaces {
		if ifaceTail(name) == tail {
			hit = info
			n++
		}
	}
	if n == 1 {
		return hit
	}
	return IfaceInfo{}
}

var reIfaceTail = regexp.MustCompile(`\d+(?:/\d+)+(?:\.\d+)?$`)

func ifaceTail(name string) string { return reIfaceTail.FindString(name) }

var (
	reVlanifNum = regexp.MustCompile(`^Vlanif(\d+)`)
	reIPAddr    = regexp.MustCompile(`ip address (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)`)
	reDot1q     = regexp.MustCompile(`(?:vlan-type dot1q|dot1q termination vid|port default vlan) (\d+)`)
	reAllowVlan = regexp.MustCompile(`port trunk allow-pass vlan (.+)`)
)

// parseInterfaces extrai interface -> {desc, ip, vlan} do config.
func parseInterfaces(path string) map[string]IfaceInfo {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	out := map[string]IfaceInfo{}
	var cur string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		trim := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "interface "):
			cur = strings.TrimSpace(strings.TrimPrefix(line, "interface "))
			info := out[cur]
			if m := reVlanifNum.FindStringSubmatch(cur); m != nil {
				info.VLAN = m[1] // Vlanif274 -> VLAN 274
			}
			out[cur] = info
		case cur == "":
			// fora de bloco de interface
		case strings.HasPrefix(trim, "description "):
			info := out[cur]
			info.Desc = strings.TrimSpace(strings.TrimPrefix(trim, "description "))
			out[cur] = info
		case strings.HasPrefix(trim, "ip address "):
			if m := reIPAddr.FindStringSubmatch(trim); m != nil {
				info := out[cur]
				if info.IP == "" { // primeiro = principal
					info.IP = m[1] + "/" + maskToPrefix(m[2])
				}
				out[cur] = info
			}
		case strings.Contains(trim, "dot1q") || strings.HasPrefix(trim, "port default vlan"):
			if m := reDot1q.FindStringSubmatch(trim); m != nil {
				info := out[cur]
				if info.VLAN == "" {
					info.VLAN = m[1]
				}
				out[cur] = info
			}
		case strings.HasPrefix(trim, "port trunk allow-pass vlan"):
			if m := reAllowVlan.FindStringSubmatch(trim); m != nil {
				info := out[cur]
				if info.VLAN == "" {
					info.VLAN = "trunk " + strings.TrimSpace(m[1])
				}
				out[cur] = info
			}
		case line != "" && !strings.HasPrefix(line, " "):
			cur = "" // saiu do bloco
		}
	}
	return out
}

// maskToPrefix converte 255.255.255.252 -> "30".
func maskToPrefix(mask string) string {
	p := strings.Split(mask, ".")
	if len(p) != 4 {
		return mask
	}
	var b [4]byte
	for i, s := range p {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 || n > 255 {
			return mask
		}
		b[i] = byte(n)
	}
	ones, bits := net.IPv4Mask(b[0], b[1], b[2], b[3]).Size()
	if bits == 0 {
		return mask // mascara nao-contigua
	}
	return strconv.Itoa(ones)
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
