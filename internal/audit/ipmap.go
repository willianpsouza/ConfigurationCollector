package audit

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/willianpsouza/ConfigurationCollector/internal/parse"
)

// Inventario de IP por device + deteccao de IP/rede duplicados.
//
// O user pediu: mapear o IP local de cada device ANTES de concluir correlacoes,
// para identificar classes/IPs duplicados na rede — vetores de erro que passam
// batido numa operacao com muitos ativos.
func init() {
	FleetRegistry = append(FleetRegistry, ipDuplicates, publicIPInternal)
}

// publicIPInternal sinaliza IPs fora da RFC1918 (e RFC6598/CGNAT) onde nao
// deveriam estar: loopbacks internos e interconexoes internas (mesma rede /30
// com 2+ ativos NOSSOS). Enlaces WAN/peering (so a nossa ponta na rede) sao
// esperados e ficam so no inventario (csv), sem virar achado.
func publicIPInternal(devs []*parse.Device) []Finding {
	inv := IPInventory(devs)
	var out []Finding
	byNet := map[string]map[string]bool{}
	byNetEntries := map[string][]IPEntry{}

	for _, e := range inv {
		if isPrivateIP(e.IP) {
			continue
		}
		if isLoopbackIface(e.Iface) {
			out = append(out, Finding{
				Asset: e.Device, Rule: "loopback-public-ip", Severity: High,
				Object: fmt.Sprintf("%s %s", e.Iface, e.IP),
				Detail: "loopback com IP publico (fora RFC1918) — loopbacks internos deveriam ser privados",
			})
		}
		if e.Network == "" {
			continue
		}
		if byNet[e.Network] == nil {
			byNet[e.Network] = map[string]bool{}
		}
		byNet[e.Network][e.Device] = true
		byNetEntries[e.Network] = append(byNetEntries[e.Network], e)
	}

	nets := make([]string, 0, len(byNet))
	for n := range byNet {
		nets = append(nets, n)
	}
	sort.Strings(nets)
	for _, net := range nets {
		if len(byNet[net]) >= 2 {
			out = append(out, Finding{
				Rule: "internal-link-public-ip", Severity: Med,
				Object: net,
				Detail: fmt.Sprintf("interconexao interna com IP publico (fora RFC1918) entre %d ativos: %s",
					len(byNet[net]), ipLocations(byNetEntries[net])),
				Suggestion: "usar espaco RFC1918 em enlaces internos (salvo transito/peering real)",
			})
		}
	}
	return out
}

// isPrivateIP: RFC1918 + RFC6598 (CGNAT 100.64/10) + loopback/link-local.
func isPrivateIP(ip string) bool {
	o := parseOctets(ip)
	if o == nil {
		return true // nao classificavel -> nao flaga
	}
	switch {
	case o[0] == 10:
		return true
	case o[0] == 172 && o[1] >= 16 && o[1] <= 31:
		return true
	case o[0] == 192 && o[1] == 168:
		return true
	case o[0] == 100 && o[1] >= 64 && o[1] <= 127: // RFC6598 CGNAT
		return true
	case o[0] == 127: // loopback
		return true
	case o[0] == 169 && o[1] == 254: // link-local
		return true
	}
	return false
}

func isLoopbackIface(iface string) bool {
	return strings.HasPrefix(strings.ToLower(iface), "loopback")
}

// reIPAddrMask captura "ip address <ip> <mask|prefix>" (com "sub" opcional).
var reIPAddrMask = regexp.MustCompile(`ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+|\d{1,2})(\s+sub)?`)

// IPEntry e um endereco IPv4 configurado num device.
type IPEntry struct {
	Device    string `json:"device"`
	IP        string `json:"ip"`
	Mask      string `json:"mask"`
	Iface     string `json:"iface"`
	Network   string `json:"network"`
	Secondary bool   `json:"secondary"`
}

// IPInventory extrai todos os IPv4 configurados nas interfaces do parque.
func IPInventory(devs []*parse.Device) []IPEntry {
	var out []IPEntry
	for _, d := range devs {
		for _, iface := range d.Interfaces {
			for _, ln := range iface.Lines {
				m := reIPAddrMask.FindStringSubmatch(ln)
				if m == nil {
					continue
				}
				out = append(out, IPEntry{
					Device:    d.Asset,
					IP:        m[1],
					Mask:      m[2],
					Iface:     iface.Name,
					Network:   networkOf(m[1], m[2]),
					Secondary: strings.Contains(m[3], "sub"),
				})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].IP == out[j].IP {
			return out[i].Device < out[j].Device
		}
		return ipLess(out[i].IP, out[j].IP)
	})
	return out
}

// ipDuplicates flaga o MESMO IP configurado em devices diferentes (conflito) e
// tambem o mesmo IP repetido no mesmo device.
func ipDuplicates(devs []*parse.Device) []Finding {
	inv := IPInventory(devs)
	byIP := map[string][]IPEntry{}
	for _, e := range inv {
		byIP[e.IP] = append(byIP[e.IP], e)
	}

	var out []Finding
	ips := make([]string, 0, len(byIP))
	for ip := range byIP {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool { return ipLess(ips[i], ips[j]) })

	for _, ip := range ips {
		entries := byIP[ip]
		devSet := map[string]bool{}
		for _, e := range entries {
			devSet[e.device()] = true
		}
		if len(devSet) >= 2 {
			// Portas de gerencia OOB (MEth) costumam reusar o mesmo IP em
			// segmentos isolados — provavelmente intencional, entao LOW.
			if allMgmtIface(entries) {
				out = append(out, Finding{
					Rule: "ip-duplicate-oob-mgmt", Severity: Low,
					Object: ip,
					Detail: fmt.Sprintf("mesmo IP em %d portas de gerencia OOB (MEth): %s — provavel intencional", len(devSet), ipLocations(entries)),
				})
			} else {
				out = append(out, Finding{
					Rule: "ip-duplicate-cross-device", Severity: High,
					Object: ip,
					Detail: fmt.Sprintf("MESMO IP em %d devices: %s", len(devSet), ipLocations(entries)),
					Suggestion: "conflito de IP entre ativos — corrigir (ou confirmar se e anycast/VRRP intencional)",
				})
			}
		} else if len(entries) >= 2 {
			// mesmo IP repetido no mesmo device em interfaces diferentes
			out = append(out, Finding{
				Asset: entries[0].Device, Rule: "ip-duplicate-same-device", Severity: Med,
				Object: ip,
				Detail: fmt.Sprintf("IP repetido no mesmo device: %s", ipLocations(entries)),
			})
		}
	}
	return out
}

func (e IPEntry) device() string { return e.Device }

// allMgmtIface informa se todas as entradas sao de portas de gerencia OOB.
func allMgmtIface(entries []IPEntry) bool {
	for _, e := range entries {
		l := strings.ToLower(e.Iface)
		if !strings.HasPrefix(l, "meth") && !strings.Contains(l, "management") {
			return false
		}
	}
	return true
}

func ipLocations(entries []IPEntry) string {
	parts := make([]string, len(entries))
	for i, e := range entries {
		parts[i] = short(e.Device) + "/" + e.Iface
	}
	return strings.Join(parts, ", ")
}

// networkOf calcula o endereco de rede dado ip e mascara (dotted ou prefixo).
func networkOf(ip, mask string) string {
	prefix := maskToPrefix(mask)
	if prefix < 0 {
		return ""
	}
	o := parseOctets(ip)
	if o == nil {
		return ""
	}
	bits := uint32(o[0])<<24 | uint32(o[1])<<16 | uint32(o[2])<<8 | uint32(o[3])
	var m uint32
	if prefix == 0 {
		m = 0
	} else {
		m = ^uint32(0) << (32 - prefix)
	}
	n := bits & m
	return fmt.Sprintf("%d.%d.%d.%d/%d", byte(n>>24), byte(n>>16), byte(n>>8), byte(n), prefix)
}

func maskToPrefix(mask string) int {
	if !strings.Contains(mask, ".") {
		var p int
		if _, err := fmt.Sscanf(mask, "%d", &p); err != nil || p < 0 || p > 32 {
			return -1
		}
		return p
	}
	o := parseOctets(mask)
	if o == nil {
		return -1
	}
	bits := uint32(o[0])<<24 | uint32(o[1])<<16 | uint32(o[2])<<8 | uint32(o[3])
	p := 0
	for i := 31; i >= 0; i-- {
		if bits&(1<<uint(i)) != 0 {
			p++
		} else {
			break
		}
	}
	return p
}

func parseOctets(s string) []int {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return nil
	}
	o := make([]int, 4)
	for i, p := range parts {
		v := 0
		if _, err := fmt.Sscanf(p, "%d", &v); err != nil || v < 0 || v > 255 {
			return nil
		}
		o[i] = v
	}
	return o
}

func ipLess(a, b string) bool {
	oa, ob := parseOctets(a), parseOctets(b)
	if oa == nil || ob == nil {
		return a < b
	}
	for i := 0; i < 4; i++ {
		if oa[i] != ob[i] {
			return oa[i] < ob[i]
		}
	}
	return false
}
