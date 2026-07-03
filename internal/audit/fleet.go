package audit

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/willianpsouza/ConfigurationCollector/internal/parse"
)

// FleetRule inspeciona TODOS os devices juntos (correlacao cross-device).
type FleetRule func(devs []*parse.Device) []Finding

// FleetRegistry sao as regras de correlacao ativas.
var FleetRegistry = []FleetRule{
	vlanCircuitCorrelation,
}

// RunFleet roda as regras de correlacao sobre o parque inteiro.
func RunFleet(devs []*parse.Device) []Finding {
	var out []Finding
	for _, r := range FleetRegistry {
		out = append(out, r(devs)...)
	}
	sort.SliceStable(out, func(i, j int) bool { return sevRank(out[i].Severity) < sevRank(out[j].Severity) })
	return out
}

// endpoint e uma ponta de circuito (subinterface dot1q) num device.
type endpoint struct {
	device  string
	ip      string
	iface   string
	desc    string
	hasCAR  bool
	hasStat bool
	mtu     string
	client  bool // heuristica: ponta de cliente/carrier/IX (far-end externo)
}

var (
	reVID = regexp.MustCompile(`(?m)^\s*(?:dot1q termination vid|vlan-type dot1q|dot1q vid|encapsulation dot1q|pe-vid)\s+(\d+)`)
	reMTU = regexp.MustCompile(`(?m)^\s*mtu (\d+)`)
	reVSI = regexp.MustCompile(`(?m)^\s*(vsi |bridge-domain|l2 binding vsi)`)
)

// vlanCircuitCorrelation correlaciona subinterfaces dot1q por VID no parque.
// Como VLANs nao se repetem (modelo ponta-A/ponta-B), cada VID deveria ter 2
// pontas internas simetricas; assimetria, multiponto inesperado e (informativo)
// pontas orfas viram achados.
func vlanCircuitCorrelation(devs []*parse.Device) []Finding {
	byVID := map[int][]endpoint{}

	for _, d := range devs {
		for _, iface := range d.Interfaces {
			if !iface.IsSubinterface() {
				continue
			}
			body := iface.Name + "\n" + joinLines(iface.Lines)
			m := reVID.FindStringSubmatch(body)
			if m == nil {
				continue
			}
			vid := atoi(m[1])
			if vid == 0 {
				continue
			}
			mtu := ""
			if mm := reMTU.FindStringSubmatch(body); mm != nil {
				mtu = mm[1]
			}
			byVID[vid] = append(byVID[vid], endpoint{
				device:  d.Asset,
				ip:      d.IP,
				iface:   iface.Name,
				desc:    iface.Description,
				hasCAR:  reBandwidth.MatchString(body),
				hasStat: reStats.MatchString(body),
				mtu:     mtu,
				client:  !reBackbone.MatchString(body),
			})
		}
	}

	var out []Finding
	vids := make([]int, 0, len(byVID))
	for v := range byVID {
		vids = append(vids, v)
	}
	sort.Ints(vids)

	for _, vid := range vids {
		eps := byVID[vid]
		switch {
		case len(eps) == 2:
			out = append(out, symmetryFindings(vid, eps[0], eps[1])...)
		case len(eps) >= 3:
			// multiponto: so esperado com VSI em alguma ponta
			hasVSI := false
			for _, d := range devs {
				if reVSI.MatchString(d.Config) && epsHasDevice(eps, d.Asset) {
					hasVSI = true
					break
				}
			}
			if !hasVSI {
				out = append(out, Finding{
					Rule: "vlan-unexpected-multipoint", Severity: Med,
					Object: fmt.Sprintf("VLAN %d", vid),
					Detail: fmt.Sprintf("VID em %d pontas sem VSI (esperado ponta-A/ponta-B): %s", len(eps), epsList(eps)),
					Suggestion: "confirmar se e VSI/VPLS multiponto legitimo ou reuso indevido de VLAN",
				})
			}
		case len(eps) == 1 && !eps[0].client:
			// orfao interno (nao-cliente): provavel ponta B faltando
			out = append(out, Finding{
				Asset: eps[0].device, IP: eps[0].ip,
				Rule: "vlan-single-end", Severity: Low,
				Object: fmt.Sprintf("VLAN %d @ %s", vid, eps[0].iface),
				Detail: fmt.Sprintf("circuito interno com apenas 1 ponta coletada (%s) — ponta B ausente ou nao coletada", eps[0].desc),
			})
		}
	}
	return out
}

// symmetryFindings compara as duas pontas de um circuito.
func symmetryFindings(vid int, a, b endpoint) []Finding {
	var out []Finding
	label := fmt.Sprintf("VLAN %d [A=%s/%s B=%s/%s]", vid, short(a.device), a.iface, short(b.device), b.iface)

	if a.hasStat != b.hasStat {
		out = append(out, Finding{
			Rule: "circuit-asymmetric-stats", Severity: Med, Object: label,
			Detail: fmt.Sprintf("estatistica assimetrica: A=%v B=%v (uma ponta cega)", a.hasStat, b.hasStat),
			Suggestion: "habilitar statistic/netstream na ponta sem estatistica",
		})
	}
	if a.hasCAR != b.hasCAR {
		out = append(out, Finding{
			Rule: "circuit-asymmetric-bandwidth", Severity: Med, Object: label,
			Detail: fmt.Sprintf("controle de banda assimetrico: A=%v B=%v", a.hasCAR, b.hasCAR),
			Suggestion: "alinhar traffic-policy/CAR nas duas pontas",
		})
	}
	if a.mtu != b.mtu && (a.mtu != "" || b.mtu != "") {
		out = append(out, Finding{
			Rule: "circuit-mtu-mismatch", Severity: High, Object: label,
			Detail: fmt.Sprintf("MTU divergente entre pontas: A=%q B=%q", a.mtu, b.mtu),
			Suggestion: "igualar MTU nas duas pontas (risco de black-hole/fragmentacao)",
		})
	}
	return out
}

func epsHasDevice(eps []endpoint, dev string) bool {
	for _, e := range eps {
		if e.device == dev {
			return true
		}
	}
	return false
}

func epsList(eps []endpoint) string {
	parts := make([]string, len(eps))
	for i, e := range eps {
		parts[i] = short(e.device) + "/" + e.iface
	}
	return strings.Join(parts, ", ")
}

// short encurta o nome do device para os rotulos.
func short(name string) string {
	if i := strings.Index(name, "-10-99-99-"); i > 0 {
		return name[:i]
	}
	return name
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
