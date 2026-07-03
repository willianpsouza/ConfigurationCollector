package audit

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/willianpsouza/ConfigurationCollector/internal/parse"
)

// Correlacao da malha de TRANSPORTE MPLS (deterministica).
//
// L2VC (VLL/Martini) e ponto-a-ponto: vc-id e a chave global do circuito e cada
// vc-id deve ter exatamente 2 pontas, com o "peer" de cada lado apontando para o
// lsr-id do outro. VSI (VPLS) e multiponto: cada peer deve ser reciproco.
func init() {
	FleetRegistry = append(FleetRegistry, l2vcCorrelation, vsiCorrelation)
}

var (
	reLsrID   = regexp.MustCompile(`(?m)^\s*mpls lsr-id\s+(\d+\.\d+\.\d+\.\d+)`)
	reL2VC    = regexp.MustCompile(`(?m)^\s*mpls l2vc\s+(?:ip-interface\s+)?(\d+\.\d+\.\d+\.\d+)\s+(\d+)`)
	rePwTpl   = regexp.MustCompile(`pw-template\s+(\S+)`)
	reVsiHead = regexp.MustCompile(`^\s*vsi\s+(\S+)`)
	reVsiID   = regexp.MustCompile(`^\s*vsi-id\s+(\d+)`)
	reVsiPeer = regexp.MustCompile(`^\s*peer\s+(\d+\.\d+\.\d+\.\d+)`)
	reIfaceIP = regexp.MustCompile(`(?m)^\s*ipv?6? address\s+(\d+\.\d+\.\d+\.\d+)`)
)

// addr2dev mapeia TODOS os enderecos IPv4 de um device (loopbacks, mgmt, lsr-id,
// enderecos de interface) para o nome do device. Um device tem varios IPs — ex.
// ITAQUA-CORE01 responde por 10.99.99.100 (LoopBack1000) E 10.99.99.200
// (LoopBack100); PWs podem apontar para qualquer um deles.
func buildAddr2Dev(devs []*parse.Device) map[string]string {
	m := map[string]string{}
	for _, d := range devs {
		if d.IP != "" {
			m[d.IP] = d.Asset
		}
		for _, mm := range reLsrID.FindAllStringSubmatch(d.Config, -1) {
			m[mm[1]] = d.Asset
		}
		for _, mm := range reIfaceIP.FindAllStringSubmatch(d.Config, -1) {
			// nao sobrescreve um mapeamento ja existente por mgmt/lsr-id
			if _, ok := m[mm[1]]; !ok {
				m[mm[1]] = d.Asset
			}
		}
	}
	return m
}

// Mesh descreve a membership da malha MPLS enxergada pelos configs coletados.
type Mesh struct {
	Collected []string            // lsr-id/IP dos devices coletados
	Peers     map[string][]string // peer-addr -> devices que o referenciam
	Missing   []string            // peers referenciados mas NAO coletados
}

// MeshSummary enumera todos os lsr-ids referenciados como peer (l2vc/vsi) no
// parque e identifica quais nao foram coletados (membros da malha faltando).
func MeshSummary(devs []*parse.Device) Mesh {
	addr2dev := buildAddr2Dev(devs)
	var collectedList []string
	for _, d := range devs {
		if m := reLsrID.FindStringSubmatch(d.Config); m != nil {
			collectedList = append(collectedList, m[1])
		}
	}
	collected := func(a string) bool { return addr2dev[a] != "" }

	peers := map[string]map[string]bool{}
	addPeer := func(addr, dev string) {
		if peers[addr] == nil {
			peers[addr] = map[string]bool{}
		}
		peers[addr][dev] = true
	}
	for _, d := range devs {
		for _, iface := range d.Interfaces {
			if m := reL2VC.FindStringSubmatch(joinLines(iface.Lines)); m != nil {
				addPeer(m[1], short(d.Asset))
			}
		}
		for _, v := range parseVSIs(d) {
			for _, p := range v.peers {
				addPeer(p, short(d.Asset))
			}
		}
	}

	mesh := Mesh{Collected: uniqStrings(collectedList), Peers: map[string][]string{}}
	for addr, devset := range peers {
		devlist := make([]string, 0, len(devset))
		for dv := range devset {
			devlist = append(devlist, dv)
		}
		sort.Strings(devlist)
		mesh.Peers[addr] = devlist
		if !collected(addr) {
			mesh.Missing = append(mesh.Missing, addr)
		}
	}
	sort.Strings(mesh.Missing)
	return mesh
}

type l2vcEnd struct {
	device, ip, iface string
	peer, vcid, mtu   string
	pwTpl, lsrid      string
}

// l2vcCorrelation cruza os pseudowires L2VC do parque por vc-id.
func l2vcCorrelation(devs []*parse.Device) []Finding {
	// addr2dev resolve qualquer IP (loopback/mgmt/interface) -> device dono.
	addr2dev := buildAddr2Dev(devs)

	byVC := map[string][]l2vcEnd{}
	for _, d := range devs {
		lsr := ""
		if m := reLsrID.FindStringSubmatch(d.Config); m != nil {
			lsr = m[1]
		}
		for _, iface := range d.Interfaces {
			body := joinLines(iface.Lines)
			m := reL2VC.FindStringSubmatch(body)
			if m == nil {
				continue
			}
			e := l2vcEnd{
				device: d.Asset, ip: d.IP, iface: iface.Name,
				peer: m[1], vcid: m[2], lsrid: lsr,
			}
			if mm := reMTU.FindStringSubmatch(body); mm != nil {
				e.mtu = mm[1]
			}
			if pt := rePwTpl.FindStringSubmatch(body); pt != nil {
				e.pwTpl = pt[1]
			}
			byVC[e.vcid] = append(byVC[e.vcid], e)
		}
	}

	var out []Finding
	vcids := sortedKeys(byVC)
	for _, vc := range vcids {
		eps := byVC[vc]
		switch {
		case len(eps) == 1:
			e := eps[0]
			if owner := addr2dev[e.peer]; owner == "" {
				// Par aponta para device fora do escopo coletado — informativo.
				out = append(out, Finding{
					Asset: e.device, IP: e.ip, Rule: "l2vc-far-end-not-collected", Severity: Low,
					Object: fmt.Sprintf("L2VC vc-id %s @ %s", vc, e.iface),
					Detail: fmt.Sprintf("ponta B (peer=%s) fora do escopo coletado — coletar para correlacionar", e.peer),
				})
			} else {
				// Par existe entre os coletados mas nao tem o mesmo vc-id: dangling real.
				out = append(out, Finding{
					Asset: e.device, IP: e.ip, Rule: "l2vc-single-end", Severity: Med,
					Object: fmt.Sprintf("L2VC vc-id %s @ %s", vc, e.iface),
					Detail: fmt.Sprintf("ponta B (peer=%s = %s) foi coletada mas NAO tem este vc-id — circuito incompleto", e.peer, short(owner)),
					Suggestion: "conferir o pseudowire na ponta B (vc-id ausente ou divergente)",
				})
			}
		case len(eps) == 2:
			out = append(out, l2vcPairFindings(vc, eps[0], eps[1], addr2dev)...)
		default:
			out = append(out, Finding{
				Rule: "l2vc-unexpected-multipoint", Severity: Med,
				Object: fmt.Sprintf("L2VC vc-id %s", vc),
				Detail: fmt.Sprintf("vc-id em %d pontas (VLL e ponto-a-ponto): %s", len(eps), l2vcList(eps)),
				Suggestion: "vc-id reutilizado indevidamente ou deveria ser VSI/VPLS",
			})
		}
	}
	return out
}

func l2vcPairFindings(vc string, a, b l2vcEnd, addr2dev map[string]string) []Finding {
	var out []Finding
	label := fmt.Sprintf("L2VC vc-id %s [A=%s/%s B=%s/%s]", vc, short(a.device), a.iface, short(b.device), b.iface)

	// O peer de cada lado deve RESOLVER (por qualquer IP/loopback) para o device
	// da ponta oposta. Ex.: .12->.200 e valido pois .200 e loopback do .100.
	out = append(out, peerResolveFinding(vc, label, "A", a, b, addr2dev)...)
	out = append(out, peerResolveFinding(vc, label, "B", b, a, addr2dev)...)
	if a.mtu != b.mtu && (a.mtu != "" || b.mtu != "") {
		out = append(out, Finding{
			Rule: "l2vc-mtu-mismatch", Severity: High, Object: label,
			Detail: fmt.Sprintf("MTU divergente entre pontas: A=%q B=%q", a.mtu, b.mtu),
			Suggestion: "igualar MTU nas duas pontas do pseudowire",
		})
	}
	if a.pwTpl != b.pwTpl && (a.pwTpl != "" || b.pwTpl != "") {
		out = append(out, Finding{
			Rule: "l2vc-pwtemplate-mismatch", Severity: Med, Object: label,
			Detail: fmt.Sprintf("pw-template divergente: A=%q B=%q", a.pwTpl, b.pwTpl),
		})
	}
	return out
}

// peerResolveFinding checa se o peer de "self" resolve para o device de "other".
func peerResolveFinding(vc, label, side string, self, other l2vcEnd, addr2dev map[string]string) []Finding {
	owner := addr2dev[self.peer]
	if owner == "" {
		return []Finding{{
			Rule: "l2vc-peer-unresolved", Severity: Med, Object: label,
			Detail: fmt.Sprintf("ponta %s aponta peer %s que NAO resolve para device coletado (morto/desconhecido)", side, self.peer),
			Suggestion: "verificar se o peer esta correto/vivo",
		}}
	}
	if owner != other.device {
		return []Finding{{
			Rule: "l2vc-peer-mismatch", Severity: High, Object: label,
			Detail: fmt.Sprintf("ponta %s aponta peer %s (=%s), mas a ponta oposta e %s — cross-wire ou vc-id reusado",
				side, self.peer, short(owner), short(other.device)),
			Suggestion: "corrigir o peer do pseudowire para a ponta oposta correta",
		}}
	}
	return nil
}

type vsiInst struct {
	device, ip, name, vsiid string
	peers                   []string
}

// vsiCorrelation cruza instancias VSI (VPLS) por vsi-id e checa reciprocidade
// dos peers.
func vsiCorrelation(devs []*parse.Device) []Finding {
	byID := map[string][]vsiInst{}
	for _, d := range devs {
		for _, v := range parseVSIs(d) {
			if v.vsiid == "" {
				continue
			}
			byID[v.vsiid] = append(byID[v.vsiid], v)
		}
	}

	var out []Finding
	for _, id := range sortedKeysVSI(byID) {
		insts := byID[id]
		// mapa lsr-id/ip -> instancia (para checar reciprocidade)
		lsrOf := map[string]vsiInst{}
		for _, in := range insts {
			for _, d := range devs {
				if d.Asset == in.device {
					if m := reLsrID.FindStringSubmatch(d.Config); m != nil {
						lsrOf[m[1]] = in
					}
				}
			}
		}
		for _, in := range insts {
			myLSR := ""
			for lsr, x := range lsrOf {
				if x.device == in.device {
					myLSR = lsr
				}
			}
			for _, p := range in.peers {
				other, ok := lsrOf[p]
				if !ok {
					out = append(out, Finding{
						Asset: in.device, IP: in.ip, Rule: "vsi-peer-uncollected", Severity: Low,
						Object: fmt.Sprintf("VSI %s (id %s)", in.name, id),
						Detail: fmt.Sprintf("peer %s nao esta entre os devices coletados", p),
					})
					continue
				}
				if myLSR != "" && !contains(other.peers, myLSR) {
					out = append(out, Finding{
						Asset: in.device, IP: in.ip, Rule: "vsi-peer-not-reciprocal", Severity: Med,
						Object: fmt.Sprintf("VSI %s (id %s)", in.name, id),
						Detail: fmt.Sprintf("aponta peer %s (%s) mas o outro lado nao aponta de volta (%s)",
							p, short(other.device), myLSR),
						Suggestion: "adicionar o peer reciproco para fechar a malha VSI",
					})
				}
			}
		}
	}
	return out
}

// parseVSIs extrai blocos "vsi NAME ... vsi-id N ... peer X" da config.
func parseVSIs(d *parse.Device) []vsiInst {
	var out []vsiInst
	var cur *vsiInst
	flush := func() {
		if cur != nil {
			out = append(out, *cur)
			cur = nil
		}
	}
	for _, raw := range strings.Split(d.Config, "\n") {
		line := strings.TrimRight(raw, " ")
		if m := reVsiHead.FindStringSubmatch(line); m != nil && !strings.Contains(line, "vsi-id") {
			flush()
			cur = &vsiInst{device: d.Asset, ip: d.IP, name: m[1]}
			continue
		}
		if cur == nil {
			continue
		}
		if strings.TrimSpace(line) == "#" {
			flush()
			continue
		}
		if m := reVsiID.FindStringSubmatch(line); m != nil {
			cur.vsiid = m[1]
		}
		if m := reVsiPeer.FindStringSubmatch(line); m != nil {
			cur.peers = append(cur.peers, m[1])
		}
	}
	flush()
	return out
}

func l2vcList(eps []l2vcEnd) string {
	parts := make([]string, len(eps))
	for i, e := range eps {
		parts[i] = short(e.device) + "/" + e.iface
	}
	return strings.Join(parts, ", ")
}

func sortedKeys(m map[string][]l2vcEnd) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func sortedKeysVSI(m map[string][]vsiInst) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
