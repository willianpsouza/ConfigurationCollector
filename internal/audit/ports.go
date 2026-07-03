package audit

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/willianpsouza/ConfigurationCollector/internal/parse"
)

// Higiene de portas: mapa de portas fisicas ATIVAS (nao-shut) SEM configuracao.
//
// Dor real: monitorar 2000+ portas onde muitas estao admin-up / oper-down / sem
// descricao / sem config = lixo que polui o monitoramento. Esta regra cruza o
// estado operacional (display interface description: PHY/Protocol) com a config
// (shutdown? tem config real?).
func init() {
	Registry = append(Registry, portHygiene)
}

// linha do "display interface description": <iface> <PHY> <Protocol> <desc...>
// PHY "*down" = administrativamente desligada (shutdown).
var reIfaceDescRow = regexp.MustCompile(`^(\S+)\s+(\*?down|up|down|\*down)\s+(\*?down|up|down|\*down)\s*(.*)$`)

// portas fisicas (exclui logicas: Eth-Trunk, Vlanif, Loopback, NULL, MEth...).
var rePhysPort = regexp.MustCompile(`^(?:\d+)?(?:GigabitEthernet|XGigabitEthernet|GE|XGE|Ethernet|Ten-GigabitEthernet)\d+/\d+/\d+$`)

// PortEntry e uma porta fisica com estado + veredicto de higiene.
type PortEntry struct {
	Device      string `json:"device"`
	Iface       string `json:"iface"`
	Admin       string `json:"admin"` // up|down(shut)
	Oper        string `json:"oper"`  // up|down
	HasDesc     bool   `json:"has_desc"`
	HasConfig   bool   `json:"has_config"`
	Verdict     string `json:"verdict"`
}

// PortInventory devolve todas as portas fisicas do parque com seu veredicto.
func PortInventory(devs []*parse.Device) []PortEntry {
	var out []PortEntry
	for _, d := range devs {
		out = append(out, devicePorts(d)...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Device == out[j].Device {
			return out[i].Iface < out[j].Iface
		}
		return out[i].Device < out[j].Device
	})
	return out
}

// devicePorts calcula as portas fisicas de um device.
func devicePorts(d *parse.Device) []PortEntry {
	brief := d.Commands["display interface description"]
	if brief == "" {
		return nil
	}
	cfg := map[string]parse.Interface{}
	hasSubif := map[string]bool{} // porta-pai com subinterface (servico mora na subif)
	for _, i := range d.Interfaces {
		cfg[i.Name] = i
		if dot := strings.IndexByte(i.Name, '.'); dot > 0 {
			hasSubif[i.Name[:dot]] = true
		}
	}

	var out []PortEntry
	for _, ln := range strings.Split(brief, "\n") {
		m := reIfaceDescRow.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		iface, phy, proto, desc := m[1], m[2], m[3], strings.TrimSpace(m[4])
		if !rePhysPort.MatchString(iface) {
			continue
		}

		adminDown := strings.HasPrefix(phy, "*")
		operUp := !strings.Contains(proto, "down")

		in, inCfg := cfg[iface]
		if inCfg && hasShutdown(in) {
			adminDown = true
		}
		hasDesc := desc != "" || (inCfg && in.Description != "")
		// Porta com subinterface (X.N) esta EM USO mesmo com stanza-pai vazia:
		// o servico (L2VC/QinQ/dot1q) mora na subif. Sem isso, transporte de
		// cliente vira falso-positivo "unconfigured".
		hasConfig := (inCfg && hasRealConfig(in)) || hasSubif[iface]

		e := PortEntry{
			Device: d.Asset, Iface: iface,
			Admin: boolWord(!adminDown, "up", "shut"),
			Oper:  boolWord(operUp, "up", "down"),
			HasDesc: hasDesc, HasConfig: hasConfig,
		}
		e.Verdict = verdictOf(adminDown, operUp, hasDesc, hasConfig)
		out = append(out, e)
	}
	return out
}

func verdictOf(adminDown, operUp, hasDesc, hasConfig bool) string {
	switch {
	case adminDown:
		return "shut"
	case hasConfig:
		if !hasDesc {
			return "configured-no-desc"
		}
		return "configured"
	case operUp:
		return "unconfigured-up" // ativa, passando link, sem config
	default:
		return "unconfigured-dark" // admin up, oper down, sem config = lixo
	}
}

// portHygiene emite achados para portas NAO-shut SEM configuracao.
func portHygiene(d *parse.Device) []Finding {
	var out []Finding
	for _, p := range devicePorts(d) {
		switch p.Verdict {
		case "unconfigured-dark":
			out = append(out, Finding{
				Asset: d.Asset, IP: d.IP, Rule: "port-active-unconfigured", Severity: Med,
				Object: p.Iface,
				Detail: "porta admin-up / oper-down SEM config e sem descricao — lixo de monitoramento (nao esta em shut)",
				Suggestion: "colocar em shutdown se sem uso, ou configurar+descrever",
			})
		case "unconfigured-up":
			out = append(out, Finding{
				Asset: d.Asset, IP: d.IP, Rule: "port-up-unconfigured", Severity: Low,
				Object: p.Iface,
				Detail: "porta com link UP mas sem config e sem descricao — documentar/investigar",
			})
		}
	}
	// resumo por device
	if n := countVerdict(d, "unconfigured-dark"); n > 0 {
		out = append(out, Finding{
			Asset: d.Asset, IP: d.IP, Rule: "port-hygiene-summary", Severity: Low,
			Object: fmt.Sprintf("%d portas", n),
			Detail: fmt.Sprintf("%d portas admin-up/oper-down sem config (candidatas a shutdown)", n),
		})
	}
	return out
}

func countVerdict(d *parse.Device, v string) int {
	n := 0
	for _, p := range devicePorts(d) {
		if p.Verdict == v {
			n++
		}
	}
	return n
}

var reShutdown = regexp.MustCompile(`(?m)^\s*shutdown\s*$`)

func hasShutdown(i parse.Interface) bool {
	for _, ln := range i.Lines {
		if reShutdown.MatchString(ln) {
			return true
		}
	}
	return false
}

// hasRealConfig: a stanza tem alguma config alem de description/shutdown?
func hasRealConfig(i parse.Interface) bool {
	for _, ln := range i.Lines {
		t := strings.TrimSpace(ln)
		if t == "" || t == "#" {
			continue
		}
		if strings.HasPrefix(t, "description ") || t == "shutdown" {
			continue
		}
		return true
	}
	return false
}

func boolWord(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}
