// Package audit roda checagens deterministicas sobre configuracoes ja parseadas.
//
// Regras sao codigo (nao LLM): resultado exato e reproduzivel, sem alucinacao.
// A camada de LLM (pacote llm) cuida de documentacao e divergencias difusas.
package audit

import (
	"regexp"
	"sort"

	"github.com/willianpsouza/ConfigurationCollector/internal/parse"
)

// Severity classifica um achado.
type Severity string

const (
	High Severity = "HIGH"
	Med  Severity = "MEDIUM"
	Low  Severity = "LOW"
)

// Finding e um achado da auditoria.
type Finding struct {
	Asset     string   `json:"asset"`
	IP        string   `json:"ip"`
	Rule      string   `json:"rule"`
	Severity  Severity `json:"severity"`
	Object    string   `json:"object"` // interface/objeto afetado
	Detail    string   `json:"detail"`
	Suggestion string  `json:"suggestion,omitempty"`
}

// Rule inspeciona um Device e devolve achados.
type Rule func(d *parse.Device) []Finding

// Registry sao as regras ativas.
var Registry = []Rule{
	clientInterfaceBlindness,
}

// Run roda todas as regras sobre o device.
func Run(d *parse.Device) []Finding {
	var out []Finding
	for _, r := range Registry {
		out = append(out, r(d)...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return sevRank(out[i].Severity) < sevRank(out[j].Severity)
	})
	return out
}

func sevRank(s Severity) int {
	switch s {
	case High:
		return 0
	case Med:
		return 1
	default:
		return 2
	}
}

var (
	reIPAddr    = regexp.MustCompile(`(?m)^\s*ip(v6)? address `)
	reDot1q     = regexp.MustCompile(`dot1q|qinq|\buser-vlan\b|\bpe-vid\b`)
	reBackbone  = regexp.MustCompile(`(?m)^\s*(mpls|ospf |ospfv3|isis |bgp )`)
	reBandwidth = regexp.MustCompile(`traffic-policy|qos car|car cir|qos-profile|qos queue-profile|user-queue`)
	reStats     = regexp.MustCompile(`statistic enable|statistics enable|ip netstream|ipv6 netstream`)
	reVpnBind   = regexp.MustCompile(`ip binding vpn-instance`)
)

// clientInterfaceBlindness sinaliza subinterfaces de CLIENTE que ficam "cegas":
// sem controle de banda (traffic-policy/CAR) e/ou sem estatistica de trafego
// (statistic enable / netstream). E o furo relatado nos NE40: cliente sem
// medicao de trafego e sem limitacao.
//
// Heuristica de "cliente": subinterface (tem "."), com endereco IP (ou binding
// de VPN) e encapsulamento dot1q/qinq, que NAO seja enlace de backbone
// (sem mpls/ospf/isis/bgp na stanza).
func clientInterfaceBlindness(d *parse.Device) []Finding {
	var out []Finding
	for _, iface := range d.Interfaces {
		if !iface.IsSubinterface() {
			continue
		}
		body := iface.Name + "\n" + joinLines(iface.Lines)
		hasIP := reIPAddr.MatchString(body) || reVpnBind.MatchString(body)
		hasEncap := reDot1q.MatchString(body)
		if !hasIP || !hasEncap {
			continue
		}
		if reBackbone.MatchString(body) {
			continue // enlace de infra/backbone, nao cliente
		}

		missingBand := !reBandwidth.MatchString(body)
		missingStat := !reStats.MatchString(body)
		if !missingBand && !missingStat {
			continue
		}

		obj := iface.Name
		if iface.Description != "" {
			obj += " (" + iface.Description + ")"
		}
		switch {
		case missingBand && missingStat:
			out = append(out, Finding{
				Asset: d.Asset, IP: d.IP, Rule: "client-interface-blindness", Severity: High,
				Object: obj,
				Detail: "interface de cliente sem controle de banda E sem estatistica de trafego (cego: sem limitar nem medir)",
				Suggestion: "aplicar traffic-policy/qos car inbound+outbound e habilitar 'statistic enable' (ou ip netstream)",
			})
		case missingBand:
			out = append(out, Finding{
				Asset: d.Asset, IP: d.IP, Rule: "client-interface-no-bandwidth", Severity: Med,
				Object: obj,
				Detail: "interface de cliente sem controle de banda (traffic-policy/CAR)",
				Suggestion: "aplicar traffic-policy ou qos car conforme o plano contratado",
			})
		case missingStat:
			out = append(out, Finding{
				Asset: d.Asset, IP: d.IP, Rule: "client-interface-no-stats", Severity: Med,
				Object: obj,
				Detail: "interface de cliente sem estatistica de trafego ativa (cego para trafego)",
				Suggestion: "habilitar 'statistic enable' (e/ou ip netstream inbound|outbound)",
			})
		}
	}
	return out
}

func joinLines(lines []string) string {
	s := ""
	for _, l := range lines {
		s += l + "\n"
	}
	return s
}
