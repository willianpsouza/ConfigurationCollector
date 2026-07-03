package audit

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/willianpsouza/ConfigurationCollector/internal/parse"
)

// VLAN orfa: criada (vlan batch / vlan N) mas NAO vinculada a nenhuma porta,
// Vlanif, subinterface dot1q ou transporte (L2VC/VSI). Cruft que confunde
// operacao e inventario.
func init() {
	Registry = append(Registry, vlanOrphans)
}

var (
	reVlanBatch    = regexp.MustCompile(`(?m)^\s*vlan batch (.+)$`)
	reVlanDecl     = regexp.MustCompile(`(?m)^vlan (\d+)\s*$`)
	reVlanif       = regexp.MustCompile(`(?m)^\s*interface Vlanif(\d+)`)
	rePortDefVlan  = regexp.MustCompile(`(?m)^\s*port default vlan (\d+)`)
	rePortTrunkPv  = regexp.MustCompile(`(?m)^\s*port trunk pvid vlan (\d+)`)
	rePortAllow    = regexp.MustCompile(`(?m)^\s*port trunk allow-pass vlan (.+)$`)
	rePortHybrid   = regexp.MustCompile(`(?m)^\s*port hybrid (?:tagged|untagged) vlan (.+)$`)
	reDot1qUse     = regexp.MustCompile(`(?m)^\s*(?:vlan-type dot1q|dot1q termination vid|dot1q vid|encapsulation dot1q) (\d+)`)
	reStackVlan    = regexp.MustCompile(`(?m)^\s*(?:qinq|stacking-vlan|mux-vlan).*?(\d+)`)
)

// vlanOrphans acha VLANs criadas e nao usadas.
func vlanOrphans(d *parse.Device) []Finding {
	cfg := d.Config
	if cfg == "" {
		return nil
	}
	created := map[int]bool{}
	for _, m := range reVlanBatch.FindAllStringSubmatch(cfg, -1) {
		for _, v := range parseVlanList(m[1]) {
			created[v] = true
		}
	}
	for _, m := range reVlanDecl.FindAllStringSubmatch(cfg, -1) {
		if v, err := strconv.Atoi(m[1]); err == nil {
			created[v] = true
		}
	}
	if len(created) == 0 {
		return nil
	}

	used := map[int]bool{}
	single := []*regexp.Regexp{reVlanif, rePortDefVlan, rePortTrunkPv, reDot1qUse, reStackVlan}
	for _, re := range single {
		for _, m := range re.FindAllStringSubmatch(cfg, -1) {
			if v, err := strconv.Atoi(m[1]); err == nil {
				used[v] = true
			}
		}
	}
	lists := []*regexp.Regexp{rePortAllow, rePortHybrid}
	for _, re := range lists {
		for _, m := range re.FindAllStringSubmatch(cfg, -1) {
			for _, v := range parseVlanList(m[1]) {
				used[v] = true
			}
		}
	}

	var orphans []int
	for v := range created {
		if v == 1 {
			continue // VLAN 1 default, ignora
		}
		if !used[v] {
			orphans = append(orphans, v)
		}
	}
	if len(orphans) == 0 {
		return nil
	}
	sort.Ints(orphans)

	sev := Low
	if len(orphans) > 20 {
		sev = Med
	}
	return []Finding{{
		Asset: d.Asset, IP: d.IP, Rule: "vlan-orphan", Severity: sev,
		Object: fmt.Sprintf("%d VLANs", len(orphans)),
		Detail: fmt.Sprintf("VLANs criadas sem vinculo (porta/Vlanif/dot1q/transporte): %s", compactRanges(orphans)),
		Suggestion: "remover VLANs sem uso do 'vlan batch' (cruft de config)",
	}}
}

// parseVlanList expande "135 274 to 275 300" -> [135,274,275,300].
func parseVlanList(s string) []int {
	var out []int
	toks := strings.Fields(s)
	for i := 0; i < len(toks); i++ {
		if i+2 < len(toks) && toks[i+1] == "to" {
			a, e1 := strconv.Atoi(toks[i])
			b, e2 := strconv.Atoi(toks[i+2])
			if e1 == nil && e2 == nil {
				for v := a; v <= b && v-a < 4096; v++ {
					out = append(out, v)
				}
			}
			i += 2
			continue
		}
		if v, err := strconv.Atoi(toks[i]); err == nil {
			out = append(out, v)
		}
	}
	return out
}

// compactRanges: [274,275,276,300] -> "274-276 300".
func compactRanges(v []int) string {
	if len(v) == 0 {
		return ""
	}
	var parts []string
	start := v[0]
	prev := v[0]
	flush := func(a, b int) {
		if a == b {
			parts = append(parts, strconv.Itoa(a))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", a, b))
		}
	}
	for _, x := range v[1:] {
		if x == prev+1 {
			prev = x
			continue
		}
		flush(start, prev)
		start, prev = x, x
	}
	flush(start, prev)
	s := strings.Join(parts, " ")
	if len(s) > 300 {
		s = s[:300] + " ..."
	}
	return s
}
