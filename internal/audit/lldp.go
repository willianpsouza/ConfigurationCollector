package audit

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/willianpsouza/ConfigurationCollector/internal/parse"
)

// LLDP flood: uma porta FISICA deveria ter ~1 vizinho LLDP direto. Muitos
// vizinhos na mesma porta indicam super-emissao (ex.: device emitindo LLDP em
// cada VLAN) ou loop L2 — causa de LLDP/4/RATEEXCESSIVE.
func init() {
	Registry = append(Registry, lldpNeighborFlood)
}

const lldpFloodThreshold = 3

var (
	reCols     = regexp.MustCompile(`\s{2,}`)
	reLldpIntf = regexp.MustCompile(`^(?:\d+)?(?:GE|XGE|GigabitEthernet|XGigabitEthernet|Eth-Trunk|Ten-GigabitEthernet|Ethernet)[\d/.\-]+$`)
)

// lldpNeighborFlood conta vizinhos LLDP por porta local e sinaliza portas com
// muitos vizinhos.
func lldpNeighborFlood(d *parse.Device) []Finding {
	out := d.Commands["display lldp neighbor brief"]
	if out == "" {
		return nil
	}

	countByIntf := map[string]int{}
	devsByIntf := map[string]map[string]bool{}

	for _, ln := range strings.Split(out, "\n") {
		f := reCols.Split(strings.TrimSpace(ln), -1)
		if len(f) < 4 {
			continue
		}
		local := f[0]
		if !reLldpIntf.MatchString(local) {
			continue // pula header/legenda
		}
		countByIntf[local]++
		if devsByIntf[local] == nil {
			devsByIntf[local] = map[string]bool{}
		}
		devsByIntf[local][f[1]] = true
	}

	var intfs []string
	for i := range countByIntf {
		intfs = append(intfs, i)
	}
	sort.Strings(intfs)

	var findings []Finding
	for _, local := range intfs {
		n := countByIntf[local]
		if n < lldpFloodThreshold {
			continue
		}
		findings = append(findings, Finding{
			Asset: d.Asset, IP: d.IP, Rule: "lldp-neighbor-flood", Severity: Med,
			Object: local,
			Detail: fmt.Sprintf("%d vizinhos LLDP numa porta fisica (super-emissao/loop de LLDP): %s",
				n, strings.Join(sortedSet(devsByIntf[local]), ", ")),
			Suggestion: "limitar emissao de LLDP no device conectado (ou desabilitar lldp na porta se necessario)",
		})
	}
	return findings
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
