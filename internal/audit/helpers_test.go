package audit

import "github.com/willianpsouza/ConfigurationCollector/internal/parse"

// mkDev monta um parse.Device de fixture.
func mkDev(asset, ip, config string, ifaces []parse.Interface, cmds map[string]string) *parse.Device {
	if cmds == nil {
		cmds = map[string]string{}
	}
	return &parse.Device{
		Asset:      asset,
		IP:         ip,
		Vendor:     "Huawei",
		Config:     config,
		Interfaces: ifaces,
		Commands:   cmds,
	}
}

// mkIface monta uma stanza de interface de fixture.
func mkIface(name, desc string, lines ...string) parse.Interface {
	return parse.Interface{Name: name, Description: desc, Lines: lines}
}

// rules coleta os nomes de regra dos achados (para asserts).
func rules(fs []Finding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[f.Rule]++
	}
	return m
}

// sevOf devolve a severidade do primeiro achado com dada regra ("" se ausente).
func sevOf(fs []Finding, rule string) Severity {
	for _, f := range fs {
		if f.Rule == rule {
			return f.Severity
		}
	}
	return ""
}

// hasRule informa se algum achado tem a regra.
func hasRule(fs []Finding, rule string) bool {
	for _, f := range fs {
		if f.Rule == rule {
			return true
		}
	}
	return false
}
