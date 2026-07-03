package audit

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/willianpsouza/ConfigurationCollector/internal/parse"
)

// Regras de padronizacao de casa (logs, NTP, timezone) — problemas reais
// relatados no parque Skynet. Sao FleetRules: comparam cada device contra o
// padrao de-facto (maioria) e flagam desvios/ausencias.
func init() {
	FleetRegistry = append(FleetRegistry, logNtpStandardization)
}

var (
	// Huawei VRP5: "ntp-service unicast-server 1.2.3.4"; VRP8: "ntp unicast-server 1.2.3.4"
	reNTP = regexp.MustCompile(`(?m)^\s*ntp(?:-service)?\s+(?:unicast-server|server)\s+(\d+\.\d+\.\d+\.\d+)`)
	// "info-center loghost 1.2.3.4" ou "info-center loghost source X 1.2.3.4"
	reLogHost  = regexp.MustCompile(`(?m)^\s*info-center loghost\s+(?:source\s+\S+\s+)?(\d+\.\d+\.\d+\.\d+)`)
	reTimezone = regexp.MustCompile(`(?m)^\s*clock timezone\s+(\S+)\s+(\S+)\s+(\S+)`)
)

type devStd struct {
	dev, ip  string
	ntp      []string
	loghost  []string
	timezone string
}

func logNtpStandardization(devs []*parse.Device) []Finding {
	var std []devStd
	ntpCount := map[string]int{}
	logCount := map[string]int{}
	tzCount := map[string]int{}

	for _, d := range devs {
		cfg := d.Config
		if cfg == "" {
			continue
		}
		s := devStd{dev: d.Asset, ip: d.IP}
		s.ntp = uniqStrings(allMatches(reNTP, cfg))
		s.loghost = uniqStrings(allMatches(reLogHost, cfg))
		if m := reTimezone.FindStringSubmatch(cfg); m != nil {
			s.timezone = m[1] + " " + m[2] + " " + m[3]
		}
		std = append(std, s)
		for _, v := range s.ntp {
			ntpCount[v]++
		}
		for _, v := range s.loghost {
			logCount[v]++
		}
		if s.timezone != "" {
			tzCount[s.timezone]++
		}
	}
	if len(std) == 0 {
		return nil
	}

	stdNTP := majority(ntpCount)
	stdLog := majority(logCount)
	stdTZ := majority(tzCount)

	var out []Finding
	for _, s := range std {
		// NTP
		switch {
		case len(s.ntp) == 0:
			out = append(out, Finding{
				Asset: s.dev, IP: s.ip, Rule: "ntp-missing", Severity: High,
				Object: "NTP",
				Detail: fmt.Sprintf("sem servidor NTP configurado (padrao de casa: %s)", orNone(stdNTP)),
				Suggestion: fmt.Sprintf("configurar 'ntp unicast-server %s'", orNone(stdNTP)),
			})
		case stdNTP != "" && !contains(s.ntp, stdNTP):
			out = append(out, Finding{
				Asset: s.dev, IP: s.ip, Rule: "ntp-nonstandard", Severity: Med,
				Object: "NTP",
				Detail: fmt.Sprintf("NTP divergente do padrao: tem [%s], padrao=%s", strings.Join(s.ntp, ", "), stdNTP),
				Suggestion: fmt.Sprintf("incluir o servidor NTP padrao %s", stdNTP),
			})
		}
		// Logging (info-center loghost)
		switch {
		case len(s.loghost) == 0:
			out = append(out, Finding{
				Asset: s.dev, IP: s.ip, Rule: "loghost-missing", Severity: High,
				Object: "syslog/info-center",
				Detail: fmt.Sprintf("sem loghost (info-center) configurado (padrao: %s)", orNone(stdLog)),
				Suggestion: fmt.Sprintf("configurar 'info-center loghost %s'", orNone(stdLog)),
			})
		case stdLog != "" && !contains(s.loghost, stdLog):
			out = append(out, Finding{
				Asset: s.dev, IP: s.ip, Rule: "loghost-nonstandard", Severity: Med,
				Object: "syslog/info-center",
				Detail: fmt.Sprintf("loghost divergente: tem [%s], padrao=%s", strings.Join(s.loghost, ", "), stdLog),
				Suggestion: fmt.Sprintf("apontar logs para o loghost padrao %s", stdLog),
			})
		}
		// Timezone
		if s.timezone != "" && stdTZ != "" && s.timezone != stdTZ {
			out = append(out, Finding{
				Asset: s.dev, IP: s.ip, Rule: "timezone-nonstandard", Severity: Low,
				Object: "clock timezone",
				Detail: fmt.Sprintf("timezone divergente: %q, padrao=%q", s.timezone, stdTZ),
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return sevRank(out[i].Severity) < sevRank(out[j].Severity) })
	return out
}

// majority devolve a chave mais frequente (padrao de-facto), ou "" se vazio.
func majority(m map[string]int) string {
	best, bestN := "", 0
	// ordena chaves para determinismo em empate
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if m[k] > bestN {
			best, bestN = k, m[k]
		}
	}
	return best
}

func allMatches(re *regexp.Regexp, s string) []string {
	var out []string
	for _, m := range re.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

func uniqStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

func orNone(s string) string {
	if s == "" {
		return "(indefinido)"
	}
	return s
}
