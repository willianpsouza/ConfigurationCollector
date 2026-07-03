package audit

import (
	"strings"
	"testing"

	"github.com/willianpsouza/ConfigurationCollector/internal/parse"
)

func stdDev(asset string, lines ...string) *parse.Device {
	return mkDev(asset, "10.0.0.1", strings.Join(lines, "\n")+"\n", nil, nil)
}

func TestLogNtpStandardization(t *testing.T) {
	a := stdDev("DEV-A",
		"ntp unicast-server 1.1.1.1",
		"info-center loghost 9.9.9.9",
		"clock timezone BRT minus 03:00:00")
	b := stdDev("DEV-B",
		"ntp-service unicast-server 1.1.1.1",
		"info-center loghost source LoopBack0 9.9.9.9",
		"clock timezone BRT minus 03:00:00")
	c := stdDev("DEV-C",
		"ntp unicast-server 2.2.2.2", // nonstandard
		// sem loghost -> missing
		"clock timezone UTC plus 00:00:00") // nonstandard
	d := stdDev("DEV-D",
		"ntp unicast-server 1.1.1.1",
		"info-center loghost 8.8.8.8", // nonstandard
		"clock timezone BRT minus 03:00:00")

	got := logNtpStandardization([]*parse.Device{a, b, c, d})

	// achados por device
	byDev := map[string]map[string]Severity{}
	for _, f := range got {
		if byDev[f.Asset] == nil {
			byDev[f.Asset] = map[string]Severity{}
		}
		byDev[f.Asset][f.Rule] = f.Severity
	}

	if byDev["DEV-C"]["ntp-nonstandard"] != Med {
		t.Errorf("DEV-C deveria ter ntp-nonstandard MED: %+v", byDev["DEV-C"])
	}
	if byDev["DEV-C"]["loghost-missing"] != High {
		t.Errorf("DEV-C deveria ter loghost-missing HIGH: %+v", byDev["DEV-C"])
	}
	if byDev["DEV-C"]["timezone-nonstandard"] != Low {
		t.Errorf("DEV-C deveria ter timezone-nonstandard LOW: %+v", byDev["DEV-C"])
	}
	if byDev["DEV-D"]["loghost-nonstandard"] != Med {
		t.Errorf("DEV-D deveria ter loghost-nonstandard MED: %+v", byDev["DEV-D"])
	}
	if len(byDev["DEV-A"]) != 0 || len(byDev["DEV-B"]) != 0 {
		t.Errorf("DEV-A/B (padrao) nao deveriam ter achados: %+v %+v", byDev["DEV-A"], byDev["DEV-B"])
	}
}

func TestLogNtpMissingAll(t *testing.T) {
	// device unico sem ntp/loghost/tz -> ntp-missing + loghost-missing, orNone vazio.
	d := stdDev("DEV-X", "sysname DEV-X")
	got := logNtpStandardization([]*parse.Device{d})
	if sevOf(got, "ntp-missing") != High || sevOf(got, "loghost-missing") != High {
		t.Fatalf("esperava ntp-missing e loghost-missing HIGH: %+v", got)
	}
	// orNone("") -> "(indefinido)"
	found := false
	for _, f := range got {
		if f.Rule == "ntp-missing" && strings.Contains(f.Detail, "(indefinido)") {
			found = true
		}
	}
	if !found {
		t.Errorf("esperava '(indefinido)' no detail do ntp-missing: %+v", got)
	}
}

func TestLogNtpAllEmptyConfigs(t *testing.T) {
	// configs vazias -> std vazio -> nil
	d := mkDev("DEV-A", "10.0.0.1", "", nil, nil)
	if got := logNtpStandardization([]*parse.Device{d}); got != nil {
		t.Errorf("esperava nil para configs vazias: %+v", got)
	}
}

func TestMajority(t *testing.T) {
	if got := majority(map[string]int{"a": 2, "b": 1}); got != "a" {
		t.Errorf("majority=%q want a", got)
	}
	if got := majority(map[string]int{}); got != "" {
		t.Errorf("majority vazio=%q want ''", got)
	}
	// empate -> menor lexicografico (determinismo)
	if got := majority(map[string]int{"b": 1, "a": 1}); got != "a" {
		t.Errorf("majority empate=%q want a", got)
	}
}

func TestUniqStrings(t *testing.T) {
	got := uniqStrings([]string{"b", "a", "b", "c", "a"})
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("uniqStrings=%v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("uniqStrings[%d]=%q want %q", i, got[i], want[i])
		}
	}
}

func TestContains(t *testing.T) {
	if !contains([]string{"a", "b"}, "a") {
		t.Errorf("contains deveria achar 'a'")
	}
	if contains([]string{"a", "b"}, "z") {
		t.Errorf("contains nao deveria achar 'z'")
	}
}
