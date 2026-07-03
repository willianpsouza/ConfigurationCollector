package audit

import (
	"testing"

	"github.com/willianpsouza/ConfigurationCollector/internal/parse"
)

// subIf monta uma subinterface dot1q com o vid dado e linhas extras.
func subIf(name string, vid string, extra ...string) parse.Interface {
	lines := append([]string{" dot1q termination vid " + vid}, extra...)
	return mkIface(name, "", lines...)
}

func TestVlanCircuitCorrelationSymmetric(t *testing.T) {
	// Duas pontas simetricas (nem stat nem CAR nem mtu) -> zero achados.
	a := mkDev("DEV-A", "10.99.99.1", "", []parse.Interface{
		subIf("GigabitEthernet0/0/1.100", "100"),
	}, nil)
	b := mkDev("DEV-B", "10.99.99.2", "", []parse.Interface{
		subIf("GigabitEthernet0/0/1.100", "100"),
	}, nil)
	got := vlanCircuitCorrelation([]*parse.Device{a, b})
	if len(got) != 0 {
		t.Fatalf("esperava 0 achados simetricos, veio %+v", got)
	}
}

func TestVlanCircuitCorrelationAsymmetric(t *testing.T) {
	// Stats assimetrica (A tem, B nao), CAR assimetrica, MTU divergente.
	a := mkDev("DEV-A", "10.99.99.1", "", []parse.Interface{
		subIf("GigabitEthernet0/0/1.100", "100",
			" statistic enable",
			" traffic-policy PLANO inbound",
			" mtu 1500"),
	}, nil)
	b := mkDev("DEV-B", "10.99.99.2", "", []parse.Interface{
		subIf("GigabitEthernet0/0/1.100", "100",
			" mtu 9000"),
	}, nil)
	got := vlanCircuitCorrelation([]*parse.Device{a, b})
	r := rules(got)
	if r["circuit-asymmetric-stats"] == 0 {
		t.Errorf("faltou circuit-asymmetric-stats: %+v", got)
	}
	if r["circuit-asymmetric-bandwidth"] == 0 {
		t.Errorf("faltou circuit-asymmetric-bandwidth: %+v", got)
	}
	if sevOf(got, "circuit-mtu-mismatch") != High {
		t.Errorf("circuit-mtu-mismatch deveria ser HIGH: %+v", got)
	}
}

func TestVlanCircuitSingleEnd(t *testing.T) {
	// 1 ponta INTERNA (backbone, client=false) -> vlan-single-end LOW.
	internal := mkDev("DEV-A", "10.99.99.1", "", []parse.Interface{
		subIf("GigabitEthernet0/0/1.100", "100", " ospf enable 1 area 0.0.0.0"),
	}, nil)
	got := vlanCircuitCorrelation([]*parse.Device{internal})
	if sevOf(got, "vlan-single-end") != Low {
		t.Errorf("esperava vlan-single-end LOW: %+v", got)
	}

	// 1 ponta CLIENTE (sem backbone -> client=true) -> nenhum achado.
	client := mkDev("DEV-B", "10.99.99.2", "", []parse.Interface{
		subIf("GigabitEthernet0/0/1.200", "200"),
	}, nil)
	got2 := vlanCircuitCorrelation([]*parse.Device{client})
	if hasRule(got2, "vlan-single-end") {
		t.Errorf("ponta cliente nao deveria gerar vlan-single-end: %+v", got2)
	}
}

func TestVlanCircuitMultipoint(t *testing.T) {
	mk := func(asset, cfg string) *parse.Device {
		return mkDev(asset, "10.0.0.1", cfg, []parse.Interface{
			subIf("GigabitEthernet0/0/1.500", "500"),
		}, nil)
	}
	// 3 pontas sem VSI em lugar nenhum -> vlan-unexpected-multipoint MED.
	got := vlanCircuitCorrelation([]*parse.Device{mk("DEV-A", ""), mk("DEV-B", ""), mk("DEV-C", "")})
	if sevOf(got, "vlan-unexpected-multipoint") != Med {
		t.Fatalf("esperava vlan-unexpected-multipoint MED: %+v", got)
	}

	// 3 pontas mas uma delas tem VSI no config -> sem achado multipoint.
	withVSI := vlanCircuitCorrelation([]*parse.Device{
		mk("DEV-A", " l2 binding vsi FOO\n"),
		mk("DEV-B", ""),
		mk("DEV-C", ""),
	})
	if hasRule(withVSI, "vlan-unexpected-multipoint") {
		t.Errorf("com VSI nao deveria gerar multipoint: %+v", withVSI)
	}
}

func TestVlanCircuitIgnoresNonDot1qAndVidZero(t *testing.T) {
	// Subinterface sem VID dot1q e nao-subinterface -> ignoradas (byVID vazio).
	d := mkDev("DEV-A", "10.0.0.1", "", []parse.Interface{
		mkIface("GigabitEthernet0/0/1.100", "", " ip address 10.0.0.1 255.255.255.252"),
		mkIface("GigabitEthernet0/0/2", "", " dot1q termination vid 10"),
	}, nil)
	if got := vlanCircuitCorrelation([]*parse.Device{d}); len(got) != 0 {
		t.Errorf("esperava 0, veio %+v", got)
	}
}

func TestSymmetryFindingsNoMtuFindingWhenBothEmpty(t *testing.T) {
	a := endpoint{device: "A", iface: "if0", hasStat: true, hasCAR: true, mtu: ""}
	b := endpoint{device: "B", iface: "if0", hasStat: true, hasCAR: true, mtu: ""}
	if got := symmetryFindings(10, a, b); len(got) != 0 {
		t.Errorf("simetrico deveria dar 0: %+v", got)
	}
}

func TestRunFleetAggregates(t *testing.T) {
	// RunFleet passa por todas as FleetRules; garante que roda e ordena.
	a := mkDev("DEV-A", "10.99.99.1", "", []parse.Interface{
		subIf("GigabitEthernet0/0/1.100", "100", " statistic enable", " mtu 1500"),
	}, nil)
	b := mkDev("DEV-B", "10.99.99.2", "", []parse.Interface{
		subIf("GigabitEthernet0/0/1.100", "100", " mtu 9000"),
	}, nil)
	out := RunFleet([]*parse.Device{a, b})
	if len(out) == 0 {
		t.Fatalf("RunFleet nao produziu achados")
	}
	// ordenado por severidade nao-decrescente
	for i := 1; i < len(out); i++ {
		if sevRank(out[i-1].Severity) > sevRank(out[i].Severity) {
			t.Fatalf("RunFleet nao ordenou por severidade: %+v", out)
		}
	}
}

func TestAtoi(t *testing.T) {
	cases := map[string]int{"0": 0, "123": 123, "12a": 0, "": 0, "007": 7}
	for in, want := range cases {
		if got := atoi(in); got != want {
			t.Errorf("atoi(%q)=%d want %d", in, got, want)
		}
	}
}

func TestShort(t *testing.T) {
	if got := short("ITAQUA-CORE01-10-99-99-100"); got != "ITAQUA-CORE01" {
		t.Errorf("short trunca errado: %q", got)
	}
	if got := short("SEMPADRAO"); got != "SEMPADRAO" {
		t.Errorf("short sem padrao deveria manter: %q", got)
	}
}

func TestEpsHelpers(t *testing.T) {
	eps := []endpoint{
		{device: "DEV-A", iface: "GE0/0/1.1"},
		{device: "DEV-B", iface: "GE0/0/2.2"},
	}
	if !epsHasDevice(eps, "DEV-A") || epsHasDevice(eps, "DEV-Z") {
		t.Errorf("epsHasDevice errado")
	}
	if got := epsList(eps); got != "DEV-A/GE0/0/1.1, DEV-B/GE0/0/2.2" {
		t.Errorf("epsList=%q", got)
	}
}
