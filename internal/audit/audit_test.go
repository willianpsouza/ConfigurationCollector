package audit

import (
	"testing"

	"github.com/willianpsouza/ConfigurationCollector/internal/parse"
)

func TestClientInterfaceBlindness(t *testing.T) {
	cases := []struct {
		name      string
		ifc       parse.Interface
		wantRule  string
		wantSev   Severity
		wantEmpty bool
	}{
		{
			name: "sub dot1q ip sem band e sem stat -> HIGH",
			ifc: mkIface("GigabitEthernet0/0/1.100", "CLIENTE-X",
				" dot1q termination vid 100",
				" ip address 10.0.0.1 255.255.255.252",
			),
			wantRule: "client-interface-blindness", wantSev: High,
		},
		{
			name: "sub com stat mas sem band -> MED no-bandwidth",
			ifc: mkIface("GigabitEthernet0/0/2.200", "",
				" dot1q termination vid 200",
				" ip address 10.0.0.5 255.255.255.252",
				" statistic enable",
			),
			wantRule: "client-interface-no-bandwidth", wantSev: Med,
		},
		{
			name: "sub com band mas sem stat -> MED no-stats",
			ifc: mkIface("GigabitEthernet0/0/3.300", "",
				" dot1q termination vid 300",
				" ip address 10.0.0.9 255.255.255.252",
				" traffic-policy PLANO inbound",
			),
			wantRule: "client-interface-no-stats", wantSev: Med,
		},
		{
			name: "sub com band E stat -> nada",
			ifc: mkIface("GigabitEthernet0/0/4.400", "",
				" dot1q termination vid 400",
				" ip address 10.0.0.13 255.255.255.252",
				" traffic-policy PLANO inbound",
				" statistic enable",
			),
			wantEmpty: true,
		},
		{
			name: "sub backbone (ospf) -> excluida",
			ifc: mkIface("GigabitEthernet0/0/5.500", "",
				" dot1q termination vid 500",
				" ip address 10.0.0.17 255.255.255.252",
				" ospf enable 1 area 0.0.0.0",
			),
			wantEmpty: true,
		},
		{
			name: "sub dot1q sem ip -> ignorada",
			ifc: mkIface("GigabitEthernet0/0/6.600", "",
				" dot1q termination vid 600",
			),
			wantEmpty: true,
		},
		{
			name: "sub com ip mas sem encap -> ignorada",
			ifc: mkIface("GigabitEthernet0/0/7.700", "",
				" ip address 10.0.0.21 255.255.255.252",
			),
			wantEmpty: true,
		},
		{
			name:      "nao-subinterface -> ignorada",
			ifc:       mkIface("GigabitEthernet0/0/8", "", " dot1q termination vid 800", " ip address 10.0.0.25 255.255.255.252"),
			wantEmpty: true,
		},
		{
			name: "vpn-bind + dot1q sem band/stat -> HIGH (hasIP via binding)",
			ifc: mkIface("GigabitEthernet0/0/9.900", "",
				" ip binding vpn-instance VRF-A",
				" dot1q termination vid 900",
			),
			wantRule: "client-interface-blindness", wantSev: High,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := mkDev("DEV-A", "10.99.99.1", "", []parse.Interface{c.ifc}, nil)
			got := clientInterfaceBlindness(d)
			if c.wantEmpty {
				if len(got) != 0 {
					t.Fatalf("esperava vazio, veio %+v", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("esperava 1 achado, veio %d: %+v", len(got), got)
			}
			if got[0].Rule != c.wantRule {
				t.Errorf("rule=%q want %q", got[0].Rule, c.wantRule)
			}
			if got[0].Severity != c.wantSev {
				t.Errorf("sev=%q want %q", got[0].Severity, c.wantSev)
			}
		})
	}
}

// TestClientBlindnessObjectHasDesc garante que a descricao entra no Object.
func TestClientBlindnessObjectHasDesc(t *testing.T) {
	ifc := mkIface("GigabitEthernet0/0/1.100", "CLIENTE-Z",
		" dot1q termination vid 100",
		" ip address 10.0.0.1 255.255.255.252",
	)
	d := mkDev("DEV-A", "10.99.99.1", "", []parse.Interface{ifc}, nil)
	got := clientInterfaceBlindness(d)
	if len(got) != 1 {
		t.Fatalf("esperava 1: %+v", got)
	}
	if got[0].Object != "GigabitEthernet0/0/1.100 (CLIENTE-Z)" {
		t.Errorf("object=%q", got[0].Object)
	}
}

func TestSevRankAndRunSorting(t *testing.T) {
	if sevRank(High) != 0 || sevRank(Med) != 1 || sevRank(Low) != 2 || sevRank("x") != 2 {
		t.Fatalf("sevRank inesperado")
	}

	// Device que gera HIGH (client-blindness) e LOW (vlan-orphan) -> HIGH primeiro.
	cfg := "vlan batch 10 20\n#\ninterface Vlanif10\n ip address 10.0.0.1 255.255.255.0\n#\n"
	ifc := mkIface("GigabitEthernet0/0/1.100", "",
		" dot1q termination vid 100",
		" ip address 172.16.0.1 255.255.255.252",
	)
	d := mkDev("DEV-A", "10.99.99.1", cfg, []parse.Interface{ifc}, nil)
	out := Run(d)
	if len(out) < 2 {
		t.Fatalf("esperava >=2 achados, veio %+v", out)
	}
	if sevRank(out[0].Severity) > sevRank(out[len(out)-1].Severity) {
		t.Errorf("ordenacao por severidade quebrada: %+v", out)
	}
	if out[0].Severity != High {
		t.Errorf("primeiro achado deveria ser HIGH: %+v", out[0])
	}
}

func TestJoinLines(t *testing.T) {
	if joinLines(nil) != "" {
		t.Errorf("joinLines(nil) != \"\"")
	}
	if joinLines([]string{"a", "b"}) != "a\nb\n" {
		t.Errorf("joinLines mismatch: %q", joinLines([]string{"a", "b"}))
	}
}
