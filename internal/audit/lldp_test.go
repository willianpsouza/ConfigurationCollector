package audit

import (
	"strings"
	"testing"

	"github.com/willianpsouza/ConfigurationCollector/internal/parse"
)

func lldpDev(brief string) *parse.Device {
	return &parse.Device{
		Asset:    "SW-01-10-99-99-3",
		IP:       "10.99.99.3",
		Commands: map[string]string{"display lldp neighbor brief": brief},
	}
}

func TestLldpNeighborFlood(t *testing.T) {
	brief := `display lldp neighbor brief
Local Intf       Neighbor Dev             Neighbor Intf             Exptime(s)
XGE0/0/24        SERVIDOR-ESCRITORIO      sfp-sfpplus1              120
XGE0/0/24        SERVIDOR-ESCRITORIO      vlan759                   120
XGE0/0/24        SERVIDOR-ESCRITORIO      vlan3466                  120
XGE0/0/1         CORE-01                  100GE0/0/1                115
Eth-Trunk0       PEER-02                  Eth-Trunk0                110
`
	got := lldpNeighborFlood(lldpDev(brief))
	if len(got) != 1 {
		t.Fatalf("esperava 1 achado, veio %d: %+v", len(got), got)
	}
	f := got[0]
	if f.Rule != "lldp-neighbor-flood" || f.Severity != Med {
		t.Errorf("rule/sev inesperado: %s/%s", f.Rule, f.Severity)
	}
	if f.Object != "XGE0/0/24" {
		t.Errorf("object = %q, quero XGE0/0/24", f.Object)
	}
	if !strings.Contains(f.Detail, "3 vizinhos") || !strings.Contains(f.Detail, "SERVIDOR-ESCRITORIO") {
		t.Errorf("detail inesperado: %q", f.Detail)
	}
}

func TestLldpNeighborFloodBelowThreshold(t *testing.T) {
	// 2 vizinhos na mesma porta: abaixo do threshold (3) -> nao flaga.
	brief := `Local Intf       Neighbor Dev             Neighbor Intf             Exptime(s)
XGE0/0/9         DEV-A                    ether1                    120
XGE0/0/9         DEV-A                    ether2                    120
`
	if got := lldpNeighborFlood(lldpDev(brief)); len(got) != 0 {
		t.Fatalf("esperava 0 achados, veio %d", len(got))
	}
}

func TestLldpNeighborFloodNoCommand(t *testing.T) {
	if got := lldpNeighborFlood(&parse.Device{Commands: map[string]string{}}); got != nil {
		t.Fatalf("sem comando deveria devolver nil, veio %+v", got)
	}
}

func TestLldpNeighborFloodMultiDev(t *testing.T) {
	// 3 vizinhos de 2 devices distintos na mesma porta -> flag, lista ambos.
	brief := `Local Intf       Neighbor Dev             Neighbor Intf             Exptime(s)
XGE0/0/15        SERV-DMZ                 ether1                    120
XGE0/0/15        SERV-HOTSPOT             ether2                    120
XGE0/0/15        SERV-DMZ                 ether3                    120
`
	got := lldpNeighborFlood(lldpDev(brief))
	if len(got) != 1 {
		t.Fatalf("esperava 1 achado, veio %d", len(got))
	}
	if !strings.Contains(got[0].Detail, "SERV-DMZ") || !strings.Contains(got[0].Detail, "SERV-HOTSPOT") {
		t.Errorf("detail deveria listar os 2 devices: %q", got[0].Detail)
	}
}

func TestSortedSet(t *testing.T) {
	got := sortedSet(map[string]bool{"b": true, "a": true, "c": true})
	if strings.Join(got, ",") != "a,b,c" {
		t.Errorf("sortedSet = %v", got)
	}
}
