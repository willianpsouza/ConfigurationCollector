package audit

import (
	"strings"
	"testing"
)

func TestVlanOrphansSingle(t *testing.T) {
	cfg := strings.Join([]string{
		"vlan batch 10 20 to 22 30 40 50 60",
		"#",
		"interface Vlanif10",
		" ip address 10.0.0.1 255.255.255.0",
		"#",
		"interface GigabitEthernet0/0/1",
		" port default vlan 20",
		" port trunk allow-pass vlan 21",
		" port trunk pvid vlan 60",
		"#",
		"interface GigabitEthernet0/0/2",
		" port hybrid tagged vlan 40",
		" mux-vlan 50",
		"#",
		"interface GigabitEthernet0/0/3.30",
		" dot1q termination vid 30",
		"#",
	}, "\n") + "\n"

	d := mkDev("DEV-A", "10.99.99.1", cfg, nil, nil)
	got := vlanOrphans(d)
	if len(got) != 1 {
		t.Fatalf("esperava 1 achado, veio %+v", got)
	}
	f := got[0]
	if f.Rule != "vlan-orphan" || f.Severity != Low {
		t.Errorf("rule/sev inesperado: %+v", f)
	}
	if f.Object != "1 VLANs" {
		t.Errorf("object=%q want '1 VLANs'", f.Object)
	}
	if !strings.Contains(f.Detail, "22") {
		t.Errorf("detail deveria citar VLAN 22 orfa: %q", f.Detail)
	}
}

func TestVlanOrphansVlanDeclAndVlan1Ignored(t *testing.T) {
	// forma "vlan N" declara; VLAN 1 e ignorada; 40 fica orfa.
	cfg := "vlan batch 1\n#\nvlan 40\n#\n"
	d := mkDev("DEV-A", "10.99.99.1", cfg, nil, nil)
	got := vlanOrphans(d)
	if len(got) != 1 || !strings.Contains(got[0].Detail, "40") {
		t.Fatalf("esperava orfa 40 (VLAN 1 ignorada): %+v", got)
	}
}

func TestVlanOrphansManyIsMed(t *testing.T) {
	cfg := "vlan batch 100 to 130\n#\n"
	d := mkDev("DEV-A", "10.99.99.1", cfg, nil, nil)
	got := vlanOrphans(d)
	if len(got) != 1 || got[0].Severity != Med {
		t.Fatalf("esperava 1 achado MED (>20 orfas): %+v", got)
	}
	if got[0].Object != "31 VLANs" {
		t.Errorf("object=%q want '31 VLANs'", got[0].Object)
	}
}

func TestVlanOrphansEdgeCases(t *testing.T) {
	// config vazia
	if got := vlanOrphans(mkDev("D", "1", "", nil, nil)); got != nil {
		t.Errorf("config vazia deveria dar nil: %+v", got)
	}
	// nenhuma VLAN criada
	if got := vlanOrphans(mkDev("D", "1", "interface GigabitEthernet0/0/1\n#\n", nil, nil)); got != nil {
		t.Errorf("sem vlans criadas deveria dar nil: %+v", got)
	}
	// todas usadas -> sem orfas
	cfg := "vlan batch 10\n#\ninterface Vlanif10\n ip address 10.0.0.1 255.255.255.0\n#\n"
	if got := vlanOrphans(mkDev("D", "1", cfg, nil, nil)); got != nil {
		t.Errorf("todas usadas deveria dar nil: %+v", got)
	}
}

func TestParseVlanList(t *testing.T) {
	got := parseVlanList("135 274 to 275 300")
	want := []int{135, 274, 275, 300}
	if len(got) != len(want) {
		t.Fatalf("parseVlanList len=%d want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("parseVlanList[%d]=%d want %d", i, got[i], want[i])
		}
	}
}

func TestCompactRanges(t *testing.T) {
	if got := compactRanges([]int{274, 275, 276, 300}); got != "274-276 300" {
		t.Errorf("compactRanges=%q want '274-276 300'", got)
	}
	if got := compactRanges(nil); got != "" {
		t.Errorf("compactRanges(nil)=%q want ''", got)
	}
	if got := compactRanges([]int{5}); got != "5" {
		t.Errorf("compactRanges([5])=%q want '5'", got)
	}

	// forca truncamento (>300 chars): muitos valores nao-consecutivos.
	var big []int
	for i := 0; i < 200; i++ {
		big = append(big, i*2) // pares -> nenhum consecutivo
	}
	got := compactRanges(big)
	if !strings.HasSuffix(got, " ...") {
		t.Errorf("compactRanges longo deveria truncar com ' ...': len=%d", len(got))
	}
	if len(got) > 320 {
		t.Errorf("compactRanges truncado tamanho inesperado: %d", len(got))
	}
}
