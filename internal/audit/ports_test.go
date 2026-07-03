package audit

import (
	"strings"
	"testing"

	"github.com/willianpsouza/ConfigurationCollector/internal/parse"
)

func portsDevice() *parse.Device {
	brief := strings.Join([]string{
		"Interface                     PHY     Protocol Description",
		"GigabitEthernet0/0/1          up      up       to-CLIENT-A",
		"GigabitEthernet0/0/2          down    down",
		"GigabitEthernet0/0/3          *down   down     RESERVED",
		"GigabitEthernet0/0/4          up      up",
		"GigabitEthernet0/0/5          up      up",
		"GigabitEthernet0/0/6          up      up",
		"Vlanif10                      up      up",
	}, "\n")

	ifaces := []parse.Interface{
		mkIface("GigabitEthernet0/0/1", "to-CLIENT-A", " description to-CLIENT-A", " ip address 10.0.0.1 255.255.255.252"),
		mkIface("GigabitEthernet0/0/3", "RESERVED", " description RESERVED", " shutdown"),
		mkIface("GigabitEthernet0/0/4", "", " ip address 10.0.0.5 255.255.255.252"),
		mkIface("GigabitEthernet0/0/6", "", " shutdown"),
	}
	return mkDev("DEV-A", "10.99.99.1", "", ifaces, map[string]string{
		"display interface description": brief,
	})
}

func TestDevicePortsVerdicts(t *testing.T) {
	ports := devicePorts(portsDevice())
	got := map[string]string{}
	for _, p := range ports {
		got[p.Iface] = p.Verdict
	}
	want := map[string]string{
		"GigabitEthernet0/0/1": "configured",
		"GigabitEthernet0/0/2": "unconfigured-dark",
		"GigabitEthernet0/0/3": "shut",
		"GigabitEthernet0/0/4": "configured-no-desc",
		"GigabitEthernet0/0/5": "unconfigured-up",
		"GigabitEthernet0/0/6": "shut", // shutdown via config apesar de brief up
	}
	for iface, wv := range want {
		if got[iface] != wv {
			t.Errorf("%s verdict=%q want %q", iface, got[iface], wv)
		}
	}
	if _, ok := got["Vlanif10"]; ok {
		t.Errorf("Vlanif10 nao e porta fisica, nao deveria aparecer")
	}
}

func TestDevicePortsNoBrief(t *testing.T) {
	if got := devicePorts(mkDev("D", "1", "", nil, nil)); got != nil {
		t.Errorf("sem 'display interface description' deveria dar nil: %+v", got)
	}
}

func TestPortInventorySorted(t *testing.T) {
	inv := PortInventory([]*parse.Device{portsDevice()})
	if len(inv) != 6 {
		t.Fatalf("esperava 6 portas fisicas, veio %d", len(inv))
	}
	for i := 1; i < len(inv); i++ {
		if inv[i-1].Iface > inv[i].Iface {
			t.Errorf("PortInventory nao ordenou: %+v", inv)
		}
	}
}

func TestPortHygiene(t *testing.T) {
	got := portHygiene(portsDevice())
	r := rules(got)
	if r["port-active-unconfigured"] != 1 {
		t.Errorf("esperava 1 port-active-unconfigured (MED): %+v", got)
	}
	if sevOf(got, "port-active-unconfigured") != Med {
		t.Errorf("port-active-unconfigured deveria ser MED")
	}
	if r["port-up-unconfigured"] != 1 {
		t.Errorf("esperava 1 port-up-unconfigured (LOW): %+v", got)
	}
	if r["port-hygiene-summary"] != 1 {
		t.Errorf("esperava 1 port-hygiene-summary: %+v", got)
	}
}

func TestDevicePortsSubinterface(t *testing.T) {
	// Porta-pai bare (omitida do config pelo Huawei) mas com SUBINTERFACE que
	// carrega servico (L2VC do cliente). NAO pode virar "unconfigured".
	brief := strings.Join([]string{
		"Interface                     PHY     Protocol Description",
		"GigabitEthernet0/0/7          up      down", // pai: pareceria dark sem o guard
	}, "\n")
	ifaces := []parse.Interface{
		mkIface("GigabitEthernet0/0/7.3000", "TRANSP-CLIENTE-TEKNET",
			" description TRANSP-CLIENTE-TEKNET", " mpls l2vc 10.99.99.50 3000"),
	}
	d := mkDev("DEV-SUB", "10.99.99.13", "", ifaces, map[string]string{
		"display interface description": brief,
	})

	var v string
	for _, p := range devicePorts(d) {
		if p.Iface == "GigabitEthernet0/0/7" {
			v = p.Verdict
		}
	}
	if v == "" || strings.HasPrefix(v, "unconfigured") {
		t.Errorf("porta com subinterface (L2VC) NAO pode ser unconfigured, veio %q", v)
	}
	for _, f := range portHygiene(d) {
		if f.Object == "GigabitEthernet0/0/7" && strings.Contains(f.Rule, "unconfigured") {
			t.Errorf("nao deveria flagar porta com subif como dark: %+v", f)
		}
	}
}

func TestVerdictOf(t *testing.T) {
	cases := []struct {
		adminDown, operUp, hasDesc, hasConfig bool
		want                                  string
	}{
		{true, true, true, true, "shut"},
		{false, false, false, true, "configured-no-desc"},
		{false, true, true, true, "configured"},
		{false, true, false, false, "unconfigured-up"},
		{false, false, false, false, "unconfigured-dark"},
	}
	for _, c := range cases {
		if got := verdictOf(c.adminDown, c.operUp, c.hasDesc, c.hasConfig); got != c.want {
			t.Errorf("verdictOf(%v,%v,%v,%v)=%q want %q", c.adminDown, c.operUp, c.hasDesc, c.hasConfig, got, c.want)
		}
	}
}

func TestHasShutdownAndRealConfig(t *testing.T) {
	shut := mkIface("GE0/0/1", "", " description X", " shutdown")
	if !hasShutdown(shut) {
		t.Errorf("hasShutdown deveria ser true")
	}
	if hasRealConfig(shut) {
		t.Errorf("so description+shutdown nao e config real")
	}
	noShut := mkIface("GE0/0/2", "", " ip address 10.0.0.1 255.255.255.0")
	if hasShutdown(noShut) {
		t.Errorf("hasShutdown deveria ser false")
	}
	if !hasRealConfig(noShut) {
		t.Errorf("ip address e config real")
	}
	empty := mkIface("GE0/0/3", "", "", "#")
	if hasRealConfig(empty) {
		t.Errorf("linhas vazias/# nao sao config real")
	}
}

func TestBoolWord(t *testing.T) {
	if boolWord(true, "up", "shut") != "up" || boolWord(false, "up", "shut") != "shut" {
		t.Errorf("boolWord errado")
	}
}
