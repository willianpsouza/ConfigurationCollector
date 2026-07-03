package audit

import (
	"testing"

	"github.com/willianpsouza/ConfigurationCollector/internal/parse"
)

func ipIf(name, line string) parse.Interface {
	return mkIface(name, "", " "+line)
}

func TestIPInventory(t *testing.T) {
	a := mkDev("DEV-A", "10.99.99.1", "", []parse.Interface{
		ipIf("GigabitEthernet0/0/1", "ip address 10.0.0.2 255.255.255.0"),
		ipIf("GigabitEthernet0/0/2", "ip address 10.0.0.3 255.255.255.0 sub"),
	}, nil)
	b := mkDev("DEV-B", "10.99.99.2", "", []parse.Interface{
		ipIf("GigabitEthernet0/0/1", "ip address 10.0.0.1 255.255.255.0"),
	}, nil)

	inv := IPInventory([]*parse.Device{a, b})
	if len(inv) != 3 {
		t.Fatalf("esperava 3 entradas, veio %d: %+v", len(inv), inv)
	}
	// ordenado por IP ascendente
	if inv[0].IP != "10.0.0.1" {
		t.Errorf("primeira entrada deveria ser 10.0.0.1, veio %s", inv[0].IP)
	}
	// flag secondary via " sub"
	var sec *IPEntry
	for i := range inv {
		if inv[i].IP == "10.0.0.3" {
			sec = &inv[i]
		}
	}
	if sec == nil || !sec.Secondary {
		t.Errorf("10.0.0.3 deveria ser secondary: %+v", sec)
	}
	if sec.Network != "10.0.0.0/24" {
		t.Errorf("network=%q want 10.0.0.0/24", sec.Network)
	}
}

func TestIPDuplicates(t *testing.T) {
	t.Run("cross-device HIGH", func(t *testing.T) {
		a := mkDev("DEV-A", "10.99.99.1", "", []parse.Interface{
			ipIf("GigabitEthernet0/0/1", "ip address 10.5.5.5 255.255.255.0"),
		}, nil)
		b := mkDev("DEV-B", "10.99.99.2", "", []parse.Interface{
			ipIf("GigabitEthernet0/0/1", "ip address 10.5.5.5 255.255.255.0"),
		}, nil)
		got := ipDuplicates([]*parse.Device{a, b})
		if sevOf(got, "ip-duplicate-cross-device") != High {
			t.Fatalf("esperava ip-duplicate-cross-device HIGH: %+v", got)
		}
	})

	t.Run("OOB mgmt LOW", func(t *testing.T) {
		a := mkDev("DEV-A", "10.99.99.1", "", []parse.Interface{
			ipIf("MEth0/0/0", "ip address 192.168.1.1 255.255.255.0"),
		}, nil)
		b := mkDev("DEV-B", "10.99.99.2", "", []parse.Interface{
			ipIf("MEth0/0/0", "ip address 192.168.1.1 255.255.255.0"),
		}, nil)
		got := ipDuplicates([]*parse.Device{a, b})
		if sevOf(got, "ip-duplicate-oob-mgmt") != Low {
			t.Fatalf("esperava ip-duplicate-oob-mgmt LOW: %+v", got)
		}
	})

	t.Run("same-device MED", func(t *testing.T) {
		a := mkDev("DEV-A", "10.99.99.1", "", []parse.Interface{
			ipIf("GigabitEthernet0/0/1", "ip address 10.6.6.6 255.255.255.0"),
			ipIf("GigabitEthernet0/0/2", "ip address 10.6.6.6 255.255.255.0"),
		}, nil)
		got := ipDuplicates([]*parse.Device{a})
		if sevOf(got, "ip-duplicate-same-device") != Med {
			t.Fatalf("esperava ip-duplicate-same-device MED: %+v", got)
		}
	})

	t.Run("sem duplicata -> nada", func(t *testing.T) {
		a := mkDev("DEV-A", "10.99.99.1", "", []parse.Interface{
			ipIf("GigabitEthernet0/0/1", "ip address 10.7.7.7 255.255.255.0"),
		}, nil)
		if got := ipDuplicates([]*parse.Device{a}); len(got) != 0 {
			t.Errorf("esperava 0: %+v", got)
		}
	})
}

func TestPublicIPInternal(t *testing.T) {
	a := mkDev("DEV-A", "10.99.99.1", "", []parse.Interface{
		ipIf("LoopBack0", "ip address 200.1.1.1 255.255.255.255"),
		ipIf("GigabitEthernet0/0/1", "ip address 200.2.2.1 255.255.255.252"),
		ipIf("GigabitEthernet0/0/2", "ip address 200.3.3.1 255.255.255.252"), // WAN 1 ponta
		ipIf("GigabitEthernet0/0/3", "ip address 10.0.0.1 255.255.255.0"),    // privado
	}, nil)
	b := mkDev("DEV-B", "10.99.99.2", "", []parse.Interface{
		ipIf("GigabitEthernet0/0/1", "ip address 200.2.2.2 255.255.255.252"),
	}, nil)

	got := publicIPInternal([]*parse.Device{a, b})
	if sevOf(got, "loopback-public-ip") != High {
		t.Errorf("esperava loopback-public-ip HIGH: %+v", got)
	}
	if sevOf(got, "internal-link-public-ip") != Med {
		t.Errorf("esperava internal-link-public-ip MED: %+v", got)
	}
	// WAN 200.3.3.0/30 (1 ponta) nao deve virar internal-link.
	r := rules(got)
	if r["internal-link-public-ip"] != 1 {
		t.Errorf("deveria haver exatamente 1 internal-link (200.2.2.0/30): %+v", got)
	}
	if r["loopback-public-ip"] != 1 {
		t.Errorf("deveria haver exatamente 1 loopback-public: %+v", got)
	}
}

func TestIsPrivateIP(t *testing.T) {
	cases := map[string]bool{
		"10.1.2.3":        true,
		"172.16.0.1":      true,
		"172.31.255.255":  true,
		"172.15.0.1":      false,
		"172.32.0.1":      false,
		"192.168.0.1":     true,
		"192.167.0.1":     false,
		"100.64.0.1":      true,
		"100.127.0.1":     true,
		"100.63.0.1":      false,
		"100.128.0.1":     false,
		"127.0.0.1":       true,
		"169.254.0.1":     true,
		"169.253.0.1":     false,
		"8.8.8.8":         false,
		"200.1.1.1":       false,
		"nao.eh.ip":       true, // nao classificavel -> nao flaga
		"1.2.3":           true,
	}
	for ip, want := range cases {
		if got := isPrivateIP(ip); got != want {
			t.Errorf("isPrivateIP(%q)=%v want %v", ip, got, want)
		}
	}
}

func TestIsLoopbackIface(t *testing.T) {
	if !isLoopbackIface("LoopBack0") || !isLoopbackIface("loopback10") {
		t.Errorf("loopback deveria ser reconhecido")
	}
	if isLoopbackIface("GigabitEthernet0/0/1") {
		t.Errorf("GE nao e loopback")
	}
}

func TestNetworkOf(t *testing.T) {
	cases := []struct {
		ip, mask, want string
	}{
		{"10.0.0.5", "255.255.255.0", "10.0.0.0/24"},
		{"10.0.0.5", "24", "10.0.0.0/24"},
		{"200.2.2.1", "255.255.255.252", "200.2.2.0/30"},
		{"10.1.2.3", "0", "0.0.0.0/0"},
		{"10.0.0.5", "999", ""}, // prefixo invalido
		{"bad-ip", "24", ""},    // ip invalido
	}
	for _, c := range cases {
		if got := networkOf(c.ip, c.mask); got != c.want {
			t.Errorf("networkOf(%q,%q)=%q want %q", c.ip, c.mask, got, c.want)
		}
	}
}

func TestMaskToPrefix(t *testing.T) {
	cases := map[string]int{
		"255.255.255.252": 30,
		"255.255.255.0":   24,
		"255.0.255.0":     8, // conta 1s ate primeiro 0
		"30":              30,
		"0":               0,
		"33":              -1,
		"abc":             -1,
		"999.1.1.1":       -1,
	}
	for m, want := range cases {
		if got := maskToPrefix(m); got != want {
			t.Errorf("maskToPrefix(%q)=%d want %d", m, got, want)
		}
	}
}

func TestParseOctets(t *testing.T) {
	if o := parseOctets("1.2.3.4"); o == nil || o[0] != 1 || o[3] != 4 {
		t.Errorf("parseOctets valido falhou: %v", o)
	}
	for _, bad := range []string{"1.2.3", "256.0.0.1", "a.b.c.d", "-1.0.0.0", "1.2.3.4.5"} {
		if parseOctets(bad) != nil {
			t.Errorf("parseOctets(%q) deveria ser nil", bad)
		}
	}
}

func TestIPLess(t *testing.T) {
	if !ipLess("10.0.0.1", "10.0.0.2") {
		t.Errorf("10.0.0.1 < 10.0.0.2")
	}
	if ipLess("10.0.0.2", "10.0.0.1") {
		t.Errorf("10.0.0.2 !< 10.0.0.1")
	}
	if ipLess("10.0.0.1", "10.0.0.1") {
		t.Errorf("igual nao e menor")
	}
	// caminho invalido -> comparacao de string
	if !ipLess("aaa", "bbb") {
		t.Errorf("fallback string: aaa < bbb")
	}
}

func TestAllMgmtIfaceAndLocations(t *testing.T) {
	meth := []IPEntry{{Device: "DEV-A", Iface: "MEth0/0/0"}, {Device: "DEV-B", Iface: "management0"}}
	if !allMgmtIface(meth) {
		t.Errorf("todas mgmt deveria ser true")
	}
	mix := []IPEntry{{Device: "DEV-A", Iface: "MEth0/0/0"}, {Device: "DEV-B", Iface: "GigabitEthernet0/0/1"}}
	if allMgmtIface(mix) {
		t.Errorf("mix nao deveria ser mgmt")
	}
	loc := ipLocations([]IPEntry{{Device: "DEV-A", Iface: "GE0/0/1"}, {Device: "DEV-B", Iface: "GE0/0/2"}})
	if loc != "DEV-A/GE0/0/1, DEV-B/GE0/0/2" {
		t.Errorf("ipLocations=%q", loc)
	}
}
