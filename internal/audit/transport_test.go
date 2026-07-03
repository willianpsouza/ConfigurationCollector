package audit

import (
	"testing"

	"github.com/willianpsouza/ConfigurationCollector/internal/parse"
)

// l2vcIf monta uma interface com stanza "mpls l2vc <peer> <vcid> [pw-template X]".
func l2vcIf(name, line string) parse.Interface {
	return mkIface(name, "", " "+line)
}

func TestBuildAddr2DevMultiLoopback(t *testing.T) {
	// Device com IP de mgmt + lsr-id + loopback secundario no config.
	cfg := "mpls lsr-id 10.99.99.100\n" +
		"#\n" +
		"interface LoopBack100\n" +
		" ip address 10.99.99.200 255.255.255.255\n" +
		"#\n" +
		"interface LoopBack1000\n" +
		" ip address 10.99.99.100 255.255.255.255\n" +
		"#\n"
	d := mkDev("ITAQUA-CORE01", "10.1.1.1", cfg, nil, nil)
	m := buildAddr2Dev([]*parse.Device{d})
	for _, ip := range []string{"10.1.1.1", "10.99.99.100", "10.99.99.200"} {
		if m[ip] != "ITAQUA-CORE01" {
			t.Errorf("addr2dev[%s]=%q want ITAQUA-CORE01", ip, m[ip])
		}
	}
}

func TestMeshSummary(t *testing.T) {
	a := mkDev("DEV-A", "10.0.0.1", "mpls lsr-id 10.0.0.1\n", []parse.Interface{
		l2vcIf("GigabitEthernet0/0/1.10", "mpls l2vc 10.0.0.2 100"),
	}, nil)
	b := mkDev("DEV-B", "10.0.0.2", "mpls lsr-id 10.0.0.2\n", []parse.Interface{
		l2vcIf("GigabitEthernet0/0/1.10", "mpls l2vc 10.0.0.9 100"),
	}, nil)
	mesh := MeshSummary([]*parse.Device{a, b})

	if len(mesh.Collected) != 2 {
		t.Errorf("Collected=%v want 2", mesh.Collected)
	}
	// 10.0.0.2 e coletado (lsr-id de B); 10.0.0.9 nao.
	if len(mesh.Missing) != 1 || mesh.Missing[0] != "10.0.0.9" {
		t.Errorf("Missing=%v want [10.0.0.9]", mesh.Missing)
	}
	if _, ok := mesh.Peers["10.0.0.2"]; !ok {
		t.Errorf("Peers deveria conter 10.0.0.2: %v", mesh.Peers)
	}
}

func TestL2vcPairPeerResolveOK(t *testing.T) {
	// ITQ resolve pelo loopback secundario (10.0.0.200 -> DEV-ITQ).
	itq := mkDev("DEV-ITQ", "10.0.0.100",
		"mpls lsr-id 10.0.0.100\n#\ninterface LoopBack1\n ip address 10.0.0.200 255.255.255.255\n#\n",
		[]parse.Interface{l2vcIf("GigabitEthernet0/0/1.10", "mpls l2vc 10.0.0.2 100")}, nil)
	sp := mkDev("DEV-SP", "10.0.0.2", "mpls lsr-id 10.0.0.2\n",
		[]parse.Interface{l2vcIf("GigabitEthernet0/0/1.10", "mpls l2vc 10.0.0.200 100")}, nil)

	got := l2vcCorrelation([]*parse.Device{itq, sp})
	if len(got) != 0 {
		t.Fatalf("par resolvido corretamente nao deveria gerar achados: %+v", got)
	}
}

func TestL2vcPeerMismatch(t *testing.T) {
	// Ponta B aponta para um terceiro device coletado (DEV-X) -> mismatch HIGH.
	a := mkDev("DEV-A", "10.0.0.1", "mpls lsr-id 10.0.0.1\n",
		[]parse.Interface{l2vcIf("GigabitEthernet0/0/1.10", "mpls l2vc 10.0.0.2 100")}, nil)
	b := mkDev("DEV-B", "10.0.0.2", "mpls lsr-id 10.0.0.2\n",
		[]parse.Interface{l2vcIf("GigabitEthernet0/0/1.10", "mpls l2vc 10.0.0.9 100")}, nil)
	x := mkDev("DEV-X", "10.0.0.9", "mpls lsr-id 10.0.0.9\n", nil, nil)

	got := l2vcCorrelation([]*parse.Device{a, b, x})
	if sevOf(got, "l2vc-peer-mismatch") != High {
		t.Fatalf("esperava l2vc-peer-mismatch HIGH: %+v", got)
	}
}

func TestL2vcPeerUnresolved(t *testing.T) {
	// Ponta B aponta para IP que nao resolve para nenhum device coletado -> MED.
	a := mkDev("DEV-A", "10.0.0.1", "mpls lsr-id 10.0.0.1\n",
		[]parse.Interface{l2vcIf("GigabitEthernet0/0/1.10", "mpls l2vc 10.0.0.2 100")}, nil)
	b := mkDev("DEV-B", "10.0.0.2", "mpls lsr-id 10.0.0.2\n",
		[]parse.Interface{l2vcIf("GigabitEthernet0/0/1.10", "mpls l2vc 10.0.0.250 100")}, nil)

	got := l2vcCorrelation([]*parse.Device{a, b})
	if sevOf(got, "l2vc-peer-unresolved") != Med {
		t.Fatalf("esperava l2vc-peer-unresolved MED: %+v", got)
	}
}

func TestL2vcSingleEndFarNotCollected(t *testing.T) {
	// 1 ponta, peer fora do escopo -> l2vc-far-end-not-collected LOW.
	a := mkDev("DEV-A", "10.0.0.1", "mpls lsr-id 10.0.0.1\n",
		[]parse.Interface{l2vcIf("GigabitEthernet0/0/1.10", "mpls l2vc 10.0.0.250 100")}, nil)
	got := l2vcCorrelation([]*parse.Device{a})
	if sevOf(got, "l2vc-far-end-not-collected") != Low {
		t.Fatalf("esperava l2vc-far-end-not-collected LOW: %+v", got)
	}
}

func TestL2vcSingleEndDangling(t *testing.T) {
	// 1 ponta, peer coletado (DEV-B) mas sem este vc-id -> l2vc-single-end MED.
	a := mkDev("DEV-A", "10.0.0.1", "mpls lsr-id 10.0.0.1\n",
		[]parse.Interface{l2vcIf("GigabitEthernet0/0/1.10", "mpls l2vc 10.0.0.2 100")}, nil)
	b := mkDev("DEV-B", "10.0.0.2", "mpls lsr-id 10.0.0.2\n", nil, nil)
	got := l2vcCorrelation([]*parse.Device{a, b})
	if sevOf(got, "l2vc-single-end") != Med {
		t.Fatalf("esperava l2vc-single-end MED: %+v", got)
	}
}

func TestL2vcMtuMismatch(t *testing.T) {
	a := mkDev("DEV-A", "10.0.0.1", "mpls lsr-id 10.0.0.1\n",
		[]parse.Interface{mkIface("GigabitEthernet0/0/1.10", "",
			" mpls l2vc 10.0.0.2 100", " mtu 1500")}, nil)
	b := mkDev("DEV-B", "10.0.0.2", "mpls lsr-id 10.0.0.2\n",
		[]parse.Interface{mkIface("GigabitEthernet0/0/1.10", "",
			" mpls l2vc 10.0.0.1 100", " mtu 9000")}, nil)
	got := l2vcCorrelation([]*parse.Device{a, b})
	if sevOf(got, "l2vc-mtu-mismatch") != High {
		t.Fatalf("esperava l2vc-mtu-mismatch HIGH: %+v", got)
	}
}

func TestL2vcPwTemplateMismatch(t *testing.T) {
	a := mkDev("DEV-A", "10.0.0.1", "mpls lsr-id 10.0.0.1\n",
		[]parse.Interface{l2vcIf("GigabitEthernet0/0/1.10", "mpls l2vc 10.0.0.2 100 pw-template TPL-A")}, nil)
	b := mkDev("DEV-B", "10.0.0.2", "mpls lsr-id 10.0.0.2\n",
		[]parse.Interface{l2vcIf("GigabitEthernet0/0/1.10", "mpls l2vc 10.0.0.1 100 pw-template TPL-B")}, nil)
	got := l2vcCorrelation([]*parse.Device{a, b})
	if sevOf(got, "l2vc-pwtemplate-mismatch") != Med {
		t.Fatalf("esperava l2vc-pwtemplate-mismatch MED: %+v", got)
	}
}

func TestL2vcUnexpectedMultipoint(t *testing.T) {
	mk := func(asset, ip, peer string) *parse.Device {
		return mkDev(asset, ip, "mpls lsr-id "+ip+"\n",
			[]parse.Interface{l2vcIf("GigabitEthernet0/0/1.10", "mpls l2vc "+peer+" 100")}, nil)
	}
	got := l2vcCorrelation([]*parse.Device{
		mk("DEV-A", "10.0.0.1", "10.0.0.2"),
		mk("DEV-B", "10.0.0.2", "10.0.0.1"),
		mk("DEV-C", "10.0.0.3", "10.0.0.1"),
	})
	if sevOf(got, "l2vc-unexpected-multipoint") != Med {
		t.Fatalf("esperava l2vc-unexpected-multipoint MED: %+v", got)
	}
}

func TestParseVSIs(t *testing.T) {
	cfg := "sysname DEV-A\n" +
		"#\n" +
		"vsi VPLS100 auto\n" +
		" pwsignal ldp\n" +
		"  vsi-id 100\n" +
		"  peer 10.0.0.2\n" +
		"  peer 10.0.0.3\n" +
		"#\n" +
		"vsi VPLS200\n" +
		"  vsi-id 200\n" +
		"#\n"
	d := mkDev("DEV-A", "10.0.0.1", cfg, nil, nil)
	vs := parseVSIs(d)
	if len(vs) != 2 {
		t.Fatalf("esperava 2 VSIs, veio %d: %+v", len(vs), vs)
	}
	if vs[0].name != "VPLS100" || vs[0].vsiid != "100" || len(vs[0].peers) != 2 {
		t.Errorf("VSI0 inesperado: %+v", vs[0])
	}
	if vs[1].name != "VPLS200" || vs[1].vsiid != "200" || len(vs[1].peers) != 0 {
		t.Errorf("VSI1 inesperado: %+v", vs[1])
	}
}

func vsiDev(asset, ip, name, id string, peers ...string) *parse.Device {
	cfg := "mpls lsr-id " + ip + "\n#\nvsi " + name + "\n  vsi-id " + id + "\n"
	for _, p := range peers {
		cfg += "  peer " + p + "\n"
	}
	cfg += "#\n"
	return mkDev(asset, ip, cfg, nil, nil)
}

func TestVsiCorrelationReciprocal(t *testing.T) {
	a := vsiDev("DEV-A", "10.0.0.1", "VPLS100", "100", "10.0.0.2")
	b := vsiDev("DEV-B", "10.0.0.2", "VPLS100", "100", "10.0.0.1")
	got := vsiCorrelation([]*parse.Device{a, b})
	if len(got) != 0 {
		t.Fatalf("reciproco nao deveria gerar achados: %+v", got)
	}
}

func TestVsiCorrelationNonReciprocal(t *testing.T) {
	// A aponta para B, mas B nao aponta de volta -> vsi-peer-not-reciprocal MED.
	a := vsiDev("DEV-A", "10.0.0.1", "VPLS100", "100", "10.0.0.2")
	b := vsiDev("DEV-B", "10.0.0.2", "VPLS100", "100") // sem peer
	got := vsiCorrelation([]*parse.Device{a, b})
	if sevOf(got, "vsi-peer-not-reciprocal") != Med {
		t.Fatalf("esperava vsi-peer-not-reciprocal MED: %+v", got)
	}
}

func TestVsiCorrelationUncollectedPeer(t *testing.T) {
	a := vsiDev("DEV-A", "10.0.0.1", "VPLS100", "100", "10.0.0.9")
	got := vsiCorrelation([]*parse.Device{a})
	if sevOf(got, "vsi-peer-uncollected") != Low {
		t.Fatalf("esperava vsi-peer-uncollected LOW: %+v", got)
	}
}

func TestVsiCorrelationSkipsNoID(t *testing.T) {
	// VSI sem vsi-id e ignorada.
	d := mkDev("DEV-A", "10.0.0.1", "mpls lsr-id 10.0.0.1\n#\nvsi NOID\n  peer 10.0.0.2\n#\n", nil, nil)
	if got := vsiCorrelation([]*parse.Device{d}); len(got) != 0 {
		t.Errorf("VSI sem id deveria ser ignorada: %+v", got)
	}
}
