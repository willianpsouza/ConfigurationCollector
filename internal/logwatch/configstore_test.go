package logwatch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fakeConfig = `sysname S6720-POPDAVO-ITQ-10-99-99-13
#
interface XGigabitEthernet0/0/13
 description ROTA_UBERABA-SATURNONET
 eth-trunk 10
#
interface Vlanif274
 description --ITX-S5730-VOCALDTC--
 ip address 168.195.100.1 255.255.255.0
#
interface GigabitEthernet0/0/100
 description CLIENTE-BANCO-XPTO
 vlan-type dot1q 2045
 ip address 192.168.10.1 255.255.255.252
#
interface GigabitEthernet0/0/9
#
`

func setupStore(t *testing.T) *ConfigStore {
	t.Helper()
	dir := t.TempDir()
	sub := filepath.Join(dir, "2026-07-03")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	name := "S6720-POPDAVO-ITQ-10-99-99-13__10.99.99.13__huawei__ssh__084347.txt"
	if err := os.WriteFile(filepath.Join(sub, name), []byte(fakeConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	s := NewConfigStore(dir)
	if err := s.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	return s
}

func TestDeviceAddr(t *testing.T) {
	cases := map[string]string{
		"S6720-POPDAVO-ITQ-10-99-99-13": "10.99.99.13",
		"EDGE-EQX-SP4-SKYNET-10-99-99-109": "10.99.99.109",
		"sem-endereco":                  "",
	}
	for in, want := range cases {
		if got := DeviceAddr(in); got != want {
			t.Errorf("DeviceAddr(%q) = %q, quero %q", in, got, want)
		}
	}
}

func TestInfoExact(t *testing.T) {
	s := setupStore(t)
	if i := s.Info("10.99.99.13", "XGigabitEthernet0/0/13"); i.Desc != "ROTA_UBERABA-SATURNONET" {
		t.Errorf("desc = %q", i.Desc)
	}
	// GE0/0/100: desc + dot1q VLAN 2045 + IP /30.
	i := s.Info("10.99.99.13", "GigabitEthernet0/0/100")
	if i.Desc != "CLIENTE-BANCO-XPTO" || i.VLAN != "2045" || i.IP != "192.168.10.1/30" {
		t.Errorf("info GE0/0/100 = %+v", i)
	}
	// Vlanif274: VLAN vem do nome + IP /24.
	v := s.Info("10.99.99.13", "Vlanif274")
	if v.VLAN != "274" || v.IP != "168.195.100.1/24" {
		t.Errorf("info Vlanif274 = %+v", v)
	}
	// interface sem nada util -> Empty.
	if i := s.Info("10.99.99.13", "GigabitEthernet0/0/9"); !i.Empty() {
		t.Errorf("iface vazia deveria ser Empty, veio %+v", i)
	}
	// device desconhecido -> Empty.
	if i := s.Info("10.99.99.99", "X"); !i.Empty() {
		t.Errorf("device desconhecido = %+v", i)
	}
}

func TestInfoTailFallback(t *testing.T) {
	s := setupStore(t)
	// forma curta (XGE) nao casa exato -> fallback pelo tail 0/0/13 (unico).
	if i := s.Info("10.99.99.13", "XGE0/0/13"); i.Desc != "ROTA_UBERABA-SATURNONET" {
		t.Errorf("fallback tail = %+v", i)
	}
}

func TestIfaceTail(t *testing.T) {
	cases := map[string]string{
		"XGigabitEthernet0/0/13": "0/0/13",
		"100GE0/0/1.2045":        "0/0/1.2045",
		"Eth-Trunk10":            "",
		"Vlanif274":              "",
	}
	for in, want := range cases {
		if got := ifaceTail(in); got != want {
			t.Errorf("ifaceTail(%q) = %q, quero %q", in, got, want)
		}
	}
}

func TestStoreDisabled(t *testing.T) {
	s := NewConfigStore("")
	if s.Enabled() {
		t.Error("dir vazio deveria ser desabilitado")
	}
	if err := s.Reload(); err != nil {
		t.Errorf("Reload desabilitado nao deveria erro: %v", err)
	}
}

func TestFormatWithEnrich(t *testing.T) {
	e, _ := Parse(optLine)
	e.Desc, e.IP, e.VLAN = "ROTA_UBERABA-SATURNONET", "192.168.10.1/30", "2045"
	s := e.Format(1)
	for _, want := range []string{"「ROTA_UBERABA-SATURNONET」", "IP 192.168.10.1/30", "VLAN 2045"} {
		if !strings.Contains(s, want) {
			t.Errorf("Format sem %q:\n%s", want, s)
		}
	}
}

func TestMaskToPrefix(t *testing.T) {
	cases := map[string]string{
		"255.255.255.252": "30",
		"255.255.255.0":   "24",
		"255.255.0.0":     "16",
		"255.255.255.255": "32",
	}
	for mask, want := range cases {
		if got := maskToPrefix(mask); got != want {
			t.Errorf("maskToPrefix(%q) = %q, quero %q", mask, got, want)
		}
	}
}
