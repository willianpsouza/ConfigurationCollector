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
#
interface GigabitEthernet0/0/100
 description CLIENTE-BANCO-XPTO
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

func TestDescribeExact(t *testing.T) {
	s := setupStore(t)
	if d := s.Describe("10.99.99.13", "XGigabitEthernet0/0/13"); d != "ROTA_UBERABA-SATURNONET" {
		t.Errorf("desc = %q", d)
	}
	if d := s.Describe("10.99.99.13", "GigabitEthernet0/0/100"); d != "CLIENTE-BANCO-XPTO" {
		t.Errorf("desc = %q", d)
	}
	// interface sem description -> vazio.
	if d := s.Describe("10.99.99.13", "GigabitEthernet0/0/9"); d != "" {
		t.Errorf("iface sem desc deveria ser vazio, veio %q", d)
	}
	// device/iface desconhecidos -> vazio.
	if d := s.Describe("10.99.99.99", "X"); d != "" {
		t.Errorf("device desconhecido = %q", d)
	}
}

func TestDescribeTailFallback(t *testing.T) {
	s := setupStore(t)
	// forma curta (XGE) nao casa exato -> fallback pelo tail 0/0/13 (unico).
	if d := s.Describe("10.99.99.13", "XGE0/0/13"); d != "ROTA_UBERABA-SATURNONET" {
		t.Errorf("fallback tail = %q", d)
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

func TestFormatWithDesc(t *testing.T) {
	e, _ := Parse(optLine)
	e.Desc = "ROTA_UBERABA-SATURNONET"
	if s := e.Format(1); !strings.Contains(s, "「ROTA_UBERABA-SATURNONET」") {
		t.Errorf("Format sem descricao: %s", s)
	}
}
