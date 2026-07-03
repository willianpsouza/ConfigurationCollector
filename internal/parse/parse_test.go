package parse

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// sampleHuawei monta um arquivo coletado no formato do coletor, com eco de
// comando, paginacao "More", prompt, ANSI e uma config com stanzas de interface.
func sampleHuawei() string {
	lines := []string{
		"### ASSET=RT01 IP=10.0.0.1 VENDOR=huawei PROTOCOL=ssh TIME=2026-07-02T10:00:00Z ###",
		"==== CMD: display version ====",
		"display version", // eco do comando (i==0) -> removido
		"Huawei VRP Software Version 8.180",
		"\x1b[32mStatus\x1b[0m: UP\r\x08", // ANSI + CR + backspace -> "Status: UP"
		"---- More ----",                 // paginacao -> removido
		"Uptime is 100 days",
		"<RT01>", // prompt -> removido
		"==== CMD: display current-configuration ====",
		"display current-configuration", // eco -> removido
		"#",
		"interface GigabitEthernet0/0/1",
		" description UPLINK-CORE",
		" ip address 10.0.0.1 255.255.255.0",
		"#",
		"interface GigabitEthernet0/0/1.100",
		" description SUBIF",
		"#",
	}
	return strings.Join(lines, "\n") + "\n"
}

func TestParseBytesHeaderECommands(t *testing.T) {
	d := parseBytes([]byte(sampleHuawei()))

	if d.Asset != "RT01" || d.IP != "10.0.0.1" || d.Vendor != "huawei" ||
		d.Protocol != "ssh" || d.Time != "2026-07-02T10:00:00Z" {
		t.Fatalf("cabecalho parseado incorreto: %+v", d)
	}

	if len(d.Order) != 2 ||
		d.Order[0] != "display version" ||
		d.Order[1] != "display current-configuration" {
		t.Fatalf("Order incorreto: %v", d.Order)
	}
	if _, ok := d.Commands["display version"]; !ok {
		t.Fatal("faltou comando display version")
	}
}

func TestCleanBlockRemoveEcoMorePromptAnsi(t *testing.T) {
	d := parseBytes([]byte(sampleHuawei()))
	out := d.Commands["display version"]

	if !strings.Contains(out, "Huawei VRP Software Version 8.180") {
		t.Errorf("saida deveria conter a versao: %q", out)
	}
	if !strings.Contains(out, "Status: UP") {
		t.Errorf("ANSI/CR/backspace nao limpos corretamente: %q", out)
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("codigos ANSI nao removidos: %q", out)
	}
	if strings.Contains(out, "More") {
		t.Errorf("linha de paginacao nao removida: %q", out)
	}
	if strings.Contains(out, "<RT01>") {
		t.Errorf("prompt nao removido: %q", out)
	}
	if strings.Contains(out, "display version") {
		t.Errorf("eco do comando nao removido: %q", out)
	}
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("saida deveria terminar com newline: %q", out)
	}
}

func TestParseInterfaces(t *testing.T) {
	d := parseBytes([]byte(sampleHuawei()))

	if d.Config == "" {
		t.Fatal("Config deveria estar preenchida a partir de display current-configuration")
	}
	if len(d.Interfaces) != 2 {
		t.Fatalf("esperava 2 interfaces, veio %d (%+v)", len(d.Interfaces), d.Interfaces)
	}

	i0 := d.Interfaces[0]
	if i0.Name != "GigabitEthernet0/0/1" {
		t.Errorf("i0.Name = %q", i0.Name)
	}
	if i0.Description != "UPLINK-CORE" {
		t.Errorf("i0.Description = %q", i0.Description)
	}
	if len(i0.Lines) != 2 {
		t.Errorf("i0.Lines = %v, quer 2 linhas", i0.Lines)
	}
	if i0.IsSubinterface() {
		t.Error("i0 nao deveria ser subinterface")
	}
	if !i0.Has(regexp.MustCompile(`ip address`)) {
		t.Error("i0.Has(ip address) deveria ser true")
	}
	if i0.Has(regexp.MustCompile(`shutdown`)) {
		t.Error("i0.Has(shutdown) deveria ser false")
	}

	i1 := d.Interfaces[1]
	if i1.Name != "GigabitEthernet0/0/1.100" {
		t.Errorf("i1.Name = %q", i1.Name)
	}
	if !i1.IsSubinterface() {
		t.Error("i1 deveria ser subinterface (contem ponto)")
	}
	if i1.Description != "SUBIF" {
		t.Errorf("i1.Description = %q", i1.Description)
	}
}

// Config terminando numa interface sem "!" final: cobre o append final de
// parseInterfaces e o separador "!" (estilo Cisco), alem da chave
// show running-config.
func TestParseInterfacesTrailingAndBang(t *testing.T) {
	lines := []string{
		"### ASSET=SW1 IP=10.0.0.9 VENDOR=cisco PROTOCOL=ssh TIME=2026-07-02T11:00:00Z ###",
		"==== CMD: show running-config ====",
		"show running-config",
		"!",
		"interface Gi0/1",
		" description LAST",
	}
	d := parseBytes([]byte(strings.Join(lines, "\n") + "\n"))

	if d.Config == "" {
		t.Fatal("Config deveria vir de show running-config")
	}
	if len(d.Interfaces) != 1 {
		t.Fatalf("esperava 1 interface, veio %d", len(d.Interfaces))
	}
	if d.Interfaces[0].Name != "Gi0/1" || d.Interfaces[0].Description != "LAST" {
		t.Errorf("interface final incorreta: %+v", d.Interfaces[0])
	}
}

// Dispositivo sem comando de config: Interfaces deve ficar vazio (branch
// d.Config == "").
func TestParseNoConfig(t *testing.T) {
	lines := []string{
		"### ASSET=MK1 IP=1.1.1.1 VENDOR=mikrotik PROTOCOL=ssh TIME=2026-07-02T12:00:00Z ###",
		"==== CMD: /system identity print ====",
		"/system identity print",
		"name: MK1",
	}
	d := parseBytes([]byte(strings.Join(lines, "\n") + "\n"))

	if d.Config != "" {
		t.Errorf("Config deveria estar vazio, veio %q", d.Config)
	}
	if len(d.Interfaces) != 0 {
		t.Errorf("Interfaces deveria estar vazio, veio %d", len(d.Interfaces))
	}
	if got := d.Commands["/system identity print"]; !strings.Contains(got, "name: MK1") {
		t.Errorf("saida do comando incorreta: %q", got)
	}
}

func TestFileOK(t *testing.T) {
	p := filepath.Join(t.TempDir(), "coleta.txt")
	if err := os.WriteFile(p, []byte(sampleHuawei()), 0o644); err != nil {
		t.Fatalf("escrevendo arquivo: %v", err)
	}
	d, err := File(p)
	if err != nil {
		t.Fatalf("File erro: %v", err)
	}
	if d.File != p {
		t.Errorf("d.File = %q, quer %q", d.File, p)
	}
	if d.Asset != "RT01" || d.Vendor != "huawei" {
		t.Errorf("cabecalho apos File incorreto: %+v", d)
	}
	if len(d.Interfaces) != 2 {
		t.Errorf("interfaces apos File = %d", len(d.Interfaces))
	}
}

func TestFileMissing(t *testing.T) {
	if _, err := File(filepath.Join(t.TempDir(), "nao", "existe.txt")); err == nil {
		t.Fatal("File de caminho inexistente deveria falhar")
	}
}
