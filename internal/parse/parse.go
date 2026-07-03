// Package parse le os arquivos brutos produzidos pelo coletor e os transforma em
// estruturas navegaveis: cabecalho, blocos por comando e, para Huawei, a config
// quebrada em stanzas e interfaces.
//
// O formato de entrada e o que o coletor grava:
//
//	### ASSET=<nome> IP=<ip> VENDOR=<v> PROTOCOL=<p> TIME=<rfc3339> ###
//
//	==== CMD: <comando> ====
//	<saida do comando>
//	==== CMD: <comando> ====
//	...
package parse

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

// Device e um arquivo coletado ja parseado.
type Device struct {
	Asset    string
	IP       string
	Vendor   string
	Protocol string
	Time     string
	File     string
	// Commands mapeia comando -> saida limpa.
	Commands map[string]string
	// Order preserva a ordem original dos comandos.
	Order []string
	// Config e a saida de display/show current/running-configuration (limpa),
	// se presente.
	Config string
	// Interfaces sao as stanzas de interface extraidas da Config (Huawei).
	Interfaces []Interface
}

// Interface e uma stanza "interface X ... #" da config.
type Interface struct {
	Name        string
	Description string
	Lines       []string // linhas da stanza (sem a linha "interface X")
}

var (
	reHeader = regexp.MustCompile(`^###\s+ASSET=(\S+)\s+IP=(\S+)\s+VENDOR=(\S+)\s+PROTOCOL=(\S+)\s+TIME=(\S+)\s+###`)
	reCmd    = regexp.MustCompile(`^==== CMD: (.*?) ====\s*$`)
	reAnsi   = regexp.MustCompile(`\x1b\[[0-9;?]*[a-zA-Z]`)
	// prompts Huawei/ZTE/OLT: <HOST>, [HOST], HOST>, HOST# no fim de linha
	rePrompt = regexp.MustCompile(`^[\s]*[<\[]?[\w.\-]+[>\]#]\s*$`)
	reMore   = regexp.MustCompile(`(?i)-+\s*more\s*-+`)
)

// File le e parseia um arquivo coletado.
func File(path string) (*Device, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	d := parseBytes(b)
	d.File = path
	return d, nil
}

func parseBytes(b []byte) *Device {
	d := &Device{Commands: map[string]string{}}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)

	var curCmd string
	var cur []string
	flush := func() {
		if curCmd == "" {
			return
		}
		out := cleanBlock(curCmd, cur)
		d.Commands[curCmd] = out
		d.Order = append(d.Order, curCmd)
		cur = nil
	}

	for sc.Scan() {
		line := sc.Text()
		if d.Asset == "" {
			if m := reHeader.FindStringSubmatch(line); m != nil {
				d.Asset, d.IP, d.Vendor, d.Protocol, d.Time = m[1], m[2], m[3], m[4], m[5]
				continue
			}
		}
		if m := reCmd.FindStringSubmatch(line); m != nil {
			flush()
			curCmd = m[1]
			continue
		}
		cur = append(cur, line)
	}
	flush()

	// Config canonica (Huawei/ZTE/Cisco).
	for _, key := range []string{"display current-configuration", "show running-config", "show running-configuration"} {
		if v, ok := d.Commands[key]; ok {
			d.Config = v
			break
		}
	}
	if d.Config != "" {
		d.Interfaces = parseInterfaces(d.Config)
	}
	return d
}

// cleanBlock remove o eco do comando, prompts, paginacao e ANSI.
func cleanBlock(cmd string, lines []string) string {
	out := make([]string, 0, len(lines))
	for i, ln := range lines {
		ln = strings.ReplaceAll(ln, "\r", "")
		ln = reAnsi.ReplaceAllString(ln, "")
		ln = strings.ReplaceAll(ln, "\x08", "") // backspace
		// primeira linha costuma ecoar o proprio comando
		if i == 0 && strings.TrimSpace(ln) == strings.TrimSpace(cmd) {
			continue
		}
		if reMore.MatchString(ln) {
			continue
		}
		if rePrompt.MatchString(ln) {
			continue
		}
		out = append(out, ln)
	}
	// colapsa linhas em branco repetidas nas bordas
	return strings.Trim(strings.Join(out, "\n"), "\n ") + "\n"
}

// parseInterfaces quebra a config em stanzas separadas por "#" e extrai as que
// comecam com "interface ".
func parseInterfaces(cfg string) []Interface {
	var ifaces []Interface
	var cur *Interface

	for _, raw := range strings.Split(cfg, "\n") {
		line := strings.TrimRight(raw, " ")
		trimmed := strings.TrimSpace(line)

		if trimmed == "#" || trimmed == "!" {
			if cur != nil {
				ifaces = append(ifaces, *cur)
				cur = nil
			}
			continue
		}
		if strings.HasPrefix(trimmed, "interface ") {
			if cur != nil {
				ifaces = append(ifaces, *cur)
			}
			cur = &Interface{Name: strings.TrimSpace(strings.TrimPrefix(trimmed, "interface "))}
			continue
		}
		if cur != nil {
			cur.Lines = append(cur.Lines, line)
			if strings.HasPrefix(trimmed, "description ") {
				cur.Description = strings.TrimSpace(strings.TrimPrefix(trimmed, "description "))
			}
		}
	}
	if cur != nil {
		ifaces = append(ifaces, *cur)
	}
	return ifaces
}

// Has informa se a stanza da interface contem alguma linha que casa com o regex.
func (i Interface) Has(re *regexp.Regexp) bool {
	for _, ln := range i.Lines {
		if re.MatchString(ln) {
			return true
		}
	}
	return false
}

// IsSubinterface indica se e uma subinterface (contem ponto no nome).
func (i Interface) IsSubinterface() bool {
	return strings.Contains(i.Name, ".")
}
