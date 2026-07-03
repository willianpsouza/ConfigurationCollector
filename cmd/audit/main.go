// Command audit le as configuracoes coletadas, roda checagens deterministicas
// (rule engine) e, opcionalmente, uma camada de LLM local (Ollama) para
// documentar e apontar divergencias.
//
// Uso:
//
//	audit [-input <dir|arquivo>] [-out report.md] [-json findings.json]
//	      [-llm] [-model qwen2.5:14b] [-ollama http://localhost:11434]
package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/willianpsouza/ConfigurationCollector/internal/audit"
	"github.com/willianpsouza/ConfigurationCollector/internal/llm"
	"github.com/willianpsouza/ConfigurationCollector/internal/parse"
)

func main() {
	input := flag.String("input", "coletas", "diretorio (recursivo) ou arquivo .txt coletado")
	outMD := flag.String("out", "audit-report.md", "arquivo markdown de saida")
	outJSON := flag.String("json", "audit-findings.json", "arquivo json de saida")
	useLLM := flag.Bool("llm", false, "rodar camada LLM (Ollama) para documentar/divergencias")
	model := flag.String("model", "qwen2.5:14b", "modelo Ollama")
	ollamaURL := flag.String("ollama", "http://localhost:11434", "URL do Ollama")
	llmMaxCfg := flag.Int("llm-max-config", 40000, "max de chars da config enviados ao LLM")
	ipCSV := flag.String("ipcsv", "ip-inventory.csv", "CSV com o inventario de IP por device")
	portCSV := flag.String("portcsv", "port-map.csv", "CSV com o mapa de portas fisicas por device")
	focus := flag.Bool("focus", false, "modo foco: corta ruido (escopo/cosmetico/informativo), so sinal acionavel")
	flag.Parse()

	files, err := collectFiles(*input)
	if err != nil {
		fmt.Fprintln(os.Stderr, "erro:", err)
		os.Exit(1)
	}
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "nenhum arquivo .txt encontrado em", *input)
		os.Exit(1)
	}

	// Parse + regras.
	type devReport struct {
		Dev      *parse.Device
		Findings []audit.Finding
		LLMDoc   string
	}
	var reports []devReport
	var allFindings []audit.Finding

	var devs []*parse.Device
	for _, f := range files {
		d, err := parse.File(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", f, err)
			continue
		}
		fs := audit.Run(d)
		reports = append(reports, devReport{Dev: d, Findings: fs})
		allFindings = append(allFindings, fs...)
		devs = append(devs, d)
	}

	// Correlacao cross-device (circuitos VLAN ponta-A/ponta-B).
	fleetFindings := audit.RunFleet(devs)
	allFindings = append(allFindings, fleetFindings...)

	// Membership da malha MPLS (o que falta coletar).
	mesh := audit.MeshSummary(devs)

	// Inventario de IP por device (base para correlacao + duplicados).
	inv := audit.IPInventory(devs)
	if err := writeIPCSV(*ipCSV, inv); err != nil {
		fmt.Fprintln(os.Stderr, "aviso: erro escrevendo ip csv:", err)
	}

	// Mapa de portas fisicas (estado + higiene).
	portInv := audit.PortInventory(devs)
	if err := writePortCSV(*portCSV, portInv); err != nil {
		fmt.Fprintln(os.Stderr, "aviso: erro escrevendo port csv:", err)
	}

	// Camada LLM (opcional).
	if *useLLM {
		cli := llm.New(*ollamaURL, *model)
		ctx := context.Background()
		if models, err := cli.Models(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "aviso: Ollama indisponivel (%v) — pulando LLM\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "Ollama OK (%d modelos). Documentando %d devices com %s...\n", len(models), len(reports), *model)
			for i := range reports {
				doc, err := runLLM(ctx, cli, reports[i].Dev, reports[i].Findings, *llmMaxCfg)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  LLM %s: %v\n", reports[i].Dev.Asset, err)
					continue
				}
				reports[i].LLMDoc = doc
				fmt.Fprintf(os.Stderr, "  [%d/%d] %s ok\n", i+1, len(reports), reports[i].Dev.Asset)
			}
		}
	}

	// Modo foco: corta ruido antes de renderizar.
	if *focus {
		for i := range reports {
			reports[i].Findings = dropNoise(reports[i].Findings)
		}
		fleetFindings = dropNoise(fleetFindings)
		allFindings = dropNoise(allFindings)
	}

	// JSON.
	if b, err := json.MarshalIndent(allFindings, "", "  "); err == nil {
		_ = os.WriteFile(*outJSON, b, 0o644)
	}

	// Markdown.
	var md strings.Builder
	writeHeader(&md, allFindings)
	writeMesh(&md, mesh)
	writeFleet(&md, fleetFindings)
	for _, r := range reports {
		writeDevice(&md, r.Dev, r.Findings, r.LLMDoc)
	}
	if err := os.WriteFile(*outMD, []byte(md.String()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "erro escrevendo md:", err)
	}

	// Resumo no console.
	high, med, low := countSev(allFindings)
	fmt.Printf("devices=%d achados=%d (HIGH=%d MEDIUM=%d LOW=%d)\n", len(reports), len(allFindings), high, med, low)
	fmt.Printf("malha MPLS: %d nos coletados, %d peers referenciados, %d FALTANDO coletar\n",
		len(mesh.Collected), len(mesh.Peers), len(mesh.Missing))
	if len(mesh.Missing) > 0 {
		fmt.Printf("  faltando: %s\n", strings.Join(mesh.Missing, " "))
	}
	dupCross, dupSame := 0, 0
	for _, f := range allFindings {
		switch f.Rule {
		case "ip-duplicate-cross-device":
			dupCross++
		case "ip-duplicate-same-device":
			dupSame++
		}
	}
	fmt.Printf("inventario IP: %d enderecos, duplicados cross-device=%d same-device=%d (csv: %s)\n",
		len(inv), dupCross, dupSame, *ipCSV)
	dark, upNoCfg := 0, 0
	for _, p := range portInv {
		switch p.Verdict {
		case "unconfigured-dark":
			dark++
		case "unconfigured-up":
			upNoCfg++
		}
	}
	fmt.Printf("portas: %d fisicas, %d ativas-sem-config-oper-down (lixo), %d up-sem-config (csv: %s)\n",
		len(portInv), dark, upNoCfg, *portCSV)
	fmt.Printf("relatorio: %s | findings: %s\n", *outMD, *outJSON)
}

// noiseRules sao achados informativos/escopo/cosmeticos — cortados no -focus
// para sobrar so o sinal acionavel.
var noiseRules = map[string]bool{
	"l2vc-far-end-not-collected": true, // escopo (par fora da coleta)
	"vsi-peer-uncollected":       true, // escopo
	"vlan-single-end":            true, // escopo/cliente
	"ip-duplicate-oob-mgmt":      true, // OOB, esperado
	"port-up-unconfigured":       true, // link-up sem desc, informativo
	"port-active-unconfigured":   true, // individual; fica o port-hygiene-summary
	"timezone-nonstandard":       true, // cosmetico
}

func dropNoise(fs []audit.Finding) []audit.Finding {
	out := fs[:0:0]
	for _, f := range fs {
		if !noiseRules[f.Rule] {
			out = append(out, f)
		}
	}
	return out
}

func collectFiles(input string) ([]string, error) {
	info, err := os.Stat(input)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{input}, nil
	}
	var files []string
	err = filepath.WalkDir(input, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".txt") {
			files = append(files, p)
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}

func countSev(fs []audit.Finding) (h, m, l int) {
	for _, f := range fs {
		switch f.Severity {
		case audit.High:
			h++
		case audit.Med:
			m++
		default:
			l++
		}
	}
	return
}

func writeHeader(md *strings.Builder, all []audit.Finding) {
	h, m, l := countSev(all)
	fmt.Fprintf(md, "# Auditoria de Configuracoes\n\n")
	fmt.Fprintf(md, "Gerado em %s\n\n", time.Now().Format("2006-01-02 15:04"))
	fmt.Fprintf(md, "**Achados:** %d total — 🔴 HIGH %d · 🟡 MEDIUM %d · ⚪ LOW %d\n\n", len(all), h, m, l)
	fmt.Fprintf(md, "---\n\n")
}

func writeIPCSV(path string, inv []audit.IPEntry) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	_ = w.Write([]string{"device", "ip", "mask", "network", "iface", "secondary"})
	for _, e := range inv {
		_ = w.Write([]string{e.Device, e.IP, e.Mask, e.Network, e.Iface, strconv.FormatBool(e.Secondary)})
	}
	return w.Error()
}

func writePortCSV(path string, ports []audit.PortEntry) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	_ = w.Write([]string{"device", "iface", "admin", "oper", "has_desc", "has_config", "verdict"})
	for _, p := range ports {
		_ = w.Write([]string{p.Device, p.Iface, p.Admin, p.Oper,
			strconv.FormatBool(p.HasDesc), strconv.FormatBool(p.HasConfig), p.Verdict})
	}
	return w.Error()
}

func writeMesh(md *strings.Builder, m audit.Mesh) {
	fmt.Fprintf(md, "## Malha MPLS — membership\n\n")
	fmt.Fprintf(md, "- Nos coletados (lsr-id): **%d**\n- Peers referenciados: **%d**\n- **Faltando coletar: %d**\n\n",
		len(m.Collected), len(m.Peers), len(m.Missing))
	if len(m.Missing) > 0 {
		fmt.Fprintf(md, "### Nos da malha ainda NAO coletados\n\n")
		fmt.Fprintf(md, "| Peer (lsr-id) | Referenciado por |\n|-----|-----|\n")
		for _, addr := range m.Missing {
			fmt.Fprintf(md, "| `%s` | %s |\n", addr, strings.Join(m.Peers[addr], ", "))
		}
		fmt.Fprintf(md, "\n")
	}
	fmt.Fprintf(md, "---\n\n")
}

func writeFleet(md *strings.Builder, fs []audit.Finding) {
	if len(fs) == 0 {
		return
	}
	fmt.Fprintf(md, "## Correlacao de circuitos (VLAN ponta-A/ponta-B)\n\n")
	fmt.Fprintf(md, "| Sev | Regra | Objeto | Detalhe |\n|-----|-------|--------|--------|\n")
	for _, f := range fs {
		fmt.Fprintf(md, "| %s | %s | `%s` | %s |\n", sevEmoji(f.Severity), f.Rule, f.Object, f.Detail)
	}
	fmt.Fprintf(md, "\n---\n\n")
}

func writeDevice(md *strings.Builder, d *parse.Device, fs []audit.Finding, llmDoc string) {
	fmt.Fprintf(md, "## %s — `%s` (%s)\n\n", d.Asset, d.IP, d.Vendor)
	if len(fs) == 0 {
		fmt.Fprintf(md, "_Sem achados deterministicos._\n\n")
	} else {
		fmt.Fprintf(md, "| Sev | Regra | Objeto | Detalhe |\n|-----|-------|--------|--------|\n")
		for _, f := range fs {
			fmt.Fprintf(md, "| %s | %s | `%s` | %s |\n",
				sevEmoji(f.Severity), f.Rule, f.Object, f.Detail)
		}
		fmt.Fprintf(md, "\n")
	}
	if llmDoc != "" {
		fmt.Fprintf(md, "### Analise LLM\n\n%s\n\n", llmDoc)
	}
	fmt.Fprintf(md, "---\n\n")
}

func sevEmoji(s audit.Severity) string {
	switch s {
	case audit.High:
		return "🔴 HIGH"
	case audit.Med:
		return "🟡 MEDIUM"
	default:
		return "⚪ LOW"
	}
}

const llmSystem = `Voce e um engenheiro de redes senior especialista em Huawei VRP (NE40/NE8000/S-series), BGP, MPLS e QoS.
Analise a configuracao fornecida e responda em PORTUGUES do Brasil, tecnico e objetivo, em Markdown.
Nao invente comandos que nao estejam na config. Se nao tiver certeza, diga.

REGRA IMPORTANTE: NAO comente, sugira ou mencione NADA relativo a controle de acesso:
nada de senhas, AAA, TACACS+, RADIUS, usuarios locais, SNMP community/ACL de acesso,
SSH/telnet, banners de login ou hardening de acesso. Ignore esses assuntos por completo.
Foque so em servico/operacao: NTP, logging (info-center), MTU, QoS/CAR, estatistica de
trafego, MPLS/LDP/TE, VLAN/L2VC, roteamento e descricoes de interface.`

func runLLM(ctx context.Context, cli *llm.Client, d *parse.Device, fs []audit.Finding, maxCfg int) (string, error) {
	cfg := d.Config
	if cfg == "" {
		cfg = d.Commands["display current-configuration"]
	}
	if len(cfg) > maxCfg {
		cfg = cfg[:maxCfg] + "\n...[config truncada]..."
	}
	var findingsTxt strings.Builder
	for _, f := range fs {
		fmt.Fprintf(&findingsTxt, "- [%s] %s: %s\n", f.Severity, f.Object, f.Detail)
	}
	if findingsTxt.Len() == 0 {
		findingsTxt.WriteString("(nenhum achado deterministico)\n")
	}

	prompt := fmt.Sprintf(`Equipamento: %s (%s), vendor %s.

Achados deterministicos ja detectados pelo rule engine:
%s

Configuracao:
%s

Tarefas:
1. **Resumo** do papel do equipamento (1-2 paragrafos): funcao, uplinks, roteamento (BGP/OSPF/ISIS/MPLS).
2. **Divergencias e riscos** de padronizacao NAO cobertos pelos achados acima, APENAS de servico/operacao (ex.: NTP/logging/MTU inconsistentes, QoS/CAR ausente, estatistica de trafego faltando, MPLS/LDP/TE, interfaces sem descricao). NAO cite acesso/senha/AAA/SNMP-community.
3. **Padronizacao**: 3 a 5 recomendacoes concretas para deixar a config alinhada a um padrao de casa.

Seja conciso. Nao repita a lista de achados verbatim.`, d.Asset, d.IP, d.Vendor, findingsTxt.String(), cfg)

	return cli.Generate(ctx, llmSystem, prompt)
}
