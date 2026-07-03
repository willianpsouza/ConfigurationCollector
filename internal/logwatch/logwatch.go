// Package logwatch parseia o syslog central (skynet.log), classifica os eventos
// que importam e faz rate-limit para nao inundar o destino (Telegram).
package logwatch

import (
	"regexp"
	"strconv"
	"strings"
)

// Category e a rota/severidade do evento.
type Category string

const (
	Critical Category = "CRITICO" // optico, peer down, hardware
	Warning  Category = "AVISO"   // link up/down e afins
	Ignore   Category = ""        // ruido (login, cmdrecord, etc.) — descartado
)

// Event e uma linha de syslog ja parseada e classificada.
type Event struct {
	Raw      string
	Time     string
	Device   string
	Addr     string // IP de gerencia do device (10.99.99.N), extraido do nome
	Module   string
	Sev      int
	Mnemonic string
	Iface    string
	Msg      string
	Category Category
	Group    string // "optico" | "hardware" | "bgp" | "ospf" | "link"
	Desc     string // descricao da interface (enriquecido do config coletado)
	IP       string // IP/prefix da interface (enriquecido)
	VLAN     string // VLAN da interface (enriquecido)
}

// Key identifica o evento para dedup: device + interface + mnemonic.
func (e Event) Key() string {
	return e.Device + "|" + e.Iface + "|" + e.Mnemonic
}

var (
	// <device> [%%01]MODULE/SEV/MNEMONIC[(l)][[123]]: <msg>
	reLine  = regexp.MustCompile(`(\S+)\s+(?:%%\d+)?([A-Za-z][\w.-]*)/(\d)/([A-Z][A-Z0-9_]+)(?:\([a-z]\))?(?:\[\d+\])?:\s*(.*)`)
	reTime  = regexp.MustCompile(`^(\S+)`)
	reEnt   = regexp.MustCompile(`EntPhysicalName="?([^"\s)]+)"?`)
	reIfName = regexp.MustCompile(`(?:IfName|Interface)[=\s]+"?([A-Za-z][\w./-]+)"?`)
	reRxPow = regexp.MustCompile(`current Rx power is (-?[\d.]+)dBM`)
)

// Parse transforma uma linha de log num Event classificado. ok=false se a linha
// nao casa o formato ou o evento e Ignore.
func Parse(line string) (Event, bool) {
	m := reLine.FindStringSubmatch(line)
	if m == nil {
		return Event{}, false
	}
	sev, _ := strconv.Atoi(m[3])
	e := Event{
		Raw:      line,
		Device:   m[1],
		Module:   m[2],
		Sev:      sev,
		Mnemonic: m[4],
		Msg:      strings.TrimSpace(m[5]),
	}
	if t := reTime.FindStringSubmatch(line); t != nil {
		e.Time = t[1]
	}
	e.Addr = DeviceAddr(e.Device)
	e.Iface = extractIface(e.Msg)
	e.Category, e.Group = classify(e)
	if e.Category == Ignore {
		return e, false
	}
	return e, true
}

func extractIface(msg string) string {
	if m := reEnt.FindStringSubmatch(msg); m != nil {
		return m[1]
	}
	if m := reIfName.FindStringSubmatch(msg); m != nil {
		return m[1]
	}
	return ""
}

// classify decide categoria e grupo do evento.
func classify(e Event) (Category, string) {
	mn := e.Mnemonic
	up := strings.ToUpper(e.Msg)

	switch {
	// Optico: potencia de modulo anormal.
	case strings.Contains(mn, "OPTPWR") || strings.Contains(mn, "OPTICAL"):
		return Critical, "optico"

	// Hardware: fonte, fan, temperatura, entity fault.
	case matchesAny(mn, "POWER", "FAN", "TEMP", "ENTITYTRAP", "PWR", "VOLTAGE", "FAULT"):
		return Critical, "hardware"

	// BGP: sessao mudou de estado — so alerta se NAO for Established (=caiu).
	case mn == "PEER_STATE_CHG" || strings.Contains(mn, "BGP_PEER"):
		if strings.Contains(up, "ESTABLISHED") {
			return Ignore, ""
		}
		return Critical, "bgp"

	// OSPF: vizinho caindo.
	case strings.Contains(mn, "NBR") || strings.Contains(mn, "NEIGHBOR"):
		if strings.Contains(up, "FULL") && !strings.Contains(up, "->") {
			return Ignore, ""
		}
		return Critical, "ospf"

	// Link up/down.
	case matchesAny(mn, "LINK", "IF_STATE", "IFNET", "PHYSICAL_DOWN", "PORT"):
		return Warning, "link"
	}
	return Ignore, ""
}

func matchesAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// RxPower devolve a potencia Rx (dBm) do evento optico, se presente.
func (e Event) RxPower() (string, bool) {
	if m := reRxPow.FindStringSubmatch(e.Msg); m != nil {
		return m[1], true
	}
	return "", false
}

// Format monta a mensagem para o Telegram (com contagem de repeticoes na janela).
func (e Event) Format(count int) string {
	emoji := "🔴"
	if e.Category == Warning {
		emoji = "🟡"
	}
	var b strings.Builder
	b.WriteString(emoji + " " + short(e.Device))
	if e.Addr != "" {
		b.WriteString(" (" + e.Addr + ")")
	}
	if e.Iface != "" {
		b.WriteString(" " + e.Iface)
	}
	if e.Desc != "" {
		b.WriteString(" 「" + e.Desc + "」")
	}
	b.WriteString(" — " + e.Group + "/" + e.Mnemonic)
	if rx, ok := e.RxPower(); ok {
		b.WriteString(" (Rx " + rx + " dBm)")
	}
	if count > 1 {
		b.WriteString("  [" + strconv.Itoa(count) + "x em 5min]")
	}
	var meta []string
	if e.IP != "" {
		meta = append(meta, "IP "+e.IP)
	}
	if e.VLAN != "" {
		meta = append(meta, "VLAN "+e.VLAN)
	}
	if len(meta) > 0 {
		b.WriteString("\n" + strings.Join(meta, " · "))
	}
	if e.Msg != "" {
		msg := e.Msg
		if len(msg) > 180 {
			msg = msg[:180] + "..."
		}
		b.WriteString("\n" + msg)
	}
	return b.String()
}

// short encurta o nome do device (tira o sufixo -10-99-99-N).
func short(name string) string {
	if i := strings.Index(name, "-10-99-99-"); i > 0 {
		return name[:i]
	}
	return name
}
