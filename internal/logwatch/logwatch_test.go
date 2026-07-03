package logwatch

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/willianpsouza/ConfigurationCollector/internal/telegram"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

const optLine = `2026-07-03T11:52:00.489-03:00 Jul  3 2026 11:52:00-03:00 S6720-POPDAVO-ITQ-10-99-99-13 SRM/3/OPTPWRABNORMAL:OID 1.3.6.1.4.1.2011.5.25.129.2.17.1 Optical module power is abnormal. (EntPhysicalName="XGigabitEthernet0/0/13", ReasonDescription="Rx power is too low. The current Rx power is -18.83dBM; Set lower threshold is -18.01dBM")`

func TestParseOptical(t *testing.T) {
	e, ok := Parse(optLine)
	if !ok {
		t.Fatal("linha optica deveria parsear")
	}
	if e.Device != "S6720-POPDAVO-ITQ-10-99-99-13" {
		t.Errorf("device = %q", e.Device)
	}
	if e.Mnemonic != "OPTPWRABNORMAL" || e.Sev != 3 {
		t.Errorf("mnemonic/sev = %q/%d", e.Mnemonic, e.Sev)
	}
	if e.Iface != "XGigabitEthernet0/0/13" {
		t.Errorf("iface = %q", e.Iface)
	}
	if e.Category != Critical || e.Group != "optico" {
		t.Errorf("categoria/grupo = %s/%s", e.Category, e.Group)
	}
	if rx, ok := e.RxPower(); !ok || rx != "-18.83" {
		t.Errorf("rx = %q ok=%v", rx, ok)
	}
}

func TestParseClassify(t *testing.T) {
	tests := []struct {
		name string
		line string
		ok   bool
		cat  Category
		grp  string
	}{
		{"cmdrecord ruido", `... S6730-X-10-99-99-3 %%01SHELL/5/CMDRECORD(s)[2]: Recorded command`, false, Ignore, ""},
		{"bgp established ignora", `... CORE-10-99-99-1 %%01BGP/6/PEER_STATE_CHG:OID x The state changed to Established`, false, Ignore, ""},
		{"bgp down critico", `... CORE-10-99-99-1 %%01BGP/6/PEER_STATE_CHG:OID x The state changed to Idle`, true, Critical, "bgp"},
		{"hardware power", `... SW-10-99-99-9 %%01SRM/2/POWERFAIL:OID x Power failed`, true, Critical, "hardware"},
		{"link", `... SW-10-99-99-9 %%01IFNET/4/LINK_STATE:OID x Interface GE0/0/1 link down`, true, Warning, "link"},
		{"nao casa formato", `linha aleatoria sem modulo`, false, Ignore, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, ok := Parse(tt.line)
			if ok != tt.ok {
				t.Fatalf("ok = %v, quero %v (ev=%+v)", ok, tt.ok, e)
			}
			if ok && (e.Category != tt.cat || e.Group != tt.grp) {
				t.Errorf("cat/grp = %s/%s, quero %s/%s", e.Category, e.Group, tt.cat, tt.grp)
			}
		})
	}
}

func TestFormat(t *testing.T) {
	e, _ := Parse(optLine)
	s := e.Format(54)
	for _, want := range []string{"🔴", "S6720-POPDAVO-ITQ", "XGigabitEthernet0/0/13", "optico", "Rx -18.83", "54x"} {
		if !strings.Contains(s, want) {
			t.Errorf("Format sem %q:\n%s", want, s)
		}
	}
}

func TestKey(t *testing.T) {
	e, _ := Parse(optLine)
	if e.Key() != "S6720-POPDAVO-ITQ-10-99-99-13|XGigabitEthernet0/0/13|OPTPWRABNORMAL" {
		t.Errorf("Key = %q", e.Key())
	}
}

func newTestWatcher() *Watcher {
	cfg := Config{Provider: "skynet", DedupWindow: 5 * time.Minute, CriticalChat: "c", WarningChat: "w"}
	return New(cfg, telegram.New("x"), discardLogger())
}

func TestRateLimit(t *testing.T) {
	w := newTestWatcher()
	e, _ := Parse(optLine)

	// 1o evento: envia, count 1.
	if c, send := w.rateLimit(e); !send || c != 1 {
		t.Fatalf("1o: send=%v count=%d", send, c)
	}
	// dentro da janela: suprime, acumula.
	for i := 0; i < 3; i++ {
		if _, send := w.rateLimit(e); send {
			t.Fatalf("dentro da janela nao deveria enviar (i=%d)", i)
		}
	}
	// forca a janela a expirar mexendo no estado interno.
	st := w.last[e.Key()]
	st.at = time.Now().Add(-10 * time.Minute)
	w.last[e.Key()] = st
	// agora envia com a contagem acumulada (3 suprimidos + 1).
	if c, send := w.rateLimit(e); !send || c != 4 {
		t.Fatalf("apos janela: send=%v count=%d (quero 4)", send, c)
	}
}
