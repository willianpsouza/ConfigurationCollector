package transport

import (
	"strings"
	"testing"
)

func TestScanErrors(t *testing.T) {
	// Estatisticas do 'display eth-trunk/interface' NAO devem virar erro.
	stats := "WorkingMode: NORMAL\n  Total Error: 0\n  Input Error: 0\nXGigabitEthernet0/0/36  Down"
	if errs := scanErrors(stats); len(errs) != 0 {
		t.Errorf("stats nao deveriam ser erro, veio: %v", errs)
	}
	// Erro real de CLI Huawei (linha comeca com Error:).
	tr := "undo network 100.127.63.212 0.0.0.3\nError: Unrecognized command found at '^' position.\n<HOST>"
	errs := scanErrors(tr)
	if len(errs) != 1 || !strings.Contains(errs[0], "Unrecognized") {
		t.Errorf("erro real deveria ser pego 1x, veio: %v", errs)
	}
	// Warning nao e erro; % Invalid e erro.
	if len(scanErrors("Warning: security risk enabling syslog")) != 0 {
		t.Error("Warning nao deveria ser erro")
	}
	if len(scanErrors("% Invalid input detected")) != 1 {
		t.Error("% Invalid deveria ser erro")
	}
	// Mix: stats + 1 erro real -> so o erro.
	mix := "  Total Error: 0\nError: Wrong parameter found\n  inErrors 0"
	if errs := scanErrors(mix); len(errs) != 1 {
		t.Errorf("mix deveria ter 1 erro, veio: %v", errs)
	}
}

func TestAwaitsConfirm(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want bool
	}{
		{"y/n prompt", "Warning: ... Continue? [Y/N]:", true},
		{"are you sure", "Are you sure to continue?[Y/N]", true},
		{"yes/no", "Delete this? [yes/no]:", true},
		{"continue question", "Continue ?", true},
		{"normal prompt", "vlan batch 10\n<HOST>", false},
		{"plain output", "Info: config aplicada com sucesso.", false},
		{"empty", "", false},
		{"confirm far from tail (fora da cauda)", "[Y/N] " + strings.Repeat("x", 300), false},
		{"confirm within tail", strings.Repeat("x", 300) + " [Y/N]:", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := awaitsConfirm(tt.out); got != tt.want {
				t.Errorf("awaitsConfirm(%q) = %v, want %v", tt.out, got, tt.want)
			}
		})
	}
}
