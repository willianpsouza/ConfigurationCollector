package transport

import (
	"strings"
	"testing"
)

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
