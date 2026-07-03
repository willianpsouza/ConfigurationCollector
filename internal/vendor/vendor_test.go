package vendor

import (
	"testing"
)

func TestModeString(t *testing.T) {
	cases := []struct {
		mode Mode
		want string
	}{
		{ModeShell, "shell"},
		{ModeExec, "exec"},
		{Mode(99), "shell"}, // valores desconhecidos caem no default "shell"
	}
	for _, c := range cases {
		if got := c.mode.String(); got != c.want {
			t.Errorf("Mode(%d).String() = %q, quer %q", c.mode, got, c.want)
		}
	}
}

func TestGetKnown(t *testing.T) {
	for _, name := range []string{"huawei", "HUAWEI", " Huawei ", "zte", "mikrotik", "cisco"} {
		d, err := Get(name)
		if err != nil {
			t.Fatalf("Get(%q) erro inesperado: %v", name, err)
		}
		if d == nil {
			t.Fatalf("Get(%q) devolveu driver nil", name)
		}
	}
}

func TestGetUnknown(t *testing.T) {
	d, err := Get("naoexiste")
	if err == nil {
		t.Fatal("Get(naoexiste) deveria retornar erro")
	}
	if d != nil {
		t.Fatalf("Get(naoexiste) driver deveria ser nil, veio %v", d)
	}
}

func TestIsRegistered(t *testing.T) {
	for _, name := range []string{"huawei", "ZTE", "mikrotik", "cisco"} {
		if !IsRegistered(name) {
			t.Errorf("IsRegistered(%q) = false, quer true", name)
		}
	}
	for _, name := range []string{"naoexiste", "", "  "} {
		if IsRegistered(name) {
			t.Errorf("IsRegistered(%q) = true, quer false", name)
		}
	}
}

func TestNamesSortedAndContainsAll(t *testing.T) {
	names := Names()
	want := []string{"cisco", "huawei", "mikrotik", "zte"}
	found := map[string]bool{}
	for _, n := range names {
		found[n] = true
	}
	for _, w := range want {
		if !found[w] {
			t.Errorf("Names() nao contem %q (veio %v)", w, names)
		}
	}
	// ordenacao alfabetica
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Fatalf("Names() nao esta ordenado: %v", names)
		}
	}
}

func TestDriversContract(t *testing.T) {
	cases := []struct {
		name     string
		wantMode Mode
	}{
		{"huawei", ModeShell},
		{"zte", ModeShell},
		{"cisco", ModeShell},
		{"mikrotik", ModeExec},
	}
	for _, c := range cases {
		d, err := Get(c.name)
		if err != nil {
			t.Fatalf("Get(%q): %v", c.name, err)
		}
		if d.Name() != c.name {
			t.Errorf("%s: Name() = %q", c.name, d.Name())
		}
		if d.Mode() != c.wantMode {
			t.Errorf("%s: Mode() = %v, quer %v", c.name, d.Mode(), c.wantMode)
		}
		if len(d.Commands()) == 0 {
			t.Errorf("%s: Commands() vazio", c.name)
		}
		if d.Exit() == "" {
			t.Errorf("%s: Exit() vazio", c.name)
		}
		// Prompts nao-vazio para todos os drivers atuais.
		if len(d.Prompts()) == 0 {
			t.Errorf("%s: Prompts() vazio", c.name)
		}
		// Setup: os shell drivers tem setup; mikrotik (exec) retorna nil.
		if c.wantMode == ModeShell && len(d.Setup()) == 0 {
			t.Errorf("%s: Setup() vazio para driver shell", c.name)
		}
		if c.wantMode == ModeExec && d.Setup() != nil {
			t.Errorf("%s: Setup() deveria ser nil no ModeExec, veio %v", c.name, d.Setup())
		}
	}
}

// emptyNameDriver serve para exercitar o panic de nome vazio.
type emptyNameDriver struct{}

func (emptyNameDriver) Name() string     { return "   " } // vira "" apos trim
func (emptyNameDriver) Mode() Mode       { return ModeShell }
func (emptyNameDriver) Setup() []string  { return nil }
func (emptyNameDriver) Commands() []string {
	return []string{"x"}
}
func (emptyNameDriver) Prompts() []string { return nil }
func (emptyNameDriver) Exit() string      { return "" }

func TestRegisterPanicEmptyName(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Register com nome vazio deveria dar panic")
		}
	}()
	Register(emptyNameDriver{})
}

func TestRegisterPanicDuplicate(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Register de driver duplicado deveria dar panic")
		}
	}()
	Register(huawei{}) // ja registrado no init()
}
