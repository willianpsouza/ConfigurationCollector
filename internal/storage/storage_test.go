package storage

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestSaveAndReadBack(t *testing.T) {
	base := t.TempDir()
	st := NewTimestamped(base)

	when := time.Date(2026, 7, 2, 13, 45, 30, 0, time.UTC)
	m := Meta{
		Asset:    "RT 01",   // espaco -> _
		Address:  "a/b",     // barra -> _
		Vendor:   "huawei",
		Protocol: "ssh",
		Time:     when,
	}
	data := []byte("conteudo da coleta\nlinha 2\n")

	path, err := st.Save(context.Background(), m, data)
	if err != nil {
		t.Fatalf("Save erro: %v", err)
	}

	wantDir := filepath.Join(base, "2026-07-02")
	wantName := "RT_01__a_b__huawei__ssh__134530.txt"
	wantPath := filepath.Join(wantDir, wantName)
	if path != wantPath {
		t.Errorf("path = %q, quer %q", path, wantPath)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("relendo arquivo salvo: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("conteudo = %q, quer %q", got, data)
	}

	// permissao 0644 (mascara pode variar por umask no diretorio, o arquivo e chmod explicito).
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("perm = %v, quer 0644", info.Mode().Perm())
	}
}

func TestSanitize(t *testing.T) {
	cases := []struct{ in, want string }{
		{"abc", "abc"},
		{"a b c", "a_b_c"},
		{"a:b", "a_b"},
		{"a/b", "a_b"},
		{`a\b`, "a_b"},
		{"  trim  ", "trim"},
		{"x: y/z\\w", "x__y_z_w"},
	}
	for _, c := range cases {
		if got := sanitize(c.in); got != c.want {
			t.Errorf("sanitize(%q) = %q, quer %q", c.in, got, c.want)
		}
	}
}

func TestSaveMkdirError(t *testing.T) {
	// baseDir aponta para um arquivo comum: MkdirAll(baseDir/dia) falha.
	f := filepath.Join(t.TempDir(), "arquivo")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	st := NewTimestamped(f)
	_, err := st.Save(context.Background(), Meta{
		Asset: "a", Address: "b", Vendor: "v", Protocol: "ssh",
		Time: time.Now(),
	}, []byte("dados"))
	if err == nil {
		t.Fatal("Save deveria falhar quando baseDir e um arquivo")
	}
}

func TestSaveRenameError(t *testing.T) {
	// Cria um diretorio exatamente no caminho do arquivo alvo: o rename final
	// falha (nao da pra sobrescrever diretorio por arquivo), cobrindo o retorno
	// de erro de Save/writeAtomic.
	base := t.TempDir()
	st := NewTimestamped(base)
	when := time.Date(2026, 7, 2, 1, 2, 3, 0, time.UTC)
	m := Meta{Asset: "n", Address: "i", Vendor: "v", Protocol: "ssh", Time: when}

	day := when.Format("2006-01-02")
	name := fmt.Sprintf("%s__%s__%s__%s__%s.txt",
		sanitize(m.Asset), sanitize(m.Address), sanitize(m.Vendor),
		sanitize(m.Protocol), when.Format("150405"))
	target := filepath.Join(base, day, name)
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	// garante que nao esta vazio (rename sobre diretorio nao-vazio falha em qualquer OS)
	if err := os.WriteFile(filepath.Join(target, "filho"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := st.Save(context.Background(), m, []byte("dados")); err == nil {
		t.Fatal("Save deveria falhar quando o alvo ja e um diretorio")
	}
}

func TestWriteAtomicCreateTempError(t *testing.T) {
	// diretorio inexistente -> os.CreateTemp falha.
	bad := filepath.Join(t.TempDir(), "nao-existe", "arquivo.txt")
	if err := writeAtomic(bad, []byte("x"), 0o644); err == nil {
		t.Fatal("writeAtomic deveria falhar com diretorio inexistente")
	}
}

// TestWriteAtomicWriteError cobre o branch de erro de tmp.Write em writeAtomic.
// Limita o tamanho maximo de arquivo do processo (RLIMIT_FSIZE) a zero: o
// CreateTemp cria um arquivo de 0 bytes (ok), mas o Write subsequente estoura o
// limite e retorna EFBIG. SIGXFSZ e ignorado para que o write devolva o erro em
// vez de encerrar o processo. Tudo e restaurado ao final.
func TestWriteAtomicWriteError(t *testing.T) {
	dir := t.TempDir() // criado antes de baixar o limite

	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Skipf("Getrlimit indisponivel: %v", err)
	}

	signal.Ignore(syscall.SIGXFSZ)
	defer signal.Reset(syscall.SIGXFSZ)

	lim := old
	lim.Cur = 0
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &lim); err != nil {
		t.Skipf("Setrlimit indisponivel: %v", err)
	}
	defer func() { _ = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old) }()

	err := writeAtomic(filepath.Join(dir, "f.txt"), []byte("dados que excedem o limite de 0 bytes"), 0o644)
	if err == nil {
		t.Fatal("writeAtomic deveria falhar por limite de tamanho de arquivo")
	}
}
