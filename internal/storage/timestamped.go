package storage

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Timestamped grava cada coleta como um arquivo datado:
//
//	<baseDir>/<YYYY-MM-DD>/<NOME>__<IP>__<VENDOR>__<PROTO>__<HHMMSS>.txt
//
// Escrita atomica (tmp + rename). Mantem o esquema historico do projeto.
type Timestamped struct {
	baseDir string
	perm    fs.FileMode
}

// NewTimestamped cria o store apontando para baseDir. Os subdiretorios por dia
// sao criados sob demanda.
func NewTimestamped(baseDir string) *Timestamped {
	return &Timestamped{baseDir: baseDir, perm: 0o644}
}

// Save grava a coleta e devolve o caminho completo do arquivo.
func (t *Timestamped) Save(_ context.Context, m Meta, data []byte) (string, error) {
	day := m.Time.Format("2006-01-02")
	dir := filepath.Join(t.baseDir, day)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("criando diretorio %s: %w", dir, err)
	}

	name := fmt.Sprintf("%s__%s__%s__%s__%s.txt",
		sanitize(m.Asset), sanitize(m.Address), sanitize(m.Vendor),
		sanitize(m.Protocol), m.Time.Format("150405"))
	path := filepath.Join(dir, name)

	if err := writeAtomic(path, data, t.perm); err != nil {
		return "", err
	}
	return path, nil
}

func sanitize(s string) string {
	s = strings.TrimSpace(s)
	r := strings.NewReplacer(":", "_", "/", "_", "\\", "_", " ", "_")
	return r.Replace(s)
}

func writeAtomic(path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-collect-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr != nil {
		_ = os.Remove(tmpName)
		return werr
	}
	if cerr != nil {
		_ = os.Remove(tmpName)
		return cerr
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}
