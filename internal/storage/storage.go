// Package storage abstrai onde as configuracoes coletadas sao persistidas.
//
// A interface Store isola o coletor do backend de armazenamento, permitindo
// trocar/somar implementacoes sem tocar na coleta (hoje: arquivos datados;
// futuro: git versionado, envio para a API do Manager, etc.).
package storage

import (
	"context"
	"time"
)

// Meta descreve a coleta que esta sendo salva.
type Meta struct {
	Asset    string
	Address  string
	Vendor   string
	Protocol string
	Time     time.Time
}

// Store persiste o conteudo bruto de uma coleta e devolve um identificador
// (caminho, URL, hash...) do que foi gravado.
type Store interface {
	Save(ctx context.Context, m Meta, data []byte) (id string, err error)
}
