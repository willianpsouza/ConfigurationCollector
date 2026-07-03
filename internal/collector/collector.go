// Package collector orquestra a coleta: distribui os alvos entre workers,
// aplica retry, escolhe transporte (SSH/Telnet) e driver (vendor), e persiste o
// resultado no Store.
package collector

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/willianpsouza/ConfigurationCollector/internal/config"
	"github.com/willianpsouza/ConfigurationCollector/internal/storage"
	"github.com/willianpsouza/ConfigurationCollector/internal/transport"
	"github.com/willianpsouza/ConfigurationCollector/internal/vendor"
)

// Collector executa coletas contra uma lista de alvos ja resolvidos.
type Collector struct {
	concurrency int
	maxRetries  int
	ssh         transport.Transport
	telnet      transport.Transport
	store       storage.Store
	logger      *slog.Logger
}

// Options configura o Collector.
type Options struct {
	Concurrency int
	MaxRetries  int
	SSH         transport.Transport // obrigatorio para alvos ssh
	Telnet      transport.Transport // obrigatorio para alvos telnet
	Store       storage.Store       // obrigatorio
	Logger      *slog.Logger        // obrigatorio
}

// New cria um Collector.
func New(o Options) *Collector {
	if o.Concurrency <= 0 {
		o.Concurrency = 5
	}
	return &Collector{
		concurrency: o.Concurrency,
		maxRetries:  o.MaxRetries,
		ssh:         o.SSH,
		telnet:      o.Telnet,
		store:       o.Store,
		logger:      o.Logger,
	}
}

// Summary resume o resultado de uma execucao.
type Summary struct {
	Total   int
	OK      int
	Failed  int
	Elapsed time.Duration
}

// Run coleta todos os alvos respeitando a concorrencia e o cancelamento do
// context. E seguro chamar concorrentemente entre execucoes distintas.
func (c *Collector) Run(ctx context.Context, targets []config.Target) Summary {
	start := time.Now()
	jobs := make(chan config.Target)
	var ok, failed int64

	var wg sync.WaitGroup
	for i := 0; i < c.concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for t := range jobs {
				if ctx.Err() != nil {
					return
				}
				if err := c.runWithRetry(ctx, t); err != nil {
					atomic.AddInt64(&failed, 1)
					c.logger.Error("coleta falhou",
						"asset", t.Name, "vendor", t.Vendor,
						"address", t.Address, "protocol", t.Protocol, "error", err)
				} else {
					atomic.AddInt64(&ok, 1)
					c.logger.Info("coleta concluida",
						"asset", t.Name, "vendor", t.Vendor,
						"address", t.Address, "protocol", t.Protocol)
				}
			}
		}(i)
	}

	for _, t := range targets {
		select {
		case <-ctx.Done():
			goto done
		case jobs <- t:
		}
	}
done:
	close(jobs)
	wg.Wait()

	return Summary{
		Total:   len(targets),
		OK:      int(ok),
		Failed:  int(failed),
		Elapsed: time.Since(start),
	}
}

func (c *Collector) runWithRetry(ctx context.Context, t config.Target) error {
	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if attempt > 0 {
			backoff := time.Duration(attempt) * 2 * time.Second
			c.logger.Info("tentando novamente",
				"asset", t.Name, "attempt", attempt, "max_retries", c.maxRetries, "backoff", backoff)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}
		if err := c.runOnce(ctx, t); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return fmt.Errorf("falhou apos %d tentativas: %w", c.maxRetries+1, lastErr)
}

func (c *Collector) runOnce(ctx context.Context, t config.Target) error {
	driver, err := vendor.Get(t.Vendor)
	if err != nil {
		return err
	}

	tr, err := c.transportFor(t.Protocol)
	if err != nil {
		return err
	}

	sess := transport.Session{
		Vendor:   t.Vendor,
		Name:     t.Name,
		Address:  t.Address,
		Port:     t.Port,
		Username: t.Username,
		Password: t.Password,
		Timeout:  t.Timeout,
	}

	out, err := tr.Collect(ctx, sess, driver, c.logger)
	if err != nil {
		return err
	}

	_, err = c.store.Save(ctx, storage.Meta{
		Asset:    t.Name,
		Address:  t.Address,
		Vendor:   t.Vendor,
		Protocol: t.Protocol,
		Time:     time.Now(),
	}, []byte(out))
	return err
}

func (c *Collector) transportFor(protocol string) (transport.Transport, error) {
	switch protocol {
	case "ssh":
		if c.ssh == nil {
			return nil, fmt.Errorf("transporte ssh nao configurado")
		}
		return c.ssh, nil
	case "telnet":
		if c.telnet == nil {
			return nil, fmt.Errorf("transporte telnet nao configurado")
		}
		return c.telnet, nil
	default:
		return nil, fmt.Errorf("protocolo desconhecido: %q", protocol)
	}
}
