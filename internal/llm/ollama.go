// Package llm e um cliente minimo para o Ollama local (documentacao e deteccao
// de divergencias difusas). Sem dependencias externas.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Client fala com a API do Ollama.
type Client struct {
	url    string
	model  string
	client *http.Client
}

// New cria um cliente. url ex.: "http://localhost:11434"; model ex.: "qwen2.5:14b".
func New(url, model string) *Client {
	return &Client{
		url:    url,
		model:  model,
		client: &http.Client{Timeout: 10 * time.Minute},
	}
}

type genReq struct {
	Model   string  `json:"model"`
	Prompt  string  `json:"prompt"`
	System  string  `json:"system,omitempty"`
	Stream  bool    `json:"stream"`
	Options options `json:"options,omitempty"`
}

type options struct {
	Temperature float64 `json:"temperature,omitempty"`
	NumCtx      int     `json:"num_ctx,omitempty"`
}

type genResp struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
	Error    string `json:"error,omitempty"`
}

// Generate roda um prompt (nao-streaming) e devolve a resposta completa.
func (c *Client) Generate(ctx context.Context, system, prompt string) (string, error) {
	body, _ := json.Marshal(genReq{
		Model:  c.model,
		Prompt: prompt,
		System: system,
		Stream: false,
		Options: options{
			Temperature: 0.1, // deterministico p/ analise de config
			NumCtx:      16384,
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ollama request: %w", err)
	}
	defer resp.Body.Close()

	var gr genResp
	if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil {
		return "", fmt.Errorf("decode ollama resp: %w", err)
	}
	if gr.Error != "" {
		return "", fmt.Errorf("ollama: %s", gr.Error)
	}
	return gr.Response, nil
}

type tagsResp struct {
	Models []struct {
		Name string `json:"name"`
	} `json:"models"`
}

// Models lista os modelos disponiveis no Ollama (preflight).
func (c *Client) Models(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url+"/api/tags", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ollama tags: %w", err)
	}
	defer resp.Body.Close()

	var tr tagsResp
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(tr.Models))
	for _, m := range tr.Models {
		out = append(out, m.Name)
	}
	return out, nil
}
