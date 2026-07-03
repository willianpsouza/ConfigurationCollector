package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGenerate(t *testing.T) {
	var gotBody genReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/generate" {
			t.Errorf("path = %q, quero /api/generate", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, quero POST", r.Method)
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		_, _ = io.WriteString(w, `{"response":"config parseada com sucesso","done":true}`)
	}))
	defer srv.Close()

	c := New(srv.URL, "qwen2.5:14b")
	out, err := c.Generate(context.Background(), "voce e engenheiro", "analise essa config")
	if err != nil {
		t.Fatalf("Generate erro: %v", err)
	}
	if !strings.Contains(out, "config parseada") {
		t.Errorf("resposta = %q", out)
	}
	if gotBody.Model != "qwen2.5:14b" {
		t.Errorf("model = %q", gotBody.Model)
	}
	if gotBody.System != "voce e engenheiro" {
		t.Errorf("system = %q", gotBody.System)
	}
	if gotBody.Prompt != "analise essa config" {
		t.Errorf("prompt = %q", gotBody.Prompt)
	}
	if gotBody.Stream {
		t.Error("stream deveria ser false")
	}
}

func TestGenerateOllamaError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"error":"model not found"}`)
	}))
	defer srv.Close()

	c := New(srv.URL, "inexistente")
	if _, err := c.Generate(context.Background(), "", "oi"); err == nil {
		t.Fatal("esperava erro do ollama")
	} else if !strings.Contains(err.Error(), "model not found") {
		t.Errorf("erro = %v", err)
	}
}

func TestGenerateBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `nao e json`)
	}))
	defer srv.Close()

	c := New(srv.URL, "m")
	if _, err := c.Generate(context.Background(), "", "oi"); err == nil {
		t.Fatal("esperava erro de decode")
	}
}

func TestGenerateConnRefused(t *testing.T) {
	c := New("http://127.0.0.1:0", "m")
	if _, err := c.Generate(context.Background(), "", "oi"); err == nil {
		t.Fatal("esperava erro de request")
	}
}

func TestModels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tags" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"models":[{"name":"qwen2.5:14b"},{"name":"gemma4:latest"}]}`)
	}))
	defer srv.Close()

	c := New(srv.URL, "qwen2.5:14b")
	models, err := c.Models(context.Background())
	if err != nil {
		t.Fatalf("Models erro: %v", err)
	}
	if len(models) != 2 || models[0] != "qwen2.5:14b" || models[1] != "gemma4:latest" {
		t.Errorf("models = %v", models)
	}
}

func TestModelsBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{`)
	}))
	defer srv.Close()

	c := New(srv.URL, "m")
	if _, err := c.Models(context.Background()); err == nil {
		t.Fatal("esperava erro de decode")
	}
}

func TestModelsConnRefused(t *testing.T) {
	c := New("http://127.0.0.1:0", "m")
	if _, err := c.Models(context.Background()); err == nil {
		t.Fatal("esperava erro de request")
	}
}
