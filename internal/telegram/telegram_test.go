package telegram

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSend(t *testing.T) {
	var gotChat, gotText, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = r.ParseForm()
		gotChat = r.FormValue("chat_id")
		gotText = r.FormValue("text")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	c := NewWithBaseURL("TOKEN123", srv.URL)
	if err := c.Send(context.Background(), "-100999", "alerta óptico"); err != nil {
		t.Fatalf("Send erro: %v", err)
	}
	if gotPath != "/botTOKEN123/sendMessage" {
		t.Errorf("path = %q", gotPath)
	}
	if gotChat != "-100999" || gotText != "alerta óptico" {
		t.Errorf("chat/text = %q/%q", gotChat, gotText)
	}
}

func TestSendHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"ok":false,"description":"chat not found"}`)
	}))
	defer srv.Close()
	c := NewWithBaseURL("T", srv.URL)
	if err := c.Send(context.Background(), "x", "y"); err == nil || !strings.Contains(err.Error(), "chat not found") {
		t.Fatalf("esperava erro com descricao, veio: %v", err)
	}
}

func TestSendNoConfig(t *testing.T) {
	if err := New("").Send(context.Background(), "x", "y"); err == nil {
		t.Error("token vazio deveria dar erro")
	}
	if err := New("T").Send(context.Background(), "", "y"); err == nil {
		t.Error("chat vazio deveria dar erro")
	}
}

func TestGetUpdates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/getUpdates") {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"ok":true,"result":[{"update_id":42,"message":{"text":"/start","chat":{"id":-100777}}}]}`)
	}))
	defer srv.Close()

	c := NewWithBaseURL("T", srv.URL)
	ups, err := c.GetUpdates(context.Background(), 0, 0)
	if err != nil {
		t.Fatalf("GetUpdates erro: %v", err)
	}
	if len(ups) != 1 || ups[0].UpdateID != 42 || ups[0].ChatID != "-100777" || ups[0].Text != "/start" {
		t.Errorf("update = %+v", ups)
	}
}
