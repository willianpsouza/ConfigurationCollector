// Package telegram e um cliente minimo para enviar mensagens via Bot API.
package telegram

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client envia mensagens por um bot do Telegram.
type Client struct {
	token   string
	baseURL string
	client  *http.Client
}

const defaultBaseURL = "https://api.telegram.org"

// New cria o cliente com o token do bot.
func New(token string) *Client {
	return &Client{token: token, baseURL: defaultBaseURL, client: &http.Client{Timeout: 15 * time.Second}}
}

// NewWithBaseURL permite apontar para outra base (ex.: httptest em testes).
func NewWithBaseURL(token, baseURL string) *Client {
	c := New(token)
	c.baseURL = baseURL
	return c
}

// Update e uma mensagem recebida (subset do getUpdates).
type Update struct {
	UpdateID int64
	ChatID   string
	Text     string
}

// GetUpdates faz long-poll de novas mensagens a partir de offset.
func (c *Client) GetUpdates(ctx context.Context, offset int64, timeoutSec int) ([]Update, error) {
	endpoint := fmt.Sprintf("%s/bot%s/getUpdates?offset=%d&timeout=%d", c.baseURL, c.token, offset, timeoutSec)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var out struct {
		OK     bool `json:"ok"`
		Result []struct {
			UpdateID int64 `json:"update_id"`
			Message  struct {
				Text string `json:"text"`
				Chat struct {
					ID int64 `json:"id"`
				} `json:"chat"`
			} `json:"message"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	var ups []Update
	for _, r := range out.Result {
		ups = append(ups, Update{
			UpdateID: r.UpdateID,
			ChatID:   strconv.FormatInt(r.Message.Chat.ID, 10),
			Text:     r.Message.Text,
		})
	}
	return ups, nil
}

// Send envia texto para um chat (chat_id pode ser numerico ou @canal).
func (c *Client) Send(ctx context.Context, chatID, text string) error {
	if c.token == "" || chatID == "" {
		return fmt.Errorf("telegram: token/chat nao configurado")
	}
	endpoint := c.baseURL + "/bot" + c.token + "/sendMessage"
	form := url.Values{
		"chat_id":                  {chatID},
		"text":                     {text},
		"disable_web_page_preview": {"true"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("telegram send: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("telegram HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}
