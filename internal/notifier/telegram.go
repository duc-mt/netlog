// ==============================================================================
// Package notifier: Telegram and webhook notifications for netlog.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-26
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"netlog/internal/collector"
	"netlog/internal/credentials"
)

// TelegramConfig defines the configuration for sending alerts to Telegram.
type TelegramConfig struct {
	Enabled         bool
	BotToken        string
	ChatID          string
	ThreadID        int
	MinSeverity     string
	CooldownSeconds int
	Silent          bool
	ProxyURL        string
}

// ConfigFromStore loads TelegramConfig from credentials.Store and fallback to process env.
func ConfigFromStore(store *credentials.Store) TelegramConfig {
	get := func(k string) string {
		if store != nil {
			return store.Get(k)
		}
		return os.Getenv(k)
	}

	enabled := false
	if v := get("TELEGRAM_ENABLED"); v != "" {
		v = strings.ToLower(strings.TrimSpace(v))
		enabled = (v == "true" || v == "1" || v == "yes" || v == "on")
	}

	threadID := 0
	if v := get("TELEGRAM_MESSAGE_THREAD_ID"); v != "" {
		if id, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			threadID = id
		}
	}

	cooldown := 300
	if v := get("TELEGRAM_COOLDOWN_SECONDS"); v != "" {
		if cd, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && cd >= 0 {
			cooldown = cd
		}
	}

	minSev := strings.ToLower(strings.TrimSpace(get("TELEGRAM_MIN_SEVERITY")))
	if minSev == "" {
		minSev = "warning"
	}

	silent := false
	if v := get("TELEGRAM_SILENT"); v != "" {
		v = strings.ToLower(strings.TrimSpace(v))
		silent = (v == "true" || v == "1" || v == "yes" || v == "on")
	}

	return TelegramConfig{
		Enabled:         enabled,
		BotToken:        strings.TrimSpace(get("TELEGRAM_BOT_TOKEN")),
		ChatID:          strings.TrimSpace(get("TELEGRAM_CHAT_ID")),
		ThreadID:        threadID,
		MinSeverity:     minSev,
		CooldownSeconds: cooldown,
		Silent:          silent,
		ProxyURL:        strings.TrimSpace(get("TELEGRAM_PROXY_URL")),
	}
}

// ConfigFromEnv loads TelegramConfig from standard environment variables matching ospf-topoviz.
func ConfigFromEnv() TelegramConfig {
	return ConfigFromStore(nil)
}

// TelegramNotifier handles dispatching alert messages to Telegram channels.
type TelegramNotifier struct {
	cfg        TelegramConfig
	client     *http.Client
	baseURL    string
	logger     collector.Logger
	cooldownMu sync.Mutex
	lastSent   map[string]time.Time
	asyncCh    chan string
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewTelegram creates an active TelegramNotifier. If cfg.Enabled is false or tokens are empty, returns nil.
func NewTelegram(cfg TelegramConfig, log collector.Logger) *TelegramNotifier {
	if !cfg.Enabled || cfg.BotToken == "" || cfg.ChatID == "" {
		return nil
	}

	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	if cfg.ProxyURL != "" {
		if u, err := url.Parse(cfg.ProxyURL); err == nil {
			transport.Proxy = http.ProxyURL(u)
		} else if log != nil {
			log.Warn("telegram: invalid proxy URL %q: %v", cfg.ProxyURL, err)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	tn := &TelegramNotifier{
		cfg:      cfg,
		client:   client,
		baseURL:  "https://api.telegram.org/bot" + cfg.BotToken,
		logger:   log,
		lastSent: make(map[string]time.Time),
		asyncCh:  make(chan string, 100),
		ctx:      ctx,
		cancel:   cancel,
	}

	tn.wg.Add(1)
	go tn.worker()

	return tn
}

// SetBaseURL overrides Telegram API URL (primarily for unit tests).
func (tn *TelegramNotifier) SetBaseURL(url string) {
	tn.baseURL = strings.TrimRight(url, "/")
}

// Close stops the background worker gracefully.
func (tn *TelegramNotifier) Close() {
	if tn == nil {
		return
	}
	tn.cancel()
	close(tn.asyncCh)
	tn.wg.Wait()
}

func (tn *TelegramNotifier) worker() {
	defer tn.wg.Done()
	for msg := range tn.asyncCh {
		if err := tn.sendRaw(context.Background(), msg); err != nil {
			if tn.logger != nil {
				tn.logger.Warn("telegram send failed: %v", err)
			}
		}
	}
}

func (tn *TelegramNotifier) shouldThrottle(key string) bool {
	if tn.cfg.CooldownSeconds <= 0 {
		return false
	}
	tn.cooldownMu.Lock()
	defer tn.cooldownMu.Unlock()

	now := time.Now()
	if last, ok := tn.lastSent[key]; ok {
		if now.Sub(last) < time.Duration(tn.cfg.CooldownSeconds)*time.Second {
			return true
		}
	}
	tn.lastSent[key] = now
	return false
}

type telegramPayload struct {
	ChatID                string `json:"chat_id"`
	Text                  string `json:"text"`
	ParseMode             string `json:"parse_mode"`
	DisableNotification   bool   `json:"disable_notification,omitempty"`
	MessageThreadID       int    `json:"message_thread_id,omitempty"`
	DisableWebPagePreview bool   `json:"disable_web_page_preview"`
}

func (tn *TelegramNotifier) sendRaw(ctx context.Context, text string) error {
	payload := telegramPayload{
		ChatID:                tn.cfg.ChatID,
		Text:                  text,
		ParseMode:             "HTML",
		DisableNotification:   tn.cfg.Silent,
		MessageThreadID:       tn.cfg.ThreadID,
		DisableWebPagePreview: true,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	endpoint := tn.baseURL + "/sendMessage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := tn.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Description string `json:"description"`
			ErrorCode   int    `json:"error_code"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		return fmt.Errorf("api error %d: %s", resp.StatusCode, errResp.Description)
	}

	return nil
}

// SendSync sends a message synchronously. Useful for CLI tests.
func (tn *TelegramNotifier) SendSync(ctx context.Context, text string) error {
	return tn.sendRaw(ctx, text)
}

// OnIncident implements triage.Hook.
func (tn *TelegramNotifier) OnIncident(report collector.IncidentReport, _ string) {
	if tn == nil {
		return
	}

	key := fmt.Sprintf("incident:%s:%s", report.Hostname, report.TriggerLog.Event)
	if tn.shouldThrottle(key) {
		if tn.logger != nil {
			tn.logger.Info("telegram: throttled incident alert for %s %s", report.Hostname, report.TriggerLog.Event)
		}
		return
	}

	var sb strings.Builder
	sb.WriteString("🚨 <b>[NETLOG INCIDENT] Auto-Triage Captured</b>\n\n")
	sb.WriteString(fmt.Sprintf("• <b>Device:</b> <code>%s</code>\n", html.EscapeString(report.Hostname)))
	sb.WriteString(fmt.Sprintf("• <b>Event:</b> <code>%s</code>\n", html.EscapeString(report.TriggerLog.Event)))
	if report.TriggerLog.Object != "" {
		sb.WriteString(fmt.Sprintf("• <b>Target:</b> <code>%s</code>\n", html.EscapeString(report.TriggerLog.Object)))
	}
	sb.WriteString(fmt.Sprintf("• <b>Playbook:</b> <code>%s</code>\n", html.EscapeString(report.Playbook)))
	sb.WriteString(fmt.Sprintf("• <b>Time:</b> %s\n", report.Timestamp.Format("2006-01-02 15:04:05 MST")))
	sb.WriteString(fmt.Sprintf("• <b>Incident ID:</b> <code>%s</code>\n", report.ID))

	if len(report.TriageHints) > 0 {
		sb.WriteString("\n🔍 <b>Root Cause Hints:</b>\n")
		for _, h := range report.TriageHints {
			sb.WriteString(fmt.Sprintf("  ▸ <i>%s</i>\n", html.EscapeString(h)))
		}
	}

	if len(report.Diagnostics) > 0 {
		sb.WriteString("\n📋 <b>Diagnostic Summary:</b>\n")
		for _, d := range report.Diagnostics {
			sb.WriteString(fmt.Sprintf("▸ <code>%s</code>", html.EscapeString(d.Command)))
			if d.Error != "" {
				sb.WriteString(fmt.Sprintf(" (Error: %s)\n", html.EscapeString(d.Error)))
			} else {
				sb.WriteString(fmt.Sprintf(" (%d ms)\n", d.DurationMs))
				lines := strings.Split(strings.TrimSpace(d.Output), "\n")
				if len(lines) > 6 {
					lines = append(lines[:6], "... [truncated]")
				}
				snippet := strings.Join(lines, "\n")
				sb.WriteString(fmt.Sprintf("<pre>%s</pre>\n", html.EscapeString(snippet)))
			}
		}
	}

	select {
	case tn.asyncCh <- sb.String():
	default:
		if tn.logger != nil {
			tn.logger.Warn("telegram: alert queue full, dropping incident %s", report.ID)
		}
	}
}

// SendDeviceHealth alerts when a device poll fails or recovers.
func (tn *TelegramNotifier) SendDeviceHealth(device string, ok bool, detail string) {
	if tn == nil {
		return
	}

	stateKey := "fail"
	if ok {
		stateKey = "ok"
	}
	key := fmt.Sprintf("health:%s:%s", device, stateKey)
	if tn.shouldThrottle(key) {
		return
	}

	var sb strings.Builder
	if ok {
		sb.WriteString("✅ <b>[NETLOG RECOVERED] Device Poll Succeeded</b>\n\n")
		sb.WriteString(fmt.Sprintf("• <b>Device:</b> <code>%s</code>\n", html.EscapeString(device)))
		sb.WriteString(fmt.Sprintf("• <b>Status:</b> Normal SSH polling resumed\n"))
		sb.WriteString(fmt.Sprintf("• <b>Time:</b> %s\n", time.Now().Format("2006-01-02 15:04:05 MST")))
	} else {
		sb.WriteString("🔴 <b>[NETLOG ALERT] Device Poll Failed</b>\n\n")
		sb.WriteString(fmt.Sprintf("• <b>Device:</b> <code>%s</code>\n", html.EscapeString(device)))
		sb.WriteString(fmt.Sprintf("• <b>Error:</b> <code>%s</code>\n", html.EscapeString(detail)))
		sb.WriteString(fmt.Sprintf("• <b>Time:</b> %s\n", time.Now().Format("2006-01-02 15:04:05 MST")))
	}

	select {
	case tn.asyncCh <- sb.String():
	default:
		if tn.logger != nil {
			tn.logger.Warn("telegram: alert queue full, dropping health alert for %s", device)
		}
	}
}

// SendCustomNotification sends an arbitrary formatted message.
func (tn *TelegramNotifier) SendCustomNotification(title, body string) {
	if tn == nil {
		return
	}
	msg := fmt.Sprintf("📢 <b>%s</b>\n\n%s", html.EscapeString(title), body)
	select {
	case tn.asyncCh <- msg:
	default:
	}
}
