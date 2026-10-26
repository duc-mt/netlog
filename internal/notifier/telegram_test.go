package notifier

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"netlog/internal/collector"
)

func TestTelegramNotifier_SendSync(t *testing.T) {
	var received telegramPayload
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/sendMessage") {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewDecoder(r.Body).Decode(&received)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true, "result": {"message_id": 123}}`))
	}))
	defer srv.Close()

	cfg := TelegramConfig{
		Enabled:         true,
		BotToken:        "123456:dummy",
		ChatID:          "-100111222333",
		ThreadID:        42,
		CooldownSeconds: 60,
	}

	tn := NewTelegram(cfg, nil)
	if tn == nil {
		t.Fatal("expected non-nil notifier")
	}
	defer tn.Close()

	tn.SetBaseURL(srv.URL)

	err := tn.SendSync(t.Context(), "Test message")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if received.ChatID != "-100111222333" {
		t.Errorf("expected chat_id -100111222333, got %s", received.ChatID)
	}
	if received.MessageThreadID != 42 {
		t.Errorf("expected thread_id 42, got %d", received.MessageThreadID)
	}
	if received.Text != "Test message" {
		t.Errorf("expected text 'Test message', got %q", received.Text)
	}
}

func TestTelegramNotifier_OnIncident_Throttling(t *testing.T) {
	sentCount := 0
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sentCount++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()

	cfg := TelegramConfig{
		Enabled:         true,
		BotToken:        "123456:dummy",
		ChatID:          "-100111222333",
		CooldownSeconds: 300,
	}

	tn := NewTelegram(cfg, nil)
	tn.SetBaseURL(srv.URL)
	defer tn.Close()

	rep := collector.IncidentReport{
		ID:       "inc-001",
		Hostname: "CORE-RT-01",
		TriggerLog: collector.LogEntry{
			Event:  "OSPF_DOWN",
			Object: "GigabitEthernet0/0/1",
		},
		Playbook: "ospf_adj_down",
		Diagnostics: []collector.DiagCmd{
			{Command: "show ip ospf neighbor", Output: "neighbor dead", DurationMs: 120},
		},
		TriageHints: []string{"Check MTU and link"},
	}

	// First call should queue
	tn.OnIncident(rep, "/path/inc-001.json")
	// Second call should be throttled by cooldown
	tn.OnIncident(rep, "/path/inc-001.json")

	// Allow worker to process
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	count := sentCount
	mu.Unlock()

	if count != 1 {
		t.Fatalf("expected exactly 1 alert sent due to cooldown, got %d", count)
	}
}
