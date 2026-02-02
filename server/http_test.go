package server

/*
HTTP API Tests - What These Tests Cover

These tests verify the HTTP SERVER LAYER ONLY, not actual command execution:
- HTTP endpoint routing and methods (POST /api/v1/message, GET /api/v1/message/status)
- Request JSON parsing and validation
- Required field validation (bot, channel, command)
- Response status codes (201, 400, 404, 405)
- Message storage and async status tracking
- Bot routing via CommandExecutor interface

These tests use a MockBot that accepts any command without validation.
They do NOT test:
- Real Slack bot behavior
- Command name resolution (findParams)
- Template execution
- Actual message posting to Slack

*/

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/devopsext/chatops/common"
)

// MockMessage implements common.Message for testing
type MockMessage struct {
	id        string
	visible   bool
	user      common.User
	caller    common.User
	channelID string
	parentID  string
}

func (m *MockMessage) ID() string              { return m.id }
func (m *MockMessage) Visible() bool           { return m.visible }
func (m *MockMessage) User() common.User       { return m.user }
func (m *MockMessage) Caller() common.User     { return m.caller }
func (m *MockMessage) Channel() common.Channel { return &MockChannel{id: m.channelID} }
func (m *MockMessage) ParentID() string        { return m.parentID }
func (m *MockMessage) SetParentID(ts string)   { m.parentID = ts }

// MockChannel implements common.Channel for testing
type MockChannel struct {
	id string
}

func (c *MockChannel) ID() string { return c.id }

// MockBot implements common.Bot interface for testing.
// It accepts any command and records what was called for verification.
type MockBot struct {
	name          string
	commandCalled bool
	lastChannel   string
	lastCommand   string
	lastUser      common.User
	commandErr    error
	commandDelay  time.Duration
	messageStatus common.MessageStatus
	mu            sync.Mutex
}

func NewMockBot(name string) *MockBot {
	return &MockBot{name: name, messageStatus: common.MessageStatusDelivered}
}

func (b *MockBot) Start(wg *sync.WaitGroup)                                     {}
func (b *MockBot) Stop()                                                        {}
func (b *MockBot) Name() string                                                 { return b.name }
func (b *MockBot) AddReaction(channel, ID, name string) error                   { return nil }
func (b *MockBot) RemoveReaction(channel, ID, name string) error                { return nil }
func (b *MockBot) AddAction(channel, ID string, action common.Action) error     { return nil }
func (b *MockBot) AddActions(channel, ID string, actions []common.Action) error { return nil }
func (b *MockBot) RemoveAction(channel, ID, name string) error                  { return nil }
func (b *MockBot) ClearActions(channel, ID string) error                        { return nil }
func (b *MockBot) PostMessage(channel string, message string, attachments []*common.Attachment, actions []common.Action, user common.User, parent common.Message, response common.Response) (string, error) {
	return "", nil
}
func (b *MockBot) DeleteMessage(channel, ID string) error                      { return nil }
func (b *MockBot) ReadMessage(channel, ID, threadID string) (string, error)    { return "", nil }
func (b *MockBot) ReadThread(channel, threadID string) ([]string, error)       { return nil, nil }
func (b *MockBot) UpdateMessage(channel, ID, message string) error             { return nil }
func (b *MockBot) TagMessage(channel, ID string, tags map[string]string) error { return nil }
func (b *MockBot) FindMessagesByTag(tagKey, tagValue string) map[string]string { return nil }
func (b *MockBot) SendImage(channelID, threadTS string, fileContent []byte, filename, initialComment string) error {
	return nil
}
func (b *MockBot) AddDivider(channel, ID string) error { return nil }
func (b *MockBot) LookupUser(identifier string) common.User {
	// Return a mock user with all commands allowed for testing
	return common.NewGenericUser(identifier, identifier, "", nil)
}

func (b *MockBot) Command(channel, text string, user common.User, parent common.Message, response common.Response) (common.Message, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.commandDelay > 0 {
		time.Sleep(b.commandDelay)
	}

	b.commandCalled = true
	b.lastChannel = channel
	b.lastCommand = text
	b.lastUser = user

	if b.commandErr != nil {
		return nil, b.commandErr
	}

	msg := &MockMessage{
		id:        "mock-msg-" + common.UUID(),
		visible:   true,
		user:      user,
		caller:    user,
		channelID: channel,
	}
	return msg, nil
}

// GetMessageStatus returns the mock message status
func (b *MockBot) GetMessageStatus(messageID string) (common.MessageStatus, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.messageStatus, nil
}

func (b *MockBot) GetLastCommand() (string, string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lastChannel, b.lastCommand
}

func (b *MockBot) WasCommandCalled() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.commandCalled
}

func (b *MockBot) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.commandCalled = false
	b.lastChannel = ""
	b.lastCommand = ""
	b.lastUser = nil
}

// MockObservability implements minimal observability for testing
type MockObservability struct{}

func (o *MockObservability) Info(format string, args ...any)  {}
func (o *MockObservability) Error(format string, args ...any) {}
func (o *MockObservability) Debug(format string, args ...any) {}

func newTestObservability() *common.Observability {
	return common.NewObservability(nil, nil)
}

func newTestServer(executor common.CommandExecutor) *HttpServer {
	return newTestServerWithAllowedCmds(executor, nil)
}

func newTestServerWithAllowedCmds(executor common.CommandExecutor, allowedCmds []string) *HttpServer {
	return NewHttpServer(
		HttpServerOptions{Listen: ":0", AllowedCmds: allowedCmds},
		newTestObservability(),
		executor,
	)
}

// TestCreateMessage tests HTTP endpoint validation and routing.
// Uses production-like values that would work with real Slack bot.
func TestCreateMessage(t *testing.T) {
	tests := []struct {
		name           string
		request        CreateMessageRequest
		allowedCmds    []string
		expectedStatus int
		expectError    bool
		errorContains  string
	}{
		{
			name: "Valid request with Slack bot",
			request: CreateMessageRequest{
				Bot:     "Slack",       // Case-sensitive: "Slack" not "slack"
				Channel: "C06F563PYM6", // Channel ID, not name
				Command: "help",        // No "/" prefix
				UserID:  "U12345678",
			},
			allowedCmds:    []string{"help"},
			expectedStatus: http.StatusCreated,
			expectError:    false,
		},
		{
			name: "Valid request with app command and params",
			request: CreateMessageRequest{
				Bot:     "Slack",
				Channel: "C06F563PYM6",
				Command: "app name=test-app",
				UserID:  "api-user",
			},
			allowedCmds:    []string{"app"},
			expectedStatus: http.StatusCreated,
			expectError:    false,
		},
		{
			name: "Valid request with nested command",
			request: CreateMessageRequest{
				Bot:     "Slack",
				Channel: "C08FPJQH0ML",
				Command: "inci/create title=\"Test Incident\"",
				UserID:  "admin",
			},
			allowedCmds:    []string{"inci/create"},
			expectedStatus: http.StatusCreated,
			expectError:    false,
		},
		{
			name: "Missing bot field - rejected by allowlist first",
			request: CreateMessageRequest{
				Bot:     "",
				Channel: "C06F563PYM6",
				Command: "help",
				UserID:  "test-user",
			},
			allowedCmds:    nil, // Empty allowlist
			expectedStatus: http.StatusForbidden,
			expectError:    true,
			errorContains:  "command not allowed",
		},
		{
			name: "Missing bot field - with allowed command",
			request: CreateMessageRequest{
				Bot:     "",
				Channel: "C06F563PYM6",
				Command: "help",
				UserID:  "test-user",
			},
			allowedCmds:    []string{"help"},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
			errorContains:  "bot, channel and command are required",
		},
		{
			name: "Missing channel field",
			request: CreateMessageRequest{
				Bot:     "Slack",
				Channel: "",
				Command: "help",
				UserID:  "test-user",
			},
			allowedCmds:    []string{"help"},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
			errorContains:  "bot, channel and command are required",
		},
		{
			name: "Missing command field",
			request: CreateMessageRequest{
				Bot:     "Slack",
				Channel: "C06F563PYM6",
				Command: "",
				UserID:  "test-user",
			},
			allowedCmds:    []string{""},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
			errorContains:  "bot, channel and command are required",
		},
		{
			name: "Empty user ID is allowed",
			request: CreateMessageRequest{
				Bot:     "Slack",
				Channel: "C06F563PYM6",
				Command: "status",
				UserID:  "",
			},
			allowedCmds:    []string{"status"},
			expectedStatus: http.StatusCreated,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// MockBot name must match request bot name
			mockBot := NewMockBot(tt.request.Bot)
			bots := common.NewBots()
			bots.Add(mockBot)

			server := newTestServerWithAllowedCmds(bots, tt.allowedCmds)

			body, _ := json.Marshal(tt.request)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/message", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			server.createMessage(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rec.Code)
			}

			if tt.expectError {
				var errResp ErrorResponse
				if err := json.NewDecoder(rec.Body).Decode(&errResp); err != nil {
					t.Fatalf("failed to decode error response: %v", err)
				}
				if tt.errorContains != "" && errResp.Error != tt.errorContains {
					t.Errorf("expected error containing %q, got %q", tt.errorContains, errResp.Error)
				}
			} else {
				var resp CreateMessageResponse
				if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp.ID == "" {
					t.Error("expected non-empty message ID")
				}
			}
		})
	}
}

func TestCreateMessageMethodNotAllowed(t *testing.T) {
	mockBot := NewMockBot("Slack")
	bots := common.NewBots()
	bots.Add(mockBot)

	server := newTestServer(bots)

	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/v1/message", nil)
			rec := httptest.NewRecorder()

			server.createMessage(rec, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
			}
		})
	}
}

func TestCreateMessageInvalidJSON(t *testing.T) {
	mockBot := NewMockBot("Slack")
	bots := common.NewBots()
	bots.Add(mockBot)

	server := newTestServer(bots)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/message", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.createMessage(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
}

// TestAllowedCmds tests command allowlist filtering
func TestAllowedCmds(t *testing.T) {
	tests := []struct {
		name           string
		allowedCmds    []string
		command        string
		expectedStatus int
		expectError    bool
		errorContains  string
	}{
		{
			name:           "Empty allowlist rejects all commands",
			allowedCmds:    []string{},
			command:        "help",
			expectedStatus: http.StatusForbidden,
			expectError:    true,
			errorContains:  "command not allowed",
		},
		{
			name:           "Nil allowlist rejects all commands",
			allowedCmds:    nil,
			command:        "help",
			expectedStatus: http.StatusForbidden,
			expectError:    true,
			errorContains:  "command not allowed",
		},
		{
			name:           "Allowed command succeeds",
			allowedCmds:    []string{"help", "status"},
			command:        "help",
			expectedStatus: http.StatusCreated,
			expectError:    false,
		},
		{
			name:           "Non-allowed command rejected",
			allowedCmds:    []string{"help", "status"},
			command:        "admin",
			expectedStatus: http.StatusForbidden,
			expectError:    true,
			errorContains:  "command not allowed",
		},
		{
			name:           "Command with params - base command allowed",
			allowedCmds:    []string{"app"},
			command:        "app name=test",
			expectedStatus: http.StatusCreated,
			expectError:    false,
		},
		{
			name:           "Command with different params - same base command allowed",
			allowedCmds:    []string{"app"},
			command:        "app name=other",
			expectedStatus: http.StatusCreated,
			expectError:    false,
		},
		{
			name:           "Nested command allowed",
			allowedCmds:    []string{"inci/digest"},
			command:        "inci/digest",
			expectedStatus: http.StatusCreated,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockBot := NewMockBot("Slack")
			bots := common.NewBots()
			bots.Add(mockBot)

			server := newTestServerWithAllowedCmds(bots, tt.allowedCmds)

			request := CreateMessageRequest{
				Bot:     "Slack",
				Channel: "C06F563PYM6",
				Command: tt.command,
				UserID:  "U12345678",
			}

			body, _ := json.Marshal(request)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/message", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			server.createMessage(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rec.Code)
			}

			if tt.expectError {
				var errResp ErrorResponse
				if err := json.NewDecoder(rec.Body).Decode(&errResp); err != nil {
					t.Fatalf("failed to decode error response: %v", err)
				}
				if tt.errorContains != "" && errResp.Error != tt.errorContains {
					t.Errorf("expected error %q, got %q", tt.errorContains, errResp.Error)
				}
			}
		})
	}
}

func TestCreateMessageBotNotFound(t *testing.T) {
	// Empty bots list - no bot registered
	bots := common.NewBots()
	server := newTestServerWithAllowedCmds(bots, []string{"help"})

	request := CreateMessageRequest{
		Bot:     "Slack",
		Channel: "C06F563PYM6",
		Command: "help",
		UserID:  "test-user",
	}

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/message", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.createMessage(rec, req)

	// Request should fail (500) because bot not found
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, rec.Code)
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if errResp.Error == "" {
		t.Error("expected non-empty error message")
	}
}

func TestCreateMessageCommandExecution(t *testing.T) {
	mockBot := NewMockBot("Slack")
	bots := common.NewBots()
	bots.Add(mockBot)

	server := newTestServerWithAllowedCmds(bots, []string{"inci/digest"})

	request := CreateMessageRequest{
		Bot:     "Slack",
		Channel: "C08FPJQH0ML",
		Command: "inci/digest period=7d",
		UserID:  "scheduler",
	}

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/message", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.createMessage(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, rec.Code)
	}

	if !mockBot.WasCommandCalled() {
		t.Error("expected bot.Command to be called")
	}

	channel, cmd := mockBot.GetLastCommand()
	if channel != "C08FPJQH0ML" {
		t.Errorf("expected channel %q, got %q", "C08FPJQH0ML", channel)
	}
	if cmd != "inci/digest period=7d" {
		t.Errorf("expected command %q, got %q", "inci/digest period=7d", cmd)
	}
}

func TestGetMessageStatus(t *testing.T) {
	mockBot := NewMockBot("Slack")
	bots := common.NewBots()
	bots.Add(mockBot)

	server := newTestServerWithAllowedCmds(bots, []string{"help"})

	// Create a message first
	request := CreateMessageRequest{
		Bot:     "Slack",
		Channel: "C06F563PYM6",
		Command: "help",
		UserID:  "test-user",
	}

	body, _ := json.Marshal(request)
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/message", bytes.NewReader(body))
	createReq.Header.Set("Content-Type", "application/json")
	createRec := httptest.NewRecorder()

	server.createMessage(createRec, createReq)

	var createResp CreateMessageResponse
	json.NewDecoder(createRec.Body).Decode(&createResp)

	// Get status - now requires bot parameter
	statusReq := httptest.NewRequest(http.MethodGet, "/api/v1/message/status?bot=Slack&id="+createResp.ID, nil)
	statusRec := httptest.NewRecorder()

	server.getMessageStatus(statusRec, statusReq)

	if statusRec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, statusRec.Code)
	}

	var statusResp GetMessageStatusResponse
	if err := json.NewDecoder(statusRec.Body).Decode(&statusResp); err != nil {
		t.Fatalf("failed to decode status response: %v", err)
	}

	if statusResp.ID != createResp.ID {
		t.Errorf("expected ID %q, got %q", createResp.ID, statusResp.ID)
	}

	if statusResp.Status != common.MessageStatusDelivered {
		t.Errorf("expected status %q, got %q", common.MessageStatusDelivered, statusResp.Status)
	}
}

func TestGetMessageStatusMissingBot(t *testing.T) {
	bots := common.NewBots()
	server := newTestServer(bots)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/message/status?id=some-id", nil)
	rec := httptest.NewRecorder()

	server.getMessageStatus(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
}

func TestGetMessageStatusMissingID(t *testing.T) {
	bots := common.NewBots()
	server := newTestServer(bots)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/message/status?bot=Slack", nil)
	rec := httptest.NewRecorder()

	server.getMessageStatus(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
}

// Note: The MockBot doesn't validate command names, so these test HTTP routing only.
var chatopsTemplateCommands = []string{
	// Root commands
	"app",
	"apps",
	"shift",
	"verification",
	"host",
	"group",
	"help",
	"show",
	"news",
	"checkup",
	"rca",
	"ntapiv2",
	"freeze",
	"report",
	"task",
	"quick",
	"endpoints",
	"catchpoint",
	"ring",
	"sms",
	"trends",
	"change",
	"loadbalancer",
	"assetalias",
	"image",
	"vm",
	"escalation",
	"incident",
	"dms-rotate",
	"notify",
	"call",
	"release",
	"test",
	"dyntest",
	"fake-release",

	// Nested commands (group/command format)
	"freeze/create",
	"dashboard/grafana",
	"dashboard/datadog",
	"host/cmd",
	"host/restart",
	"host/start",
	"host/stop",
	"runbook/ddos",
	"runbook/ban",
	"runbook/highsev",
	"runbook/inci",
	"tree/app",
	"help/digest",
	"help/host",
	"help/runbook",
	"help/highsev",
	"help/checkup",
	"help/vm",
	"message/update",
	"message/delete",
	"call/user",
	"test/site24",
	"app/add",
	"app/update",
	"prbm/digest",
	"inci/digest",
	"inci/poinc",
	"inci/create",
	"inci/message",
	"inci/po",
	"pa/list",
	"pa/stop",
	"pa/create",
	"digest/escalations",
	"ai/sum",
	"ai/title",
	"case/status",
	"case/daily",
}

func TestCreateMessageWithChatOpsTemplateCommands(t *testing.T) {
	for _, command := range chatopsTemplateCommands {
		t.Run(command, func(t *testing.T) {
			mockBot := NewMockBot("Slack")
			bots := common.NewBots()
			bots.Add(mockBot)

			// Allow this specific command
			server := newTestServerWithAllowedCmds(bots, []string{command})

			request := CreateMessageRequest{
				Bot:     "Slack",
				Channel: "C06F563PYM6",
				Command: command,
				UserID:  "api-test-user",
			}

			body, _ := json.Marshal(request)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/message", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			server.createMessage(rec, req)

			if rec.Code != http.StatusCreated {
				t.Errorf("command %s: expected status %d, got %d", command, http.StatusCreated, rec.Code)
			}

			var resp CreateMessageResponse
			if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
				t.Fatalf("command %s: failed to decode response: %v", command, err)
			}

			if resp.ID == "" {
				t.Errorf("command %s: expected non-empty message ID", command)
			}

			if !mockBot.WasCommandCalled() {
				t.Errorf("command %s: expected bot.Command to be called", command)
			}

			_, cmd := mockBot.GetLastCommand()
			if cmd != command {
				t.Errorf("command %s: expected command %q, got %q", command, command, cmd)
			}
		})
	}
}

func TestCreateMessageWithCommandParameters(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		allowedCmd string // base command name for allowlist
	}{
		{"app with name param", "app name=myapp", "app"},
		{"app with multiple params", "app name=myapp env=prod", "app"},
		{"inci create with title", "inci/create title=\"Test Incident\" severity=high", "inci/create"},
		{"host cmd with arguments", "host/cmd hostname=server1 command=\"uptime\"", "host/cmd"},
		{"freeze create with params", "freeze/create reason=\"Maintenance\" duration=2h", "freeze/create"},
		{"digest with period", "inci/digest period=24h", "inci/digest"},
		{"vm with all params", "vm name=test-vm region=us-east action=restart", "vm"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockBot := NewMockBot("Slack")
			bots := common.NewBots()
			bots.Add(mockBot)

			// Allow the base command (CommandInSlice only checks the first word)
			server := newTestServerWithAllowedCmds(bots, []string{tt.allowedCmd})

			request := CreateMessageRequest{
				Bot:     "Slack",
				Channel: "C06F563PYM6",
				Command: tt.command,
				UserID:  "test-user",
			}

			body, _ := json.Marshal(request)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/message", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			server.createMessage(rec, req)

			if rec.Code != http.StatusCreated {
				t.Errorf("expected status %d, got %d", http.StatusCreated, rec.Code)
			}

			_, cmd := mockBot.GetLastCommand()
			if cmd != tt.command {
				t.Errorf("expected command %q, got %q", tt.command, cmd)
			}
		})
	}
}
