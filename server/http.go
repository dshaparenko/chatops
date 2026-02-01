package server

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/devopsext/chatops/common"
	"github.com/google/uuid"
	"github.com/jellydator/ttlcache/v3"
)

const defaultMessageTTL = time.Hour

type HttpServerOptions struct {
	Listen      string
	AllowedCmds []string
	MessageTTL  string
}

type MessageStatus string

const (
	MessageStatusPending         MessageStatus = "pending"
	MessageStatusDelivered       MessageStatus = "delivered"
	MessageStatusFailed          MessageStatus = "failed"
	MessageStatusWaitingApproval MessageStatus = "waiting_approval"
)

type Message struct {
	ID        string        `json:"id"`
	Bot       string        `json:"bot"`
	Channel   string        `json:"channel"`
	Command   string        `json:"command"`
	UserID    string        `json:"user_id"`
	Status    MessageStatus `json:"status"`
	CreatedAt time.Time     `json:"created_at"`
	Error     string        `json:"error,omitempty"`
}

type CreateMessageRequest struct {
	Bot     string `json:"bot"`     // bot name (e.g., "Slack")
	Channel string `json:"channel"` // target channel
	Command string `json:"command"` // command to execute (no leading slash)
	UserID  string `json:"user_id"` // user triggering the command (UID or email for slack)
}

type CreateMessageResponse struct {
	ID string `json:"id"`
}

type GetMessageStatusResponse struct {
	ID        string        `json:"id"`
	Status    MessageStatus `json:"status"`
	CreatedAt time.Time     `json:"created_at"`
	Error     string        `json:"error,omitempty"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type HttpServer struct {
	options  HttpServerOptions
	obs      *common.Observability
	executor common.CommandExecutor
	messages *ttlcache.Cache[string, *Message]
	server   *http.Server
}

// messageStatusNotifier implements common.StatusNotifier for async status updates
type messageStatusNotifier struct {
	server    *HttpServer
	messageID string
}

func (n *messageStatusNotifier) OnComplete(success bool, err error) {
	if success {
		n.server.obs.Info("[API] Command completed after approval: %s", n.messageID)
		n.server.updateMessageStatus(n.messageID, MessageStatusDelivered, "")
	} else {
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}
		n.server.obs.Error("[API] Command failed after approval: %s, error: %v", n.messageID, err)
		n.server.updateMessageStatus(n.messageID, MessageStatusFailed, errMsg)
	}
}

func (s *HttpServer) createMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CreateMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if !common.CommandInSlice(req.Command, s.options.AllowedCmds) {
		s.writeError(w, "command not allowed", http.StatusForbidden)
		return
	}

	if req.Bot == "" || req.Channel == "" || req.Command == "" {
		s.writeError(w, "bot, channel and command are required", http.StatusBadRequest)
		return
	}

	msg := &Message{
		ID:        uuid.New().String(),
		Bot:       req.Bot,
		Channel:   req.Channel,
		Command:   req.Command,
		UserID:    req.UserID,
		Status:    MessageStatusPending,
		CreatedAt: time.Now(),
	}

	s.messages.Set(msg.ID, msg, ttlcache.DefaultTTL)

	s.obs.Info("[API] Command request created: %s (bot=%s, channel=%s, command=%s)", msg.ID, msg.Bot, msg.Channel, msg.Command)

	notifier := &messageStatusNotifier{
		server:    s,
		messageID: msg.ID,
	}

	go func() {
		err := s.executor.ExecuteCommand(msg.Bot, msg.Channel, msg.Command, msg.UserID, notifier)
		if err != nil {
			if err.Error() == "approval pending" {
				s.obs.Info("[API] Command waiting for approval: %s", msg.ID)
				s.updateMessageStatus(msg.ID, MessageStatusWaitingApproval, "")
			} else {
				s.obs.Error("[API] Command execution failed: %s, error: %v", msg.ID, err)
				s.updateMessageStatus(msg.ID, MessageStatusFailed, err.Error())
			}
		} else {
			s.obs.Info("[API] Command executed: %s", msg.ID)
			s.updateMessageStatus(msg.ID, MessageStatusDelivered, "")
		}
	}()

	resp := CreateMessageResponse{ID: msg.ID}
	s.writeJSON(w, resp, http.StatusCreated)
}

func (s *HttpServer) getMessageStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		s.writeError(w, "id query parameter is required", http.StatusBadRequest)
		return
	}

	item := s.messages.Get(id)
	if item == nil {
		s.writeError(w, "message not found", http.StatusNotFound)
		return
	}
	msg := item.Value()

	resp := GetMessageStatusResponse{
		ID:        msg.ID,
		Status:    msg.Status,
		CreatedAt: msg.CreatedAt,
		Error:     msg.Error,
	}
	s.writeJSON(w, resp, http.StatusOK)
}

func (s *HttpServer) writeJSON(w http.ResponseWriter, data any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (s *HttpServer) writeError(w http.ResponseWriter, message string, status int) {
	s.writeJSON(w, ErrorResponse{Error: message}, status)
}

func (s *HttpServer) Start(wg *sync.WaitGroup) {
	if s.options.Listen == "" {
		return
	}

	wg.Add(1)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/message", s.createMessage)
	mux.HandleFunc("/api/v1/message/status", s.getMessageStatus)

	s.server = &http.Server{
		Addr:    s.options.Listen,
		Handler: mux,
	}

	go func() {
		defer wg.Done()
		s.obs.Info("HTTP server starting on %s", s.options.Listen)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.obs.Error("HTTP server error: %v", err)
		}
	}()
}

func (s *HttpServer) Stop() {
	if s.server != nil {
		s.obs.Info("HTTP server stopping...")
		s.server.Close()
	}
	if s.messages != nil {
		s.messages.Stop()
	}
}

func (s *HttpServer) updateMessageStatus(id string, status MessageStatus, errMsg string) {
	item := s.messages.Get(id)
	if item != nil {
		msg := item.Value()
		msg.Status = status
		msg.Error = errMsg
	}
}

func NewHttpServer(options HttpServerOptions, obs *common.Observability, executor common.CommandExecutor) *HttpServer {
	ttl := defaultMessageTTL
	if options.MessageTTL != "" {
		if parsed, err := time.ParseDuration(options.MessageTTL); err == nil {
			ttl = parsed
		} else if obs != nil {
			obs.Error("[API] Invalid message TTL %q, using default %v: %v", options.MessageTTL, defaultMessageTTL, err)
		}
	}

	messages := ttlcache.New(
		ttlcache.WithTTL[string, *Message](ttl),
	)
	go messages.Start() // Start automatic cleanup

	return &HttpServer{
		options:  options,
		obs:      obs,
		executor: executor,
		messages: messages,
	}
}
