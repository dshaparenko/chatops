package server

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/devopsext/chatops/common"
	"github.com/google/uuid"
)

type HttpServerOptions struct {
	Listen string
}

type MessageStatus string

const (
	MessageStatusPending   MessageStatus = "pending"
	MessageStatusDelivered MessageStatus = "delivered"
	MessageStatusFailed    MessageStatus = "failed"
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
	UserID  string `json:"user_id"` // user triggering the command
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
	messages map[string]*Message
	mu       sync.RWMutex
	server   *http.Server
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

	s.mu.Lock()
	s.messages[msg.ID] = msg
	s.mu.Unlock()

	s.obs.Info("[API] Command request created: %s (bot=%s, channel=%s, command=%s)", msg.ID, msg.Bot, msg.Channel, msg.Command)

	go func() {
		err := s.executor.ExecuteCommand(msg.Bot, msg.Channel, msg.Command, msg.UserID)
		if err != nil {
			s.obs.Error("[API] Command execution failed: %s, error: %v", msg.ID, err)
			s.updateMessageStatus(msg.ID, MessageStatusFailed, err.Error())
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

	s.mu.RLock()
	msg, exists := s.messages[id]
	s.mu.RUnlock()

	if !exists {
		s.writeError(w, "message not found", http.StatusNotFound)
		return
	}

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
}

func (s *HttpServer) updateMessageStatus(id string, status MessageStatus, errMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if msg, exists := s.messages[id]; exists {
		msg.Status = status
		msg.Error = errMsg
	}
}

func NewHttpServer(options HttpServerOptions, obs *common.Observability, executor common.CommandExecutor) *HttpServer {
	return &HttpServer{
		options:  options,
		obs:      obs,
		executor: executor,
		messages: make(map[string]*Message),
	}
}
