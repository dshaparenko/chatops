package server

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/devopsext/chatops/common"
)

type HttpServerOptions struct {
	Listen      string
	AllowedCmds []string
}

type CreateMessageRequest struct {
	Bot     string `json:"bot"`     // bot name (e.g., "Slack")
	Channel string `json:"channel"` // target channel
	Command string `json:"command"` // command to execute (no leading slash)
	UserID  string `json:"user_id"` // user triggering the command (UID or email for slack)
}

type CreateMessageResponse struct {
	ID string `json:"id"` // message ID for status tracking
}

type GetMessageStatusResponse struct {
	ID     string               `json:"id"`
	Status common.MessageStatus `json:"status"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type HttpServer struct {
	options  HttpServerOptions
	obs      *common.Observability
	executor common.CommandExecutor
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

	if !common.CommandInSlice(req.Command, s.options.AllowedCmds) {
		s.writeError(w, "command not allowed", http.StatusForbidden)
		return
	}

	if req.Bot == "" || req.Channel == "" || req.Command == "" {
		s.writeError(w, "bot, channel and command are required", http.StatusBadRequest)
		return
	}

	s.obs.Info("[API] Executing command: bot=%s, channel=%s, command=%s, user=%s", req.Bot, req.Channel, req.Command, req.UserID)

	// Execute command synchronously - the bot handles all message tracking
	msg, err := s.executor.ExecuteCommand(req.Bot, req.Channel, req.Command, req.UserID)
	if err != nil {
		s.obs.Error("[API] Command execution failed: %v", err)
		s.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if msg == nil {
		s.obs.Info("[API] Command produced no trackable message")
		s.writeError(w, "command produced no message", http.StatusOK)
		return
	}

	s.obs.Info("[API] Command executed, message ID: %s", msg.ID())

	resp := CreateMessageResponse{ID: msg.ID()}
	s.writeJSON(w, resp, http.StatusCreated)
}

func (s *HttpServer) getMessageStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bot := r.URL.Query().Get("bot")
	id := r.URL.Query().Get("id")

	if bot == "" {
		s.writeError(w, "bot query parameter is required", http.StatusBadRequest)
		return
	}
	if id == "" {
		s.writeError(w, "id query parameter is required", http.StatusBadRequest)
		return
	}

	status, err := s.executor.GetMessageStatus(bot, id)
	if err != nil {
		s.obs.Error("[API] Failed to get message status: %v", err)
		s.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := GetMessageStatusResponse{
		ID:     id,
		Status: status,
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

func NewHttpServer(options HttpServerOptions, obs *common.Observability, executor common.CommandExecutor) *HttpServer {
	return &HttpServer{
		options:  options,
		obs:      obs,
		executor: executor,
	}
}
