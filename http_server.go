package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/server"
	"github.com/sirupsen/logrus"
)

// MCPSession represents a client session for HTTP transport
type MCPSession struct {
	ID            string
	APIKey        string // API Key for this session
	CreatedAt     time.Time
	LastHeartbeat time.Time
	RequestChan   chan json.RawMessage
	ResponseChan  chan json.RawMessage
	ErrorChan     chan string
	CloseOnce     sync.Once
	Closed        chan struct{}
}

// HTTPTransport handles MCP communication over HTTP using Streamable HTTP Transport
type HTTPTransport struct {
	sessions map[string]*MCPSession
	mu       sync.RWMutex
	logger   *logrus.Logger
	server   *server.MCPServer
}

// NewHTTPTransport creates a new HTTP transport handler
func NewHTTPTransport(s *server.MCPServer, logger *logrus.Logger) *HTTPTransport {
	return &HTTPTransport{
		sessions: make(map[string]*MCPSession),
		logger:   logger,
		server:   s,
	}
}

// HandleMCPRequest handles MCP requests over HTTP
// This implements the Streamable HTTP Transport specification
func (h *HTTPTransport) HandleMCPRequest(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.handlePost(w, r)
	case http.MethodGet:
		h.handleGet(w, r)
	case http.MethodDelete:
		h.handleDelete(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handlePost handles POST requests - client sends JSON-RPC messages
func (h *HTTPTransport) handlePost(w http.ResponseWriter, r *http.Request) {
	// Extract API Key from URL query parameter or Authorization header
	apiKey := r.URL.Query().Get("api_key")
	if apiKey == "" {
		// Also try to get from Authorization header
		if auth := r.Header.Get("Authorization"); auth != "" {
			apiKey = auth
		}
	}

	if apiKey == "" {
		http.Error(w, "Missing API Key", http.StatusUnauthorized)
		return
	}

	// Get or create session
	sessionID := r.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		sessionID = uuid.New().String()
	}

	session, isNewSession := h.getOrCreateSession(sessionID)

	// Set session ID in response header
	w.Header().Set("Mcp-Session-Id", sessionID)

	// Read request body
	var request json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		h.logger.Warnf("Failed to decode request body: %v", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Store API Key in the session context for access by tool handlers
	if isNewSession {
		session.APIKey = apiKey
		go h.processSession(session)
	}

	// Send request to session
	select {
	case session.RequestChan <- request:
		// Wait for response with timeout
		select {
		case response := <-session.ResponseChan:
			w.Header().Set("Content-Type", "application/json")
			w.Write(response)
		case errMsg := <-session.ErrorChan:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": errMsg})
		case <-time.After(30 * time.Second):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusGatewayTimeout)
			json.NewEncoder(w).Encode(map[string]string{"error": "Request timeout"})
		}
	case <-session.Closed:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusGone)
		json.NewEncoder(w).Encode(map[string]string{"error": "Session closed"})
	}
}

// handleGet handles GET requests - client opens SSE stream for server messages
func (h *HTTPTransport) handleGet(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		http.Error(w, "Missing Session ID", http.StatusBadRequest)
		return
	}

	h.mu.RLock()
	session, exists := h.sessions[sessionID]
	h.mu.RUnlock()

	if !exists {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Keep connection open and stream server messages
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// Initial event
	fmt.Fprintf(w, "data: {\"type\":\"initialized\"}\n\n")
	flusher.Flush()

	// Stream messages until session closes
	for {
		select {
		case <-session.Closed:
			return
		case <-r.Context().Done():
			return
		case <-time.After(30 * time.Second):
			// Send heartbeat
			fmt.Fprintf(w, "data: {\"type\":\"ping\"}\n\n")
			flusher.Flush()
		}
	}
}

// handleDelete handles DELETE requests - terminate session
func (h *HTTPTransport) handleDelete(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		http.Error(w, "Missing Session ID", http.StatusBadRequest)
		return
	}

	h.mu.Lock()
	session, exists := h.sessions[sessionID]
	if exists {
		delete(h.sessions, sessionID)
	}
	h.mu.Unlock()

	if exists {
		session.Close()
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "closed"})
	} else {
		http.Error(w, "Session not found", http.StatusNotFound)
	}
}

// getOrCreateSession gets or creates a session
func (h *HTTPTransport) getOrCreateSession(sessionID string) (*MCPSession, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if session, exists := h.sessions[sessionID]; exists {
		session.LastHeartbeat = time.Now()
		return session, false
	}

	// Create new session
	session := &MCPSession{
		ID:            sessionID,
		CreatedAt:     time.Now(),
		LastHeartbeat: time.Now(),
		RequestChan:   make(chan json.RawMessage, 1),
		ResponseChan:  make(chan json.RawMessage, 1),
		ErrorChan:     make(chan string, 1),
		Closed:        make(chan struct{}),
	}

	h.sessions[sessionID] = session
	return session, true
}

// processSession handles message processing for a session
func (h *HTTPTransport) processSession(session *MCPSession) {
	defer session.Close()

	for {
		select {
		case <-session.Closed:
			return
		case request := <-session.RequestChan:
			// Parse JSON-RPC request
			var rpcRequest struct {
				JSONRPC string          `json:"jsonrpc"`
				ID      interface{}     `json:"id"`
				Method  string          `json:"method"`
				Params  json.RawMessage `json:"params"`
			}

			if err := json.Unmarshal(request, &rpcRequest); err != nil {
				h.logger.Warnf("Failed to parse RPC request: %v", err)
				session.ErrorChan <- fmt.Sprintf("Invalid RPC request: %v", err)
				continue
			}

			// Process MCP request through server, passing API Key in context
			response, err := h.processMCPRequest(session, &rpcRequest)
			if err != nil {
				h.logger.Errorf("Failed to process MCP request: %v", err)
				session.ErrorChan <- err.Error()
			} else {
				session.ResponseChan <- response
			}
		}
	}
}

// processMCPRequest processes a single MCP request
func (h *HTTPTransport) processMCPRequest(session *MCPSession, rpcReq interface{}) (json.RawMessage, error) {
	// Process the request through the actual MCP server
	// The MCP server will route it to the appropriate tool/resource handler
	ctx := context.Background()

	// Parse the request to add API Key to arguments if needed
	var request map[string]interface{}
	requestData, err := json.Marshal(rpcReq)
	if err != nil {
		h.logger.Errorf("Failed to marshal request: %v", err)
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	if err := json.Unmarshal(requestData, &request); err != nil {
		h.logger.Errorf("Failed to unmarshal request: %v", err)
		return nil, fmt.Errorf("failed to unmarshal request: %w", err)
	}

	// Add API Key to the request parameters/arguments
	params, ok := request["params"].(map[string]interface{})
	if !ok {
		// Create params if it doesn't exist
		params = make(map[string]interface{})
		request["params"] = params
	}

	arguments, ok := params["arguments"].(map[string]interface{})
	if !ok {
		// Create arguments if it doesn't exist
		arguments = make(map[string]interface{})
		params["arguments"] = arguments
	}

	// Add API Key if it's not already there
	if _, exists := arguments["api_key"]; !exists {
		arguments["api_key"] = session.APIKey
	}

	// Marshal the modified request back to JSON to pass to the MCP server
	requestJSON, err := json.Marshal(request)
	if err != nil {
		h.logger.Errorf("Failed to marshal modified request: %v", err)
		return nil, fmt.Errorf("failed to marshal modified request: %w", err)
	}

	// Process through MCP server - HandleMessage processes JSON-RPC messages and returns a response
	responseMsg := h.server.HandleMessage(ctx, requestJSON)

	// Marshal the response back to JSON
	responseJSON, err := json.Marshal(responseMsg)
	if err != nil {
		h.logger.Errorf("Failed to marshal response: %v", err)
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	return responseJSON, nil
}

// Close closes a session
func (s *MCPSession) Close() {
	s.CloseOnce.Do(func() {
		close(s.Closed)
	})
}

// CleanupSessions periodically removes inactive sessions
func (h *HTTPTransport) CleanupSessions(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.mu.Lock()
			now := time.Now()
			for id, session := range h.sessions {
				// Close sessions inactive for more than 10 minutes
				if now.Sub(session.LastHeartbeat) > 10*time.Minute {
					session.Close()
					delete(h.sessions, id)
					h.logger.Infof("Closed inactive session: %s", id)
				}
			}
			h.mu.Unlock()
		}
	}
}
