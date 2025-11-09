package streaming

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/jkoelker/schwab-proxy/auth"
	"github.com/jkoelker/schwab-proxy/log"
)

const (
	readBufferSize  = 1024
	writeBufferSize = 1024
	maxMessageSize  = 10 * 1024 * 1024 // 10MB

	authTimeout  = 30 * time.Second
	readTimeout  = 60 * time.Second
	writeTimeout = 10 * time.Second
	pingInterval = 30 * time.Second
	pongWait     = 60 * time.Second

	clientChannelSize = 100

	reconnectStartInterval = 1 * time.Second
	// Error codes.
	codeInvalidJSON      = 1
	codeNotAuthenticated = 3
	codeServiceError     = 22
	// Connection timeouts.
	handshakeTimeout = 10 * time.Second
)

var (
	ErrMasterConnectionNotAvailable = errors.New("master connection not available")
	ErrLoginFailed                  = errors.New("LOGIN failed")
)

// Proxy manages WebSocket connections between clients and Schwab.
type Proxy struct {
	// Dependencies
	tokenManager auth.TokenServicer
	authServer   *auth.Server
	metadataFunc func() (*Metadata, error)

	// Master connection
	masterConn     *websocket.Conn
	masterMu       sync.RWMutex
	reconnectDelay time.Duration

	// Client tracking
	clients *ClientMap

	// Lifecycle
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Client represents a connected WebSocket client.
type Client struct {
	id      string
	conn    *websocket.Conn
	info    ClientInfo
	authed  bool
	msgChan chan json.RawMessage
	done    chan struct{}
}

// ClientInfo represents authenticated client information.
type ClientInfo struct {
	ClientID string
	Scopes   []string
}

// NewProxy creates a new streaming proxy.
func NewProxy(
	tokenManager auth.TokenServicer,
	authServer *auth.Server,
	metadataFunc func() (*Metadata, error),
) *Proxy {
	return &Proxy{
		tokenManager:   tokenManager,
		authServer:     authServer,
		metadataFunc:   metadataFunc,
		clients:        NewClientMap(),
		reconnectDelay: reconnectStartInterval,
	}
}

// Start begins the streaming proxy operations.
func (sp *Proxy) Start(ctx context.Context) error {
	// Don't store context, just store the cancel function
	_, cancel := context.WithCancel(ctx)
	sp.cancel = cancel

	return nil
}

// Shutdown gracefully shuts down the streaming proxy.
func (sp *Proxy) Shutdown(ctx context.Context) error {
	log.Info(ctx, "Stopping streaming proxy")

	// Cancel context
	if sp.cancel != nil {
		sp.cancel()
	}

	// Close master connection
	sp.masterMu.Lock()

	if sp.masterConn != nil {
		sp.masterConn.Close()
	}

	sp.masterMu.Unlock()

	// Close all client connections
	sp.clients.Range(func(_ string, client *Client) bool {
		close(client.done)
		client.conn.Close()

		return true
	})

	// Wait for goroutines
	sp.wg.Wait()

	return nil
}

// HandleWebSocket handles incoming WebSocket connections from clients.
func (sp *Proxy) HandleWebSocket(writer http.ResponseWriter, req *http.Request) {
	// Upgrade connection
	upgrader := websocket.Upgrader{
		ReadBufferSize:  readBufferSize,
		WriteBufferSize: writeBufferSize,
		CheckOrigin: func(_ *http.Request) bool {
			return true // Configure based on security needs
		},
	}

	conn, err := upgrader.Upgrade(writer, req, nil)
	if err != nil {
		log.Error(req.Context(), err, "Failed to upgrade WebSocket")

		return
	}

	// Create client
	clientID := "client_" + uuid.New().String()
	client := &Client{
		id:      clientID,
		conn:    conn,
		msgChan: make(chan json.RawMessage, clientChannelSize),
		done:    make(chan struct{}),
	}

	// Register client
	sp.clients.Store(clientID, client)

	// Create a context for the client that isn't tied to the HTTP request
	// Use WithoutCancel to inherit values but not cancellation from the HTTP request
	clientCtx, clientCancel := context.WithCancel(context.WithoutCancel(req.Context()))

	// Ensure master connection exists
	if err := sp.ensureMasterConnection(clientCtx); err != nil {
		log.Error(clientCtx, err, "Failed to establish master connection")

		_ = conn.WriteJSON(map[string]string{"error": "Service unavailable"})

		conn.Close()
		clientCancel()

		return
	}

	// Handle client connection
	sp.wg.Add(1)

	go func() {
		defer clientCancel()

		sp.handleClient(clientCtx, client)
	}()
}

// GetConnectionState returns the current master connection state.
func (sp *Proxy) GetConnectionState() string {
	sp.masterMu.RLock()
	defer sp.masterMu.RUnlock()

	if sp.masterConn != nil {
		return "connected"
	}

	return "disconnected"
}

// GetClientCount returns the number of connected clients.
func (sp *Proxy) GetClientCount() int {
	return sp.clients.Count()
}

// GetLastHeartbeat returns the last heartbeat time (not implemented in simplified version).
func (sp *Proxy) GetLastHeartbeat() time.Time {
	return time.Now() // Simplified - could track if needed
}

// handleClient manages a client connection lifecycle.
func (sp *Proxy) handleClient(ctx context.Context, client *Client) {
	defer sp.wg.Done()
	defer func() {
		// Cleanup
		close(client.done)
		client.conn.Close()

		sp.clients.Delete(client.id)

		log.Info(ctx, "Client disconnected", "client_id", client.id)
	}()

	log.Info(ctx, "Client connected", "client_id", client.id)

	// Start write loop
	go sp.clientWriteLoop(client)

	// Set auth timeout
	authTimer := time.NewTimer(authTimeout)
	defer authTimer.Stop()

	// Configure connection
	client.conn.SetReadLimit(maxMessageSize)
	_ = client.conn.SetReadDeadline(time.Now().Add(readTimeout))

	client.conn.SetPongHandler(func(string) error {
		return client.conn.SetReadDeadline(time.Now().Add(readTimeout))
	})

	// Read loop
	for {
		select {
		case <-ctx.Done():
			return
		case <-authTimer.C:
			if !client.authed {
				log.Info(ctx, "Client auth timeout", "client_id", client.id)

				return
			}

		default:
		}

		_, message, err := client.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(
				err,
				websocket.CloseGoingAway,
				websocket.CloseAbnormalClosure,
			) {
				log.Error(ctx, err, "WebSocket read error", "client_id", client.id)
			}

			return
		}

		// Process message
		if err := sp.processClientMessage(ctx, client, message); err != nil {
			log.Error(ctx, err, "Failed to process message", "client_id", client.id)
		}
	}
}

// clientWriteLoop sends messages to a client.
func (sp *Proxy) clientWriteLoop(client *Client) {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-client.done:
			return

		case msg := <-client.msgChan:
			_ = client.conn.SetWriteDeadline(time.Now().Add(writeTimeout))

			if err := client.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}

		case <-ticker.C:
			_ = client.conn.SetWriteDeadline(time.Now().Add(writeTimeout))

			if err := client.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// processClientMessage handles a message from a client.
func (sp *Proxy) processClientMessage(ctx context.Context, client *Client, message []byte) error {
	// Parse request
	var req RequestBatch
	if err := json.Unmarshal(message, &req); err != nil {
		return sp.sendErrorResponse(client, "", "ADMIN", "", codeInvalidJSON, "Invalid JSON")
	}

	// Process each command
	for _, cmd := range req.Requests {
		// Handle LOGIN specially
		if cmd.Service == "ADMIN" && cmd.Command == "LOGIN" {
			if err := sp.handleClientLogin(ctx, client, cmd); err != nil {
				return err
			}

			continue
		}

		// Require auth for other commands
		if !client.authed {
			return sp.sendErrorResponse(
				client,
				cmd.RequestID,
				cmd.Service,
				cmd.Command,
				codeNotAuthenticated,
				"Not authenticated",
			)
		}

		// Store original request ID before prefixing
		originalRequestID := cmd.RequestID

		// Forward to master with client ID prefix
		cmd.RequestID = PrefixRequestID(client.id, cmd.RequestID)
		if err := sp.forwardToMaster(ctx, cmd); err != nil {
			return sp.sendErrorResponse(
				client,
				originalRequestID,
				cmd.Service,
				cmd.Command,
				codeServiceError,
				"Service error",
			)
		}
	}

	return nil
}

// handleClientLogin processes a client LOGIN command.
func (sp *Proxy) handleClientLogin(ctx context.Context, client *Client, cmd Request) error {
	// Extract token
	authToken, ok := cmd.Parameters["Authorization"].(string)
	if !ok {
		return sp.sendErrorResponse(
			client,
			cmd.RequestID,
			cmd.Service,
			cmd.Command,
			codeInvalidJSON,
			"Missing Authorization",
		)
	}

	// Validate proxy JWT
	clientID, scopes, err := sp.authServer.ValidateAccessToken(ctx, authToken)
	if err != nil {
		return sp.sendErrorResponse(
			client,
			cmd.RequestID,
			cmd.Service,
			cmd.Command,
			codeNotAuthenticated,
			"Invalid token",
		)
	}

	// Mark as authenticated
	client.info = ClientInfo{ClientID: clientID, Scopes: scopes}
	client.authed = true

	// Send success response
	response := Response{
		Response: []ResponseItem{{
			Service:              cmd.Service,
			Command:              cmd.Command,
			RequestID:            cmd.RequestID,
			SchwabClientCorrelID: cmd.SchwabClientCorrelID,
			Timestamp:            time.Now().UnixMilli(),
			Content: ResponseContent{
				Code: 0,
				Msg:  "Login successful",
			},
		}},
	}

	data, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	select {
	case client.msgChan <- data:
		return nil

	case <-client.done:
		return nil
	}
}

// sendErrorResponse sends an error response to a client.
func (sp *Proxy) sendErrorResponse(
	client *Client,
	reqID string,
	service string,
	command string,
	code int,
	msg string,
) error {
	response := Response{
		Response: []ResponseItem{{
			Service:   service,
			Command:   command,
			RequestID: reqID,
			Timestamp: time.Now().UnixMilli(),
			Content: ResponseContent{
				Code: code,
				Msg:  msg,
			},
		}},
	}

	data, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	select {
	case client.msgChan <- data:
		return nil

	case <-client.done:
		return nil
	}
}

// forwardToMaster sends a command to the master connection.
func (sp *Proxy) forwardToMaster(ctx context.Context, cmd Request) error {
	// First attempt with existing connection
	sp.masterMu.RLock()
	conn := sp.masterConn
	sp.masterMu.RUnlock()

	if conn == nil {
		// Try to reconnect
		if err := sp.ensureMasterConnection(ctx); err != nil {
			return fmt.Errorf("master connection unavailable: %w", err)
		}

		// Get connection again after reconnect
		sp.masterMu.RLock()
		conn = sp.masterConn
		sp.masterMu.RUnlock()

		if conn == nil {
			return ErrMasterConnectionNotAvailable
		}
	}

	req := RequestBatch{Requests: []Request{cmd}}

	if err := conn.WriteJSON(req); err != nil {
		// Connection might be stale, mark it as closed
		sp.masterMu.Lock()

		if sp.masterConn == conn {
			sp.masterConn = nil
		}

		sp.masterMu.Unlock()

		return fmt.Errorf("failed to forward command to master: %w", err)
	}

	return nil
}

// ensureMasterConnection establishes master connection if needed.
func (sp *Proxy) ensureMasterConnection(ctx context.Context) error {
	sp.masterMu.Lock()
	defer sp.masterMu.Unlock()

	// Already connected
	if sp.masterConn != nil {
		return nil
	}

	// Get metadata
	metadata, err := sp.metadataFunc()
	if err != nil {
		return fmt.Errorf("failed to get metadata: %w", err)
	}

	// Connect to Schwab
	dialer := websocket.Dialer{
		HandshakeTimeout: handshakeTimeout,
	}

	conn, resp, err := dialer.Dial(metadata.WSEndpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}

	sp.masterConn = conn

	// Configure connection timeouts and handlers
	conn.SetReadLimit(maxMessageSize)
	_ = conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(pongWait))
	})

	// Authenticate master connection
	if err := sp.authenticateMaster(ctx, metadata); err != nil {
		sp.masterConn.Close()
		sp.masterConn = nil

		return err
	}

	// Start master read loop
	sp.wg.Add(1)

	go sp.masterReadLoop(ctx)

	log.Info(ctx, "Master connection established")

	return nil
}

// authenticateMaster sends LOGIN to Schwab.
func (sp *Proxy) authenticateMaster(ctx context.Context, metadata *Metadata) error {
	token, err := sp.tokenManager.GetProviderToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}

	loginCmd := RequestBatch{
		Requests: []Request{{
			Service:                "ADMIN",
			Command:                "LOGIN",
			RequestID:              "master_login",
			SchwabClientCustomerID: metadata.CustomerID,
			SchwabClientCorrelID:   metadata.CorrelID,
			Parameters: map[string]any{
				"Authorization":          token.AccessToken,
				"SchwabClientChannel":    metadata.Channel,
				"SchwabClientFunctionId": metadata.FunctionID,
			},
		}},
	}

	if err := sp.masterConn.WriteJSON(loginCmd); err != nil {
		return fmt.Errorf("failed to send LOGIN: %w", err)
	}

	// Wait for response
	_ = sp.masterConn.SetReadDeadline(time.Now().Add(authTimeout))

	var response Response
	if err := sp.masterConn.ReadJSON(&response); err != nil {
		return fmt.Errorf("failed to read LOGIN response: %w", err)
	}

	if len(response.Response) == 0 || response.Response[0].Content.Code != 0 {
		return ErrLoginFailed
	}

	return nil
}

// masterReadLoop reads messages from master and routes to appropriate clients.
func (sp *Proxy) masterReadLoop(ctx context.Context) {
	defer sp.wg.Done()
	defer sp.cleanupMasterConnection(ctx)

	// Get the connection to pass to the reader goroutine
	sp.masterMu.RLock()
	conn := sp.masterConn
	sp.masterMu.RUnlock()

	if conn == nil {
		log.Error(ctx, nil, "Master connection is nil in read loop")

		return
	}

	// Start ping ticker to keep connection alive
	pingTicker := time.NewTicker(pingInterval)
	defer pingTicker.Stop()

	// Create a channel for read messages
	const readChannelSize = 10

	msgChan := make(chan []byte, readChannelSize)
	errChan := make(chan error, 1)

	// Start goroutine to read messages
	go sp.readMasterMessages(conn, msgChan, errChan)

	for {
		select {
		case <-ctx.Done():
			return
		case <-pingTicker.C:
			if err := sp.sendMasterPing(ctx); err != nil {
				return
			}

		case err := <-errChan:
			log.Error(ctx, err, "Master connection read error")

			return
		case message := <-msgChan:
			// Route message to appropriate client(s)
			sp.routeMessage(ctx, message)
		}
	}
}

// cleanupMasterConnection handles cleanup when master connection is lost.
func (sp *Proxy) cleanupMasterConnection(ctx context.Context) {
	sp.masterMu.Lock()

	if sp.masterConn != nil {
		sp.masterConn.Close()
		sp.masterConn = nil
	}

	sp.masterMu.Unlock()

	// Trigger reconnection if context not cancelled
	select {
	case <-ctx.Done():
		// Shutting down, don't reconnect
	default:
		log.Info(ctx, "Master connection lost, will attempt reconnection")
	}
}

// readMasterMessages reads messages from the master connection.
func (sp *Proxy) readMasterMessages(conn *websocket.Conn, msgChan chan<- []byte, errChan chan<- error) {
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			errChan <- err

			return
		}

		// Reset read deadline on any message (including heartbeats)
		_ = conn.SetReadDeadline(time.Now().Add(pongWait))

		msgChan <- message
	}
}

// sendMasterPing sends a ping message to the master connection.
func (sp *Proxy) sendMasterPing(ctx context.Context) error {
	sp.masterMu.RLock()
	conn := sp.masterConn
	sp.masterMu.RUnlock()

	if conn != nil {
		_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))

		if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
			log.Error(ctx, err, "Failed to send ping to master")

			return fmt.Errorf("failed to send ping to master: %w", err)
		}
	}

	return nil
}

// routeMessage routes a message from master to the appropriate client(s).
func (sp *Proxy) routeMessage(ctx context.Context, message []byte) {
	// Try to parse the message to check if it's a response
	var resp Response
	if err := json.Unmarshal(message, &resp); err != nil {
		// If it's not a valid response, broadcast to all clients
		sp.broadcastToClients(message)

		return
	}

	// Check if this is a routable response message
	if !sp.isRoutableResponse(resp) {
		// For data/notify messages or messages without routing info, broadcast to all
		sp.broadcastToClients(message)

		return
	}

	// Route to specific client based on request ID
	sp.routeToSpecificClient(ctx, resp, message)
}

// isRoutableResponse checks if a response can be routed to a specific client.
func (sp *Proxy) isRoutableResponse(resp Response) bool {
	return len(resp.Response) > 0 && resp.Response[0].RequestID != ""
}

// routeToSpecificClient routes a response to a specific client based on request ID.
func (sp *Proxy) routeToSpecificClient(ctx context.Context, resp Response, originalMessage []byte) {
	requestID := resp.Response[0].RequestID

	// Extract client ID and original request ID
	clientID, originalRequestID, err := UnprefixRequestID(requestID)
	if err != nil {
		// Not a client-prefixed request ID, broadcast instead
		sp.broadcastToClients(originalMessage)

		return
	}

	// Restore original request ID
	resp.Response[0].RequestID = originalRequestID

	// Re-marshal with original request ID
	modifiedMsg, err := json.Marshal(resp)
	if err != nil {
		log.Error(ctx, err, "Failed to marshal modified response")

		return
	}

	// Send to specific client
	sp.sendToClient(ctx, clientID, modifiedMsg)
}

// sendToClient sends a message to a specific client.
func (sp *Proxy) sendToClient(ctx context.Context, clientID string, message []byte) {
	client, exists := sp.clients.Load(clientID)
	if !exists || !client.authed {
		return
	}

	select {
	case client.msgChan <- message:
		// Message sent successfully
	default:
		log.Warn(ctx, "Client channel full", "client_id", clientID)
	}
}

// broadcastToClients sends a message to all authenticated clients.
func (sp *Proxy) broadcastToClients(message []byte) {
	sp.clients.Range(func(_ string, client *Client) bool {
		if client.authed {
			select {
			case client.msgChan <- message:
			// Client channel full, skip
			default:
			}
		}

		return true
	})
}
