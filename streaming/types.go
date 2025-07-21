package streaming

import (
	"encoding/json"
	"time"
)

// Request represents a streaming API request.
type Request struct {
	Service    string         `json:"service"`
	Command    string         `json:"command"`
	RequestID  string         `json:"requestid"`
	Parameters map[string]any `json:"parameters,omitempty"`

	//nolint:tagliatelle // Required by Schwab API
	SchwabClientCustomerID string `json:"SchwabClientCustomerId,omitempty"`

	//nolint:tagliatelle // Required by Schwab API
	SchwabClientCorrelID string `json:"SchwabClientCorrelId,omitempty"`
}

// RequestBatch wraps multiple requests.
type RequestBatch struct {
	Requests []Request `json:"requests"`
}

// Response represents a streaming API response.
type Response struct {
	Response []ResponseItem `json:"response,omitempty"`
	Data     []DataItem     `json:"data,omitempty"`
	Notify   []NotifyItem   `json:"notify,omitempty"`
}

// ResponseItem represents a single response.
type ResponseItem struct {
	Service   string          `json:"service"`
	RequestID string          `json:"requestid"`
	Command   string          `json:"command"`
	Timestamp int64           `json:"timestamp"`
	Content   ResponseContent `json:"content"`

	//nolint:tagliatelle // Required by Schwab API
	SchwabClientCorrelID string `json:"SchwabClientCorrelId,omitempty"`
}

// ResponseContent represents response content.
type ResponseContent struct {
	Code int    `json:"code"`
	Msg  string `json:"msg,omitempty"`
}

// DataItem represents streaming data.
type DataItem struct {
	Service   string          `json:"service"`
	Timestamp int64           `json:"timestamp"`
	Command   string          `json:"command"`
	Content   json.RawMessage `json:"content"`
}

// NotifyItem represents a notification.
type NotifyItem struct {
	Service   string          `json:"service,omitempty"`
	Timestamp int64           `json:"timestamp,omitempty"`
	Content   json.RawMessage `json:"content,omitempty"`
	Heartbeat string          `json:"heartbeat,omitempty"`
}

// Metadata represents streaming service metadata.
type Metadata struct {
	CorrelID    string    `json:"correl_id"`
	CustomerID  string    `json:"customer_id"`
	Channel     string    `json:"channel"`
	FunctionID  string    `json:"function_id"`
	WSEndpoint  string    `json:"ws_endpoint"`
	ExtractedAt time.Time `json:"extracted_at"`

	TTL time.Duration
}
