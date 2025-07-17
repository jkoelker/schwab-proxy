package middleware_test

import (
	"net/http"
	"testing"

	"github.com/jkoelker/schwab-proxy/middleware"
)

func TestGetRealIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		expected   string
	}{
		{
			name:       "X-Real-IP present",
			headers:    map[string]string{"X-Real-IP": "192.168.1.100"},
			remoteAddr: "10.0.0.1:12345",
			expected:   "192.168.1.100",
		},
		{
			name:       "X-Forwarded-For single IP",
			headers:    map[string]string{"X-Forwarded-For": "192.168.1.100"},
			remoteAddr: "10.0.0.1:12345",
			expected:   "192.168.1.100",
		},
		{
			name:       "X-Forwarded-For multiple IPs",
			headers:    map[string]string{"X-Forwarded-For": "192.168.1.100, 10.0.0.2, 10.0.0.3"},
			remoteAddr: "10.0.0.1:12345",
			expected:   "192.168.1.100",
		},
		{
			name:       "CF-Connecting-IP present",
			headers:    map[string]string{"Cf-Connecting-Ip": "192.168.1.100"},
			remoteAddr: "10.0.0.1:12345",
			expected:   "192.168.1.100",
		},
		{
			name:       "True-Client-IP present",
			headers:    map[string]string{"True-Client-Ip": "192.168.1.100"},
			remoteAddr: "10.0.0.1:12345",
			expected:   "192.168.1.100",
		},
		{
			name:       "No headers - RemoteAddr with port",
			headers:    map[string]string{},
			remoteAddr: "192.168.1.100:12345",
			expected:   "192.168.1.100",
		},
		{
			name:       "No headers - RemoteAddr without port",
			headers:    map[string]string{},
			remoteAddr: "192.168.1.100",
			expected:   "192.168.1.100",
		},
		{
			name: "Priority: X-Real-IP over others",
			headers: map[string]string{
				"X-Real-IP":        "192.168.1.100",
				"X-Forwarded-For":  "10.0.0.100",
				"Cf-Connecting-Ip": "172.16.0.100",
			},
			remoteAddr: "10.0.0.1:12345",
			expected:   "192.168.1.100",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			req := &http.Request{
				Header:     http.Header{},
				RemoteAddr: test.remoteAddr,
			}

			for key, value := range test.headers {
				req.Header.Set(key, value)
			}

			got := middleware.GetRealIP(req)
			if got != test.expected {
				t.Errorf("GetRealIP() = %v, want %v", got, test.expected)
			}
		})
	}
}
