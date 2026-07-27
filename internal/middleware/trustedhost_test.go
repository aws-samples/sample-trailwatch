package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"cloudtrail-analyzer/internal/config"
)

func TestTrustedHost(t *testing.T) {
	cfg := &config.Config{
		Port:         7070,
		TrustedHosts: []string{"analyzer.internal", "proxy.example.com:8443"},
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	h := TrustedHost(cfg)(next)

	cases := []struct {
		name       string
		host       string
		wantStatus int
	}{
		{"loopback name with port", "localhost:7070", http.StatusOK},
		{"loopback ip with port", "127.0.0.1:7070", http.StatusOK},
		{"loopback name no port", "localhost", http.StatusOK},
		{"ipv6 loopback", "[::1]:7070", http.StatusOK},
		{"configured host", "analyzer.internal", http.StatusOK},
		{"configured host with port", "analyzer.internal:7070", http.StatusOK},
		{"configured proxy host:port", "proxy.example.com:8443", http.StatusOK},
		{"rebinding attacker host", "evil.example.com", http.StatusForbidden},
		{"attacker host pointing at loopback", "attacker.com:7070", http.StatusForbidden},
		{"empty host", "", http.StatusForbidden},
		{"trailing dot loopback", "localhost.:7070", http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://placeholder/api/health", nil)
			req.Host = tc.host
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Errorf("host %q: got status %d, want %d", tc.host, rec.Code, tc.wantStatus)
			}
		})
	}
}

func TestTrustedHostWildcardDisablesCheck(t *testing.T) {
	cfg := &config.Config{Port: 7070, TrustedHosts: []string{"*"}}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := TrustedHost(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "http://placeholder/", nil)
	req.Host = "anything.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("wildcard should allow any host, got %d", rec.Code)
	}
}
