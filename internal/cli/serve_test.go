package cli

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDevelopmentHostCheck(t *testing.T) {
	for _, tt := range []struct {
		name    string
		address string
		host    string
		status  int
	}{
		{"bound_ipv4", "127.0.0.1:7843", "127.0.0.1:7843", 204},
		{"localhost_ipv4", "127.0.0.1:7843", "localhost:7843", 204},
		{"foreign_ipv4", "127.0.0.1:7843", "attacker.example:7843", 421},
		{"foreign_without_port", "127.0.0.1:7843", "attacker.example", 421},
		{"wrong_port", "127.0.0.1:7843", "127.0.0.1:7844", 421},
		{"missing_port", "127.0.0.1:7843", "localhost", 421},
		{"trailing_dot", "127.0.0.1:7843", "localhost.:7843", 421},
		{"ipv6_on_ipv4", "127.0.0.1:7843", "[::1]:7843", 421},
		{"bound_ipv6", "[::1]:7843", "[::1]:7843", 204},
		{"localhost_ipv6", "[::1]:7843", "localhost:7843", 204},
		{"foreign_ipv6", "[::1]:7843", "attacker.example:7843", 421},
		{"ipv4_on_ipv6", "[::1]:7843", "127.0.0.1:7843", 421},
	} {
		t.Run(tt.name, func(t *testing.T) {
			handler := developmentHostCheck(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(204)
			}), tt.address)
			r := httptest.NewRequest("GET", "/v1/items", nil)
			r.Host = tt.host
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != tt.status {
				t.Fatalf("Host %q: status = %d, want %d", tt.host, w.Code, tt.status)
			}
		})
	}
}
