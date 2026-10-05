package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadValidConfig(t *testing.T) {
	path := writeConfig(t, `
listen: ":8443"
upstream: "http://user:secret@proxy.example:7890"
allowed_hosts:
  - Vector.OpenStreetMap.Org.
  - tile.openstreetmap.org
timeouts:
  client_hello: 10s
  connect: 5s
  proxy_handshake: 1500ms
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Listen != ":8443" {
		t.Fatalf("Listen = %q", cfg.Listen)
	}
	if cfg.Upstream.Host != "proxy.example:7890" {
		t.Fatalf("Upstream.Host = %q", cfg.Upstream.Host)
	}
	if _, ok := cfg.AllowedHosts["vector.openstreetmap.org"]; !ok {
		t.Fatal("normalized vector host is not allowed")
	}
	if cfg.Timeouts.ProxyHandshake != 1500*time.Millisecond {
		t.Fatalf("ProxyHandshake = %v", cfg.Timeouts.ProxyHandshake)
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	path := writeConfig(t, `
listen: ":443"
upstream: "http://proxy.example:7890"
allowed_hosts: []
timeouts:
  client_hello: 10s
  connect: 5s
  proxy_handshake: 10s
unexpected: true
`)

	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "field unexpected not found") {
		t.Fatalf("Load() error = %v, want unknown-field error", err)
	}
}

func TestLoadRejectsUnsafeOrAmbiguousValues(t *testing.T) {
	tests := []struct {
		name    string
		replace string
		with    string
	}{
		{name: "unsupported proxy", replace: "http://proxy.example:7890", with: "socks5://proxy.example:7890"},
		{name: "missing proxy port", replace: "http://proxy.example:7890", with: "http://proxy.example"},
		{name: "wildcard host", replace: "vector.openstreetmap.org", with: "*.openstreetmap.org"},
		{name: "duplicate host", replace: "  - tile.openstreetmap.org", with: "  - vector.openstreetmap.org"},
		{name: "zero timeout", replace: "client_hello: 10s", with: "client_hello: 0s"},
	}
	base := `listen: ":443"
upstream: "http://proxy.example:7890"
allowed_hosts:
  - vector.openstreetmap.org
  - tile.openstreetmap.org
timeouts:
  client_hello: 10s
  connect: 5s
  proxy_handshake: 10s
`
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfig(t, strings.Replace(base, tt.replace, tt.with, 1))
			if _, err := Load(path); err == nil {
				t.Fatal("Load() succeeded, want error")
			}
		})
	}
}

func TestNormalizeHostnameRejectsIPAndInvalidLabels(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "bad_host.example", "-bad.example", "bad-.example", " host.example"} {
		t.Run(host, func(t *testing.T) {
			if _, err := NormalizeHostname(host); err == nil {
				t.Fatalf("NormalizeHostname(%q) succeeded, want error", host)
			}
		})
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
