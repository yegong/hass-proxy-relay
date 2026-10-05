package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the validated runtime configuration.
type Config struct {
	Listen       string
	Upstream     *url.URL
	AllowedHosts map[string]struct{}
	Timeouts     Timeouts
}

type Timeouts struct {
	ClientHello    time.Duration
	Connect        time.Duration
	ProxyHandshake time.Duration
}

type fileConfig struct {
	Listen       string       `yaml:"listen"`
	Upstream     string       `yaml:"upstream"`
	AllowedHosts []string     `yaml:"allowed_hosts"`
	Timeouts     fileTimeouts `yaml:"timeouts"`
}

type fileTimeouts struct {
	ClientHello    string `yaml:"client_hello"`
	Connect        string `yaml:"connect"`
	ProxyHandshake string `yaml:"proxy_handshake"`
}

// Load reads one YAML document from path and validates all values before
// returning a runtime configuration.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	decoder := yaml.NewDecoder(f)
	decoder.KnownFields(true)

	var raw fileConfig
	if err := decoder.Decode(&raw); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("config is empty")
		}
		return nil, fmt.Errorf("decode config: %w", err)
	}

	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return nil, errors.New("config must contain exactly one YAML document")
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode trailing config data: %w", err)
	}

	return validate(raw)
}

func validate(raw fileConfig) (*Config, error) {
	if err := validateListen(raw.Listen); err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	upstream, err := validateUpstream(raw.Upstream)
	if err != nil {
		return nil, fmt.Errorf("upstream: %w", err)
	}

	allowed := make(map[string]struct{}, len(raw.AllowedHosts))
	for i, host := range raw.AllowedHosts {
		normalized, err := NormalizeHostname(host)
		if err != nil {
			return nil, fmt.Errorf("allowed_hosts[%d]: %w", i, err)
		}
		if _, exists := allowed[normalized]; exists {
			return nil, fmt.Errorf("allowed_hosts[%d]: duplicate host %q", i, normalized)
		}
		allowed[normalized] = struct{}{}
	}

	clientHello, err := positiveDuration("client_hello", raw.Timeouts.ClientHello)
	if err != nil {
		return nil, err
	}
	connect, err := positiveDuration("connect", raw.Timeouts.Connect)
	if err != nil {
		return nil, err
	}
	proxyHandshake, err := positiveDuration("proxy_handshake", raw.Timeouts.ProxyHandshake)
	if err != nil {
		return nil, err
	}

	return &Config{
		Listen:       raw.Listen,
		Upstream:     upstream,
		AllowedHosts: allowed,
		Timeouts: Timeouts{
			ClientHello:    clientHello,
			Connect:        connect,
			ProxyHandshake: proxyHandshake,
		},
	}, nil
}

func validateListen(address string) error {
	if address == "" {
		return errors.New("must not be empty")
	}
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("must be a host:port address: %w", err)
	}
	return validatePort(port)
}

func validateUpstream(value string) (*url.URL, error) {
	if value == "" {
		return nil, errors.New("must not be empty")
	}
	u, err := url.Parse(value)
	if err != nil {
		return nil, errors.New("invalid URL syntax")
	}
	if u.Scheme != "http" {
		return nil, fmt.Errorf("unsupported scheme %q (only http is supported)", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, errors.New("host must not be empty")
	}
	if u.Port() == "" {
		return nil, errors.New("port must be specified")
	}
	if err := validatePort(u.Port()); err != nil {
		return nil, err
	}
	if u.Path != "" && u.Path != "/" {
		return nil, errors.New("path is not allowed")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("query and fragment are not allowed")
	}
	if u.User != nil && strings.Contains(u.User.Username(), ":") {
		return nil, errors.New("proxy username must not contain a colon")
	}
	return u, nil
}

func validatePort(value string) error {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %q", value)
	}
	return nil
}

func positiveDuration(name, value string) (time.Duration, error) {
	if value == "" {
		return 0, fmt.Errorf("timeouts.%s must not be empty", name)
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("timeouts.%s: %w", name, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("timeouts.%s must be positive", name)
	}
	return d, nil
}

// NormalizeHostname produces the comparison form used for both configured
// hosts and SNI values. It accepts DNS hostnames only: no IPs, ports or
// wildcard labels.
func NormalizeHostname(host string) (string, error) {
	if host == "" {
		return "", errors.New("host must not be empty")
	}
	if host != strings.TrimSpace(host) {
		return "", errors.New("host must not contain surrounding whitespace")
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if len(host) == 0 || len(host) > 253 {
		return "", errors.New("host length is invalid")
	}
	if net.ParseIP(host) != nil {
		return "", errors.New("IP addresses are not allowed")
	}

	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", errors.New("DNS label length is invalid")
		}
		for i := range len(label) {
			c := label[i]
			alphanumeric := c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
			if !alphanumeric && !(c == '-' && i > 0 && i < len(label)-1) {
				return "", fmt.Errorf("invalid DNS hostname %q", host)
			}
		}
	}
	return host, nil
}
