// Command relay-smoke performs live, non-destructive checks against the
// upstream proxy configured for hass-proxy-relay. It starts a relay bound only
// to a temporary loopback port; it never binds the configured production
// listen address.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"time"

	"github.com/yegong/hass-proxy-relay/internal/config"
	"github.com/yegong/hass-proxy-relay/internal/proxy"
	"github.com/yegong/hass-proxy-relay/internal/relay"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(logger); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	var configPath string
	var overallTimeout time.Duration
	flag.StringVar(&configPath, "c", "", "path to the local YAML configuration file (required)")
	flag.DurationVar(&overallTimeout, "timeout", 2*time.Minute, "maximum duration for the complete smoke test")
	flag.Parse()
	if configPath == "" {
		return errors.New("-c is required")
	}
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", flag.Args())
	}
	if overallTimeout <= 0 {
		return errors.New("-timeout must be positive")
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("config check: %w", err)
	}
	if len(cfg.AllowedHosts) == 0 {
		return errors.New("config check: allowed_hosts is empty; no permitted target can be tested")
	}
	fmt.Printf("PASS config: listen=%s upstream=%s allowed_hosts=%d\n", cfg.Listen, cfg.Upstream.Host, len(cfg.AllowedHosts))

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("start loopback listener: %w", err)
	}
	connector := proxy.NewHTTPConnector(cfg.Upstream, cfg.Timeouts.Connect, cfg.Timeouts.ProxyHandshake)
	server := relay.NewServer(cfg.AllowedHosts, cfg.Timeouts.ClientHello, connector, logger)
	ctx, cancel := context.WithTimeout(context.Background(), overallTimeout)
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- server.Serve(ctx, listener)
	}()

	testErr := runChecks(ctx, listener.Addr().String(), cfg)
	cancel()
	serveErr := <-serverDone
	if testErr != nil {
		return testErr
	}
	if serveErr != nil {
		return fmt.Errorf("relay server: %w", serveErr)
	}
	fmt.Println("PASS all live relay checks")
	return nil
}

func runChecks(ctx context.Context, relayAddress string, cfg *config.Config) error {
	hosts := make([]string, 0, len(cfg.AllowedHosts))
	for host := range cfg.AllowedHosts {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	for _, host := range hosts {
		status, certificateName, err := checkAllowedHost(ctx, relayAddress, host, cfg.Timeouts)
		if err != nil {
			return fmt.Errorf("allowed host %s: %w", host, err)
		}
		fmt.Printf("PASS allowed host: sni=%s certificate=%s http_status=%s\n", host, certificateName, status)
	}

	deniedHost := "relay-deny-test.invalid"
	if _, exists := cfg.AllowedHosts[deniedHost]; exists {
		return fmt.Errorf("test-only denied hostname %q unexpectedly appears in allowed_hosts", deniedHost)
	}
	if err := checkDeniedHost(ctx, relayAddress, deniedHost, cfg.Timeouts.ClientHello); err != nil {
		return err
	}
	fmt.Printf("PASS denied host: sni=%s\n", deniedHost)

	elapsed, err := checkClientHelloTimeout(ctx, relayAddress, cfg.Timeouts.ClientHello)
	if err != nil {
		return err
	}
	fmt.Printf("PASS ClientHello timeout: configured=%s observed=%s\n", cfg.Timeouts.ClientHello, elapsed.Round(time.Millisecond))
	return nil
}

func checkAllowedHost(ctx context.Context, relayAddress, host string, timeouts config.Timeouts) (string, string, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", relayAddress)
	if err != nil {
		return "", "", fmt.Errorf("connect to relay: %w", err)
	}
	defer conn.Close()
	setOperationDeadline(conn, ctx, timeouts.ClientHello+timeouts.Connect+timeouts.ProxyHandshake+10*time.Second)

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return "", "", fmt.Errorf("TLS handshake through relay: %w", err)
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", "", errors.New("TLS peer returned no certificate")
	}
	if err := state.PeerCertificates[0].VerifyHostname(host); err != nil {
		return "", "", fmt.Errorf("verify target certificate: %w", err)
	}

	request := &http.Request{
		Method: http.MethodHead,
		URL:    &url.URL{Scheme: "https", Host: host, Path: "/"},
		Host:   host,
		Header: http.Header{"User-Agent": {"hass-proxy-relay-smoke-test/1"}},
		Close:  true,
	}
	if err := request.Write(tlsConn); err != nil {
		return "", "", fmt.Errorf("write HTTPS request: %w", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(tlsConn), request)
	if err != nil {
		return "", "", fmt.Errorf("read HTTPS response: %w", err)
	}
	_ = response.Body.Close()
	_ = tlsConn.Close()

	certificateName := state.PeerCertificates[0].Subject.CommonName
	if certificateName == "" {
		certificateName = "SAN-verified"
	}
	return response.Status, certificateName, nil
}

func checkDeniedHost(ctx context.Context, relayAddress, host string, clientHelloTimeout time.Duration) error {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", relayAddress)
	if err != nil {
		return fmt.Errorf("denied-host check: connect to relay: %w", err)
	}
	defer conn.Close()
	setOperationDeadline(conn, ctx, clientHelloTimeout+5*time.Second)

	tlsConn := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err := tlsConn.HandshakeContext(ctx); err == nil {
		return fmt.Errorf("denied-host check: TLS handshake for %s unexpectedly succeeded", host)
	}
	return nil
}

func checkClientHelloTimeout(ctx context.Context, relayAddress string, timeout time.Duration) (time.Duration, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", relayAddress)
	if err != nil {
		return 0, fmt.Errorf("ClientHello-timeout check: connect to relay: %w", err)
	}
	defer conn.Close()
	setOperationDeadline(conn, ctx, timeout+5*time.Second)

	started := time.Now()
	var oneByte [1]byte
	_, err = conn.Read(oneByte[:])
	elapsed := time.Since(started)
	if err == nil {
		return elapsed, errors.New("ClientHello-timeout check: relay returned unexpected data")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return elapsed, errors.New("ClientHello-timeout check: client deadline expired before relay closed the connection")
	}
	tolerance := 100 * time.Millisecond
	if timeout > tolerance && elapsed+tolerance < timeout {
		return elapsed, fmt.Errorf("ClientHello-timeout check: relay closed too early after %s", elapsed.Round(time.Millisecond))
	}
	return elapsed, nil
}

func setOperationDeadline(conn net.Conn, ctx context.Context, maximum time.Duration) {
	deadline := time.Now().Add(maximum)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = conn.SetDeadline(deadline)
}
