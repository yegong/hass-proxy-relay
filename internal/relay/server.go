// Package relay accepts TLS clients, enforces the SNI allowlist and relays
// approved connections through an upstream tunnel.
package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/yegong/hass-proxy-relay/internal/config"
	"github.com/yegong/hass-proxy-relay/internal/proxy"
	"github.com/yegong/hass-proxy-relay/internal/tlshello"
)

type Server struct {
	allowedHosts       map[string]struct{}
	clientHelloTimeout time.Duration
	connector          proxy.Connector
	logger             *slog.Logger
}

func NewServer(
	allowedHosts map[string]struct{},
	clientHelloTimeout time.Duration,
	connector proxy.Connector,
	logger *slog.Logger,
) *Server {
	allowedCopy := make(map[string]struct{}, len(allowedHosts))
	for host := range allowedHosts {
		allowedCopy[host] = struct{}{}
	}
	return &Server{
		allowedHosts:       allowedCopy,
		clientHelloTimeout: clientHelloTimeout,
		connector:          connector,
		logger:             logger,
	}
}

// Serve accepts connections until ctx is canceled or the listener fails. On
// cancellation it closes active sessions and waits for their goroutines.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	var sessions sync.WaitGroup
	defer func() {
		cancel()
		_ = listener.Close()
		sessions.Wait()
	}()

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	var retryDelay time.Duration
	for {
		client, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return fmt.Errorf("listener closed unexpectedly: %w", err)
			}
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				if retryDelay == 0 {
					retryDelay = 5 * time.Millisecond
				} else {
					retryDelay *= 2
				}
				if retryDelay > time.Second {
					retryDelay = time.Second
				}
				s.logger.Warn("temporary accept failure", "event", "accept_failure", "error", err, "retry_in", retryDelay)
				select {
				case <-time.After(retryDelay):
					continue
				case <-ctx.Done():
					return nil
				}
			}
			cancel()
			return fmt.Errorf("accept connection: %w", err)
		}
		retryDelay = 0

		sessions.Add(1)
		go func() {
			defer sessions.Done()
			s.handleSession(ctx, client)
		}()
	}
}

func (s *Server) handleSession(ctx context.Context, client net.Conn) {
	defer client.Close()
	stopClientCancellation := context.AfterFunc(ctx, func() {
		_ = client.Close()
	})
	defer stopClientCancellation()
	clientAddress := client.RemoteAddr().String()

	hello, err := tlshello.Read(client, s.clientHelloTimeout)
	if err != nil {
		if ctx.Err() == nil {
			s.logger.Warn("rejected TLS client", "event", "sni_rejected", "client", clientAddress, "error", err)
		}
		return
	}
	host, err := config.NormalizeHostname(hello.ServerName)
	if err != nil {
		// The raw SNI is untrusted and can be very large or contain control
		// bytes, so do not include it in logs until it has been validated.
		s.logger.Warn("rejected invalid SNI", "event", "sni_rejected", "client", clientAddress, "error", err)
		return
	}
	if _, allowed := s.allowedHosts[host]; !allowed {
		s.logger.Warn("rejected disallowed SNI", "event", "sni_rejected", "client", clientAddress, "sni", host)
		return
	}
	s.logger.Info("accepted SNI", "event", "sni_accepted", "client", clientAddress, "sni", host)

	upstream, err := s.connector.Connect(ctx, net.JoinHostPort(host, "443"))
	if err != nil {
		if ctx.Err() == nil {
			message := "upstream proxy handshake failed"
			event := "proxy_handshake_failure"
			if errors.Is(err, proxy.ErrUpstreamConnect) {
				message = "upstream proxy connection failed"
				event = "upstream_connect_failure"
			}
			s.logger.Error(message, "event", event, "client", clientAddress, "sni", host, "error", err)
		}
		return
	}
	defer upstream.Close()

	stopUpstreamCancellation := context.AfterFunc(ctx, func() {
		_ = upstream.Close()
	})
	defer stopUpstreamCancellation()

	if err := writeAll(upstream, hello.Raw); err != nil {
		if ctx.Err() == nil {
			s.logger.Error("failed to forward ClientHello", "event", "client_hello_forward_failure", "client", clientAddress, "sni", host, "error", err)
		}
		return
	}

	if err := relayBidirectional(client, upstream); err != nil && ctx.Err() == nil {
		s.logger.Warn("tunnel terminated abnormally", "event", "tunnel_failure", "client", clientAddress, "sni", host, "error", err)
	}
}

func writeAll(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		data = data[n:]
	}
	return nil
}

type copyResult struct {
	direction string
	err       error
}

func relayBidirectional(client, upstream net.Conn) error {
	results := make(chan copyResult, 2)
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = client.Close()
			_ = upstream.Close()
		})
	}

	pump := func(direction string, dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if err != nil {
			closeBoth()
		} else {
			closeWrite(dst)
			closeRead(src)
		}
		results <- copyResult{direction: direction, err: err}
	}

	go pump("client_to_upstream", upstream, client)
	go pump("upstream_to_client", client, upstream)

	first := <-results
	second := <-results
	closeBoth()

	if first.err != nil {
		return fmt.Errorf("%s: %w", first.direction, first.err)
	}
	if second.err != nil {
		return fmt.Errorf("%s: %w", second.direction, second.err)
	}
	return nil
}

func closeWrite(conn net.Conn) {
	if halfCloser, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = halfCloser.CloseWrite()
	}
}

func closeRead(conn net.Conn) {
	if halfCloser, ok := conn.(interface{ CloseRead() error }); ok {
		_ = halfCloser.CloseRead()
	}
}
