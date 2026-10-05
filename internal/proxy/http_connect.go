// Package proxy establishes outbound tunnels through an upstream proxy.
package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxResponseHeaderBytes = 32 * 1024

var errResponseHeaderTooLarge = errors.New("CONNECT response headers exceed 32 KiB")

var (
	ErrUpstreamConnect = errors.New("upstream proxy connection failed")
	ErrProxyHandshake  = errors.New("HTTP CONNECT handshake failed")
)

type Connector interface {
	Connect(ctx context.Context, target string) (net.Conn, error)
}

type HTTPConnector struct {
	proxyAddress     string
	authorization    string
	dialer           net.Dialer
	handshakeTimeout time.Duration
}

func NewHTTPConnector(upstream *url.URL, connectTimeout, handshakeTimeout time.Duration) *HTTPConnector {
	connector := &HTTPConnector{
		proxyAddress: upstream.Host,
		dialer: net.Dialer{
			Timeout:   connectTimeout,
			KeepAlive: 30 * time.Second,
		},
		handshakeTimeout: handshakeTimeout,
	}
	if upstream.User != nil {
		password, _ := upstream.User.Password()
		credentials := upstream.User.Username() + ":" + password
		connector.authorization = "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials))
	}
	return connector
}

func (c *HTTPConnector) Connect(ctx context.Context, target string) (net.Conn, error) {
	if target == "" || strings.ContainsAny(target, "\r\n") {
		return nil, errors.New("invalid CONNECT target")
	}

	conn, err := c.dialer.DialContext(ctx, "tcp", c.proxyAddress)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUpstreamConnect, err)
	}
	succeeded := false
	defer func() {
		if !succeeded {
			conn.Close()
		}
	}()

	deadline := time.Now().Add(c.handshakeTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("%w: set deadline: %w", ErrProxyHandshake, err)
	}
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	defer stopCancellation()

	var request strings.Builder
	fmt.Fprintf(&request, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if c.authorization != "" {
		fmt.Fprintf(&request, "Proxy-Authorization: %s\r\n", c.authorization)
	}
	request.WriteString("\r\n")
	if _, err := io.WriteString(conn, request.String()); err != nil {
		return nil, fmt.Errorf("%w: write request: %w", ErrProxyHandshake, err)
	}

	limited := &limitReader{reader: conn, remaining: maxResponseHeaderBytes, enabled: true}
	reader := bufio.NewReader(limited)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		if errors.Is(err, errResponseHeaderTooLarge) {
			return nil, fmt.Errorf("%w: %w", ErrProxyHandshake, errResponseHeaderTooLarge)
		}
		var netErr net.Error
		if errors.As(err, &netErr) {
			return nil, fmt.Errorf("%w: read response: %w", ErrProxyHandshake, err)
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("%w: upstream closed the connection", ErrProxyHandshake)
		}
		// HTTP parser errors can contain attacker-controlled response text. Do
		// not return that text to the structured logger.
		return nil, fmt.Errorf("%w: invalid HTTP response", ErrProxyHandshake)
	}
	limited.enabled = false
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_ = response.Body.Close()
		return nil, fmt.Errorf("%w: upstream proxy returned HTTP status %d", ErrProxyHandshake, response.StatusCode)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("%w: clear deadline: %w", ErrProxyHandshake, err)
	}

	succeeded = true
	return &bufferedConn{Conn: conn, reader: reader}, nil
}

// bufferedConn preserves any bytes ReadResponse read beyond the CONNECT
// response headers and forwards half-close operations to the TCP connection.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

type limitReader struct {
	reader    io.Reader
	remaining int
	enabled   bool
}

func (r *limitReader) Read(p []byte) (int, error) {
	if !r.enabled {
		return r.reader.Read(p)
	}
	if r.remaining == 0 {
		return 0, errResponseHeaderTooLarge
	}
	if len(p) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.reader.Read(p)
	r.remaining -= n
	return n, err
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *bufferedConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return nil
}

func (c *bufferedConn) CloseRead() error {
	if conn, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return conn.CloseRead()
	}
	return nil
}
