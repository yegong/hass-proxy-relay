package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestHTTPConnectorSendsCONNECTAndPreservesBufferedBytes(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	requestReceived := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		var request strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			request.WriteString(line)
			if line == "\r\n" {
				break
			}
		}
		requestReceived <- request.String()
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\nready")
		<-time.After(100 * time.Millisecond)
	}()

	upstream, _ := url.Parse("http://user:secret@" + listener.Addr().String())
	connector := NewHTTPConnector(upstream, time.Second, time.Second)
	conn, err := connector.Connect(context.Background(), "vector.openstreetmap.org:443")
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer conn.Close()

	request := <-requestReceived
	for _, expected := range []string{
		"CONNECT vector.openstreetmap.org:443 HTTP/1.1\r\n",
		"Host: vector.openstreetmap.org:443\r\n",
		"Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n",
	} {
		if !strings.Contains(request, expected) {
			t.Fatalf("request %q does not contain %q", request, expected)
		}
	}

	buffer := make([]byte, 5)
	if _, err := io.ReadFull(conn, buffer); err != nil {
		t.Fatalf("read buffered tunnel bytes: %v", err)
	}
	if string(buffer) != "ready" {
		t.Fatalf("buffered bytes = %q", buffer)
	}
}

func TestHTTPConnectorRejectsNon2xxResponse(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go serveProxyResponse(listener, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")

	upstream, _ := url.Parse("http://" + listener.Addr().String())
	connector := NewHTTPConnector(upstream, time.Second, time.Second)
	_, err = connector.Connect(context.Background(), "tile.openstreetmap.org:443")
	if err == nil || !strings.Contains(err.Error(), "407") {
		t.Fatalf("Connect() error = %v, want HTTP 407", err)
	}
}

func TestHTTPConnectorHandshakeTimeout(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	upstream, _ := url.Parse("http://" + listener.Addr().String())
	connector := NewHTTPConnector(upstream, time.Second, 20*time.Millisecond)
	_, err = connector.Connect(context.Background(), "tile.openstreetmap.org:443")
	if err == nil {
		t.Fatal("Connect() succeeded, want handshake timeout")
	}
	conn := <-accepted
	conn.Close()
}

func TestHTTPConnectorLimitsAndSanitizesInvalidResponses(t *testing.T) {
	tests := []struct {
		name          string
		response      string
		wantError     string
		forbiddenText string
	}{
		{
			name:      "oversized headers",
			response:  "HTTP/1.1 200 OK\r\nX-Large: " + strings.Repeat("x", maxResponseHeaderBytes) + "\r\n\r\n",
			wantError: "exceed",
		},
		{
			name:          "attacker controlled status line",
			response:      "not-http secret-proxy-credential\r\n\r\n",
			wantError:     "invalid HTTP response",
			forbiddenText: "secret-proxy-credential",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go serveProxyResponse(listener, tt.response)

			upstream, _ := url.Parse("http://" + listener.Addr().String())
			connector := NewHTTPConnector(upstream, time.Second, time.Second)
			_, err = connector.Connect(context.Background(), "tile.openstreetmap.org:443")
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("Connect() error = %v, want text %q", err, tt.wantError)
			}
			if tt.forbiddenText != "" && strings.Contains(err.Error(), tt.forbiddenText) {
				t.Fatalf("Connect() error leaked response text: %v", err)
			}
		})
	}
}

func serveProxyResponse(listener net.Listener, response string) {
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}
	_, _ = io.WriteString(conn, response)
}
