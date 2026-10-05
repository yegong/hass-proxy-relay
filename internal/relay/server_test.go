package relay

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestRelayBidirectionalPreservesHalfClose(t *testing.T) {
	clientPeer, clientRelay := tcpPair(t)
	upstreamRelay, upstreamPeer := tcpPair(t)
	defer clientPeer.Close()
	defer clientRelay.Close()
	defer upstreamRelay.Close()
	defer upstreamPeer.Close()

	relayDone := make(chan error, 1)
	go func() {
		relayDone <- relayBidirectional(clientRelay, upstreamRelay)
	}()

	if _, err := clientPeer.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := clientPeer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	request, err := io.ReadAll(upstreamPeer)
	if err != nil {
		t.Fatal(err)
	}
	if string(request) != "request" {
		t.Fatalf("upstream received %q", request)
	}

	if _, err := upstreamPeer.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err := upstreamPeer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(clientPeer)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "response" {
		t.Fatalf("client received %q", response)
	}

	select {
	case err := <-relayDone:
		if err != nil {
			t.Fatalf("relayBidirectional() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("relayBidirectional() did not finish")
	}
}

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan *net.TCPConn, 1)
	go func() {
		conn, _ := listener.AcceptTCP()
		accepted <- conn
	}()
	peer, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	return peer, <-accepted
}
