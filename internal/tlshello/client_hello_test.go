package tlshello

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

func TestReadFragmentedClientHelloPreservesRawBytes(t *testing.T) {
	raw := makeClientHello("Vector.OpenStreetMap.Org", 11)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write(raw)
		writeDone <- err
	}()

	hello, err := Read(server, time.Second)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if hello.ServerName != "Vector.OpenStreetMap.Org" {
		t.Fatalf("ServerName = %q", hello.ServerName)
	}
	if !bytes.Equal(hello.Raw, raw) {
		t.Fatal("Read() did not preserve the TLS records")
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write error = %v", err)
	}
}

func TestReadRejectsMissingSNI(t *testing.T) {
	raw := makeClientHello("", 0)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go client.Write(raw) //nolint:errcheck

	_, err := Read(server, time.Second)
	if err == nil || !strings.Contains(err.Error(), "SNI") {
		t.Fatalf("Read() error = %v, want missing-SNI error", err)
	}
}

func TestReadEnforcesSizeLimitBeforeAllocatingPayload(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	header := []byte{tlsHandshakeRecord, 3, 1, 0xff, 0xff}
	go client.Write(header) //nolint:errcheck

	_, err := Read(server, time.Second)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Read() error = %v, want size-limit error", err)
	}
}

func TestReadTimesOut(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	started := time.Now()
	_, err := Read(server, 20*time.Millisecond)
	if err == nil {
		t.Fatal("Read() succeeded, want timeout")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Read() took %v", elapsed)
	}
}

func makeClientHello(host string, splitAt int) []byte {
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)             // session ID
	body = append(body, 0, 2, 0x13, 1) // cipher suites
	body = append(body, 1, 0)          // compression methods

	var extensions []byte
	if host != "" {
		name := append([]byte{0, byte(len(host) >> 8), byte(len(host))}, []byte(host)...)
		serverNames := append([]byte{byte(len(name) >> 8), byte(len(name))}, name...)
		extension := append([]byte{0, 0, byte(len(serverNames) >> 8), byte(len(serverNames))}, serverNames...)
		extensions = append(extensions, extension...)
	}
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)

	handshake := []byte{clientHelloType, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	if splitAt <= 0 || splitAt >= len(handshake) {
		return makeRecord(handshake)
	}
	return append(makeRecord(handshake[:splitAt]), makeRecord(handshake[splitAt:])...)
}

func makeRecord(payload []byte) []byte {
	record := []byte{tlsHandshakeRecord, 3, 1, 0, 0}
	binary.BigEndian.PutUint16(record[3:], uint16(len(payload)))
	return append(record, payload...)
}
