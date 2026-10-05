// Package tlshello reads enough of an incoming TLS connection to extract the
// ClientHello SNI without terminating TLS.
package tlshello

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	// MaxClientHelloBytes bounds memory use and the amount of unauthenticated
	// data accepted before an allowlist decision is made.
	MaxClientHelloBytes = 64 * 1024
	tlsHandshakeRecord  = 22
	clientHelloType     = 1
)

type ClientHello struct {
	ServerName string
	Raw        []byte
}

// Read consumes complete TLS records until the first ClientHello handshake
// message is available. Raw contains every byte consumed, unchanged, so the
// caller can replay it after establishing the upstream tunnel.
func Read(conn net.Conn, timeout time.Duration) (*ClientHello, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("set ClientHello deadline: %w", err)
	}
	defer conn.SetReadDeadline(time.Time{}) //nolint:errcheck // connection is closed on caller error

	raw := make([]byte, 0, 4096)
	handshake := make([]byte, 0, 4096)
	expectedHandshakeSize := 0

	for {
		var header [5]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return nil, fmt.Errorf("read TLS record header: %w", err)
		}
		if header[0] != tlsHandshakeRecord {
			return nil, fmt.Errorf("unexpected TLS record type %d before ClientHello", header[0])
		}
		if header[1] != 3 {
			return nil, fmt.Errorf("unsupported TLS record version %d.%d", header[1], header[2])
		}

		recordSize := int(binary.BigEndian.Uint16(header[3:5]))
		if recordSize == 0 {
			return nil, errors.New("empty TLS handshake record")
		}
		if len(raw)+len(header)+recordSize > MaxClientHelloBytes {
			return nil, fmt.Errorf("ClientHello exceeds %d-byte limit", MaxClientHelloBytes)
		}

		raw = append(raw, header[:]...)
		payloadStart := len(raw)
		raw = append(raw, make([]byte, recordSize)...)
		if _, err := io.ReadFull(conn, raw[payloadStart:]); err != nil {
			return nil, fmt.Errorf("read TLS record payload: %w", err)
		}
		handshake = append(handshake, raw[payloadStart:]...)

		if expectedHandshakeSize == 0 && len(handshake) >= 4 {
			if handshake[0] != clientHelloType {
				return nil, fmt.Errorf("first TLS handshake message has type %d, not ClientHello", handshake[0])
			}
			bodySize := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
			expectedHandshakeSize = 4 + bodySize
			if expectedHandshakeSize > MaxClientHelloBytes {
				return nil, fmt.Errorf("ClientHello exceeds %d-byte limit", MaxClientHelloBytes)
			}
		}

		if expectedHandshakeSize != 0 && len(handshake) >= expectedHandshakeSize {
			serverName, err := parseServerName(handshake[4:expectedHandshakeSize])
			if err != nil {
				return nil, err
			}
			return &ClientHello{ServerName: serverName, Raw: raw}, nil
		}
	}
}

func parseServerName(body []byte) (string, error) {
	// legacy_version + random
	if len(body) < 34 {
		return "", errors.New("truncated ClientHello")
	}
	if body[0] != 3 {
		return "", fmt.Errorf("unsupported ClientHello version %d.%d", body[0], body[1])
	}
	offset := 34

	sessionIDLength, next, ok := uint8At(body, offset)
	if !ok || sessionIDLength > 32 || next+sessionIDLength > len(body) {
		return "", errors.New("invalid ClientHello session ID")
	}
	offset = next + sessionIDLength

	cipherSuitesLength, next, ok := uint16At(body, offset)
	if !ok || cipherSuitesLength < 2 || cipherSuitesLength%2 != 0 || next+cipherSuitesLength > len(body) {
		return "", errors.New("invalid ClientHello cipher suites")
	}
	offset = next + cipherSuitesLength

	compressionLength, next, ok := uint8At(body, offset)
	if !ok || compressionLength < 1 || next+compressionLength > len(body) {
		return "", errors.New("invalid ClientHello compression methods")
	}
	offset = next + compressionLength
	if offset == len(body) {
		return "", errors.New("ClientHello has no SNI extension")
	}

	extensionsLength, next, ok := uint16At(body, offset)
	if !ok || next+extensionsLength != len(body) {
		return "", errors.New("invalid ClientHello extensions")
	}
	offset = next
	end := offset + extensionsLength
	foundSNI := false
	serverName := ""

	for offset < end {
		extensionType, afterType, ok := uint16At(body, offset)
		if !ok {
			return "", errors.New("truncated ClientHello extension type")
		}
		extensionLength, dataStart, ok := uint16At(body, afterType)
		if !ok || dataStart+extensionLength > end {
			return "", errors.New("truncated ClientHello extension data")
		}
		if extensionType == 0 {
			if foundSNI {
				return "", errors.New("duplicate SNI extension")
			}
			foundSNI = true
			var err error
			serverName, err = parseSNIExtension(body[dataStart : dataStart+extensionLength])
			if err != nil {
				return "", err
			}
		}
		offset = dataStart + extensionLength
	}

	if !foundSNI || serverName == "" {
		return "", errors.New("ClientHello has no DNS SNI")
	}
	return serverName, nil
}

func parseSNIExtension(data []byte) (string, error) {
	listLength, offset, ok := uint16At(data, 0)
	if !ok || offset+listLength != len(data) {
		return "", errors.New("invalid SNI server name list")
	}
	end := offset + listLength
	serverName := ""

	for offset < end {
		if end-offset < 3 {
			return "", errors.New("truncated SNI server name")
		}
		nameType := data[offset]
		nameLength := int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))
		offset += 3
		if nameLength == 0 || offset+nameLength > end {
			return "", errors.New("invalid SNI server name length")
		}
		if nameType == 0 {
			if serverName != "" {
				return "", errors.New("multiple DNS names in SNI extension")
			}
			serverName = string(data[offset : offset+nameLength])
		}
		offset += nameLength
	}
	return serverName, nil
}

func uint8At(data []byte, offset int) (value, next int, ok bool) {
	if offset >= len(data) {
		return 0, 0, false
	}
	return int(data[offset]), offset + 1, true
}

func uint16At(data []byte, offset int) (value, next int, ok bool) {
	if offset < 0 || len(data)-offset < 2 {
		return 0, 0, false
	}
	return int(binary.BigEndian.Uint16(data[offset : offset+2])), offset + 2, true
}
