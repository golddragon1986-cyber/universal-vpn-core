//go:build with_utls

package tls

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	utls "github.com/metacubex/utls"
)

// Inspect the real ClientHello on the wire, without contacting a VPN server.
func TestRealityMLKEMClientHello(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "hybrid"}[enabled], func(t *testing.T) {
			key, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			config := &RealityClientConfig{ctx: context.Background(), publicKey: key.PublicKey().Bytes(), enableMLKEM: enabled,
				uClient: &UTLSClientConfig{ctx: context.Background(), serverName: "example.com", config: &utls.Config{ServerName: "example.com"}, id: utls.HelloChrome_Auto}}
			config = config.Clone().(*RealityClientConfig)
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			_ = client.SetDeadline(time.Now().Add(5 * time.Second))
			_ = server.SetDeadline(time.Now().Add(5 * time.Second))
			done := make(chan error, 1)
			go func() { _, err := config.ClientHandshake(context.Background(), client); done <- err }()
			header := make([]byte, 5)
			if _, err := io.ReadFull(server, header); err != nil {
				t.Fatal(err)
			}
			if header[0] != 22 {
				t.Fatalf("not a TLS handshake: %x", header)
			}
			payload := make([]byte, binary.BigEndian.Uint16(header[3:]))
			if _, err := io.ReadFull(server, payload); err != nil {
				t.Fatal(err)
			}
			_ = server.Close()
			if err := <-done; err == nil {
				t.Fatal("unverified handshake unexpectedly succeeded")
			}
			if len(payload) < 40 || payload[0] != 1 {
				t.Fatal("invalid ClientHello")
			}
			body := payload[4:]
			pos := 34
			pos += 1 + int(body[pos])
			pos += 2 + int(binary.BigEndian.Uint16(body[pos:]))
			pos += 1 + int(body[pos])
			end := pos + 2 + int(binary.BigEndian.Uint16(body[pos:]))
			pos += 2
			var groups []uint16
			for pos+4 <= end {
				kind := binary.BigEndian.Uint16(body[pos:])
				size := int(binary.BigEndian.Uint16(body[pos+2:]))
				pos += 4
				if kind == 51 {
					data := body[pos : pos+size]
					for i := 2; i+4 <= len(data); {
						groups = append(groups, binary.BigEndian.Uint16(data[i:]))
						i += 4 + int(binary.BigEndian.Uint16(data[i+2:]))
					}
				}
				pos += size
			}
			hybrid, classical := -1, -1
			for i, group := range groups {
				if group == uint16(utls.X25519MLKEM768) {
					hybrid = i
				}
				if group == uint16(utls.X25519) {
					classical = i
				}
			}
			if enabled && (hybrid < 0 || (classical >= 0 && hybrid > classical)) {
				t.Fatalf("hybrid key share missing or misplaced: %v", groups)
			}
			if !enabled && (hybrid >= 0 || classical < 0) {
				t.Fatalf("legacy behavior changed: %v", groups)
			}
		})
	}
}
