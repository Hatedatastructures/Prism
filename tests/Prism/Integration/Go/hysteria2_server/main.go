// Package main 提供固定版本 quic-go HTTP/3 Hysteria2 reference server。
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/quic-go/quicvarint"
	"github.com/metacubex/tls"
	"golang.org/x/exp/slog"
)

const tcpRequestFrameType = 0x401

type authHandler struct {
	password string
}

func (h authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.Host != "hysteria" || r.URL.Path != "/auth" ||
		r.Header.Get("Hysteria-Auth") != h.password {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Hysteria-UDP", "true")
	w.Header().Set("Hysteria-CC-RX", "0")
	w.Header().Set("Hysteria-Padding", strings.Repeat("a", 256))
	w.WriteHeader(233)
}

func readVarint(data []byte, offset *int) (uint64, bool) {
	if *offset >= len(data) {
		return 0, false
	}
	first := data[*offset]
	length := 1 << (first >> 6)
	if *offset+length > len(data) {
		return 0, false
	}
	value := uint64(first & 0x3f)
	for index := 1; index < length; index++ {
		value = (value << 8) | uint64(data[*offset+index])
	}
	*offset += length
	return value, true
}

func validUDPMessage(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	offset := 8
	destinationLength, ok := readVarint(data, &offset)
	if !ok || destinationLength == 0 || destinationLength > 2048 {
		return false
	}
	return destinationLength <= uint64(len(data)-offset)
}

func handleDatagrams(ctx context.Context, connection *quic.Conn) {
	for {
		message, err := connection.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		if !validUDPMessage(message) {
			continue
		}
		if err := connection.SendDatagram(message); err != nil {
			return
		}
	}
}

func appendVarint(out []byte, value uint64) []byte {
	if value <= 63 {
		return append(out, byte(value))
	}
	if value <= 16383 {
		return append(out, byte(value>>8)|0x40, byte(value))
	}
	if value <= 1073741823 {
		return append(out, byte(value>>24)|0x80, byte(value>>16), byte(value>>8), byte(value))
	}
	return append(out, byte(value>>56)|0xc0, byte(value>>48), byte(value>>40), byte(value>>32),
		byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
}

func writeTCPResponse(stream *quic.Stream) error {
	padding := strings.Repeat("a", 128)
	response := appendVarint([]byte{0}, 0)
	response = appendVarint(response, uint64(len(padding)))
	response = append(response, []byte(padding)...)
	_, err := stream.Write(response)
	return err
}

func handleTCPStream(stream *quic.Stream) {
	defer stream.Close()
	reader := quicvarint.NewReader(stream)
	frameType, err := quicvarint.Read(reader)
	if err != nil || frameType != tcpRequestFrameType {
		return
	}
	addressLength, err := quicvarint.Read(reader)
	if err != nil || addressLength == 0 || addressLength > 2048 {
		return
	}
	if _, err = io.CopyN(io.Discard, reader, int64(addressLength)); err != nil {
		return
	}
	paddingLength, err := quicvarint.Read(reader)
	if err != nil || paddingLength > 4096 {
		return
	}
	if _, err = io.CopyN(io.Discard, reader, int64(paddingLength)); err != nil {
		return
	}
	if err = writeTCPResponse(stream); err != nil {
		return
	}
	_, _ = io.Copy(stream, stream)
}

func makeTLSConfig() (*tls.Config, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		DNSNames:     []string{"hysteria", "localhost"},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}, nil
}

func main() {
	listen := flag.String("listen", "127.0.0.1:19089", "Hysteria2 listen address")
	password := flag.String("password", "hysteria2_password", "Hysteria2 password")
	flag.Parse()

	tlsConfig, err := makeTLSConfig()
	if err != nil {
		fmt.Printf("FAIL: TLS setup: %v\n", err)
		os.Exit(1)
	}
	addr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		fmt.Printf("FAIL: listen address: %v\n", err)
		os.Exit(2)
	}
	packetConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Printf("FAIL: UDP listen: %v\n", err)
		os.Exit(1)
	}
	listener, err := quic.Listen(packetConn, tlsConfig, &quic.Config{
		MaxIncomingStreams: 1024,
		EnableDatagrams:    true,
	})
	if err != nil {
		fmt.Printf("FAIL: QUIC listen: %v\n", err)
		packetConn.Close()
		os.Exit(1)
	}
	server := &http3.Server{
		Handler: authHandler{password: *password},
		Logger:  slog.New(slog.NewTextHandler(os.Stderr, nil)),
		StreamDispatcher: func(frameType http3.FrameType, stream *quic.Stream, dispatchErr error) (bool, error) {
			if dispatchErr != nil || frameType != tcpRequestFrameType {
				return false, nil
			}
			go handleTCPStream(stream)
			return true, nil
		},
	}
	fmt.Printf("READY: Go Hysteria2 reference server on %s\n", *listen)
	for {
		connection, acceptErr := listener.Accept(context.Background())
		if acceptErr != nil {
			return
		}
		go func() {
			go handleDatagrams(context.Background(), connection)
			_ = server.ServeQUICConn(connection)
			_ = connection.CloseWithError(0, "")
		}()
	}
}
