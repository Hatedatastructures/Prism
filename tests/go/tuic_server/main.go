// Package main 提供固定版本 mihomo TUIC v5 reference server，供 Preview 外部矩阵使用。
package main

import (
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
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/tuic"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

const defaultUUID = "123e4567-e89b-12d3-a456-426614174000"

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
		DNSNames:     []string{"tuic", "localhost"},
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

func parseUUID(value string) ([16]byte, error) {
	parsed, err := uuid.FromString(value)
	if err != nil {
		return [16]byte{}, err
	}
	return [16]byte(parsed), nil
}

func handleTCP(conn net.Conn, _ socks5.Addr, _ ...inbound.Addition) error {
	defer conn.Close()
	_, err := io.Copy(conn, conn)
	return err
}

func handleUDP(addr socks5.Addr, packet C.UDPPacket, _ ...inbound.Addition) error {
	data := append([]byte(nil), packet.Data()...)
	_, err := packet.WriteBack(data, addr.UDPAddr())
	packet.Drop()
	return err
}

func main() {
	listen := flag.String("listen", "127.0.0.1:19091", "TUIC listen address")
	password := flag.String("password", "tuic_password", "TUIC password")
	uuidText := flag.String("uuid", defaultUUID, "TUIC UUID")
	flag.Parse()

	userUUID, err := parseUUID(*uuidText)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: UUID: %v\n", err)
		os.Exit(2)
	}
	tlsConfig, err := makeTLSConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: TLS setup: %v\n", err)
		os.Exit(1)
	}
	packetConn, err := net.ListenPacket("udp", *listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: UDP listen: %v\n", err)
		os.Exit(1)
	}
	defer packetConn.Close()
	server, err := tuic.NewServer(&tuic.ServerOption{
		HandleTcpFn:           handleTCP,
		HandleUdpFn:           handleUDP,
		TlsConfig:             tlsConfig,
		QuicConfig:            &quic.Config{EnableDatagrams: true, MaxIncomingStreams: 1024},
		Users:                 map[[16]byte]string{userUUID: *password},
		AuthenticationTimeout: 10 * time.Second,
		MaxUdpRelayPacketSize: 1200,
	}, packetConn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: TUIC server: %v\n", err)
		os.Exit(1)
	}
	defer server.Close()
	fmt.Printf("READY: Go TUIC reference server on %s\n", *listen)
	if err := server.Serve(); err != nil {
		return
	}
}
