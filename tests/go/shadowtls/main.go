// Package main provides a pinned mihomo ShadowTLS v3 client and a local TLS target.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/metacubex/mihomo/transport/shadowtls"
)

const payload = "prism-shadowtls-external-payload"

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
		NotBefore:   now.Add(-time.Minute),
		NotAfter:    now.Add(time.Hour),
		DNSNames:    []string{"target", "localhost"},
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
	)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}, nil
}

func runTargetServer(address string) error {
	config, err := makeTLSConfig()
	if err != nil {
		return err
	}
	listener, err := tls.Listen("tcp", address, config)
	if err != nil {
		return err
	}
	defer listener.Close()
	fmt.Printf("READY: Go ShadowTLS TLS target on %s\n", address)
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.(*tls.Conn).Handshake(); err != nil {
		return err
	}
	_, err = io.Copy(io.Discard, conn)
	return err
}

func runClient(address string, targetName string, password string) error {
	raw, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return err
	}
	conn, err := shadowtls.NewShadowTLS(context.Background(), raw, &shadowtls.ShadowTLSOption{
		Password:       password,
		Host:           targetName,
		SkipCertVerify: true,
		Version:        3,
		ALPN:           []string{"h2", "http/1.1"},
	})
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(payload)); err != nil {
		return err
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, echo); err != nil {
		return err
	}
	if string(echo) != payload {
		return fmt.Errorf("echo mismatch: got %q want %q", echo, payload)
	}
	fmt.Printf("PASS: Go/mihomo ShadowTLS client -> Preview server (%d bytes)\n", len(echo))
	return nil
}

func main() {
	mode := flag.String("mode", "client", "client or target-server")
	address := flag.String("addr", "127.0.0.1:19096", "ShadowTLS endpoint")
	target := flag.String("target", "target", "TLS target SNI")
	password := flag.String("password", "relay-password", "ShadowTLS password")
	flag.Parse()
	var err error
	if *mode == "target-server" {
		err = runTargetServer(*address)
	} else {
		err = runClient(*address, *target, *password)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: Go ShadowTLS reference: %v\n", err)
		os.Exit(1)
	}
}
