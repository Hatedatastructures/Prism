// Package main provides a minimal standard-library TLS reference endpoint for
// the Preview native TLS carrier interoperability cases.
package main

import (
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
)

const payload = "prism-native-tls-external-interop-payload"

type options struct {
	mode string
	addr string
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
		NotBefore:   now.Add(-time.Minute),
		NotAfter:    now.Add(time.Hour),
		DNSNames:    []string{"native", "localhost"},
		KeyUsage:   x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
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
	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}}, nil
}

func runServer(address string) error {
	config, err := makeTLSConfig()
	if err != nil {
		return err
	}
	listener, err := tls.Listen("tcp", address, config)
	if err != nil {
		return err
	}
	defer listener.Close()
	fmt.Printf("READY: Go native TLS reference server on %s\n", address)
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := io.Copy(conn, conn); err != nil {
		return err
	}
	return nil
}

func runClient(address string) error {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", address, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "native",
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
	fmt.Printf("PASS: Go native TLS client -> Preview server (%d bytes)\n", len(echo))
	return nil
}

func main() {
	mode := flag.String("mode", "client", "client or server")
	address := flag.String("addr", "127.0.0.1:19092", "TCP endpoint")
	flag.Parse()
	var err error
	if *mode == "server" {
		err = runServer(*address)
	} else {
		err = runClient(*address)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: native TLS reference: %v\n", err)
		os.Exit(1)
	}
}
