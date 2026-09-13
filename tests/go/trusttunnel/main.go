package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/http2"
)

const payload = "prism-trusttunnel-http2-external-interop-payload"

func authorization() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("user:password"))
}

func loadSelfSigned() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "trusttunnel-reference"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"example.com", "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func runServer(addr string) error {
	certificate, err := loadSelfSigned()
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"h2"},
	})
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodConnect || request.Header.Get("Proxy-Authorization") != authorization() {
			writer.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		writer.WriteHeader(http.StatusOK)
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
		_, _ = io.Copy(writer, request.Body)
	})}
	if err := http2.ConfigureServer(server, nil); err != nil {
		return fmt.Errorf("configure http2: %w", err)
	}
	fmt.Printf("READY: Go TrustTunnel server on %s\n", addr)
	if err := server.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

func runClient(addr string) error {
	transport := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // reference endpoint uses an ephemeral certificate.
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	request, err := http.NewRequest(http.MethodConnect, "https://"+addr, bytes.NewReader([]byte(payload)))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	request.Host = "example.com:443"
	request.Header.Set("Proxy-Authorization", authorization())
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("http2 CONNECT: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %s", response.Status)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(response.Body, echo); err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if !bytes.Equal(echo, []byte(payload)) {
		return fmt.Errorf("echo mismatch")
	}
	fmt.Printf("PASS: Go TrustTunnel reference client echo (%d bytes)\n", len(echo))
	return nil
}

func main() {
	addr := flag.String("addr", "127.0.0.1:19097", "TLS address")
	mode := flag.String("mode", "client", "client or server")
	flag.Parse()
	var err error
	if *mode == "server" {
		err = runServer(*addr)
	} else if *mode == "client" {
		err = runClient(*addr)
	} else {
		err = fmt.Errorf("unsupported mode %q", *mode)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: TrustTunnel reference interop: %v\n", err)
		os.Exit(1)
	}
}
