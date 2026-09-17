package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

const payload = "prism-xhttp-http2-external-interop-payload"

type splitSession struct {
	down chan []byte
}

type splitSessions struct {
	sync.Mutex
	items map[string]*splitSession
}

func (sessions *splitSessions) get(id string) *splitSession {
	sessions.Lock()
	defer sessions.Unlock()
	if sessions.items == nil {
		sessions.items = make(map[string]*splitSession)
	}
	if session, ok := sessions.items[id]; ok {
		return session
	}
	session := &splitSession{down: make(chan []byte, 16)}
	sessions.items[id] = session
	return session
}

func splitPath(path string) (string, string, bool) {
	trimmed := strings.TrimPrefix(path, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) == 1 && parts[0] != "" {
		return parts[0], "", true
	}
	if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		return parts[0], parts[1], true
	}
	return "", "", false
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
		Subject:      pkix.Name{CommonName: "xhttp-reference"},
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

func runServer(addr string, mode string) error {
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
	sessions := &splitSessions{}
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if mode == "StreamOne" {
			if request.Method != http.MethodPost || request.URL.Path != "/" {
				writer.WriteHeader(http.StatusNotFound)
				return
			}
			writer.Header().Set("Content-Type", "text/event-stream")
			writer.WriteHeader(http.StatusOK)
			if flusher, ok := writer.(http.Flusher); ok {
				flusher.Flush()
			}
			_, _ = io.Copy(writer, request.Body)
			return
		}

		sessionID, sequence, ok := splitPath(request.URL.Path)
		if !ok {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		session := sessions.get(sessionID)
		if request.Method == http.MethodGet && sequence == "" {
			writer.Header().Set("Content-Type", "text/event-stream")
			writer.WriteHeader(http.StatusOK)
			if flusher, ok := writer.(http.Flusher); ok {
				flusher.Flush()
			}
			for {
				select {
				case data := <-session.down:
					if _, err := writer.Write(data); err != nil {
						return
					}
					if flusher, ok := writer.(http.Flusher); ok {
						flusher.Flush()
					}
				case <-request.Context().Done():
					return
				}
			}
		}
		if request.Method == http.MethodPost && (mode == "StreamUp" || sequence != "") {
			writer.Header().Set("Content-Type", "text/event-stream")
			writer.WriteHeader(http.StatusOK)
			if flusher, ok := writer.(http.Flusher); ok {
				flusher.Flush()
			}
			if mode == "StreamUp" {
				buffer := make([]byte, 16*1024)
				for {
					count, readErr := request.Body.Read(buffer)
					if count != 0 {
						data := append([]byte(nil), buffer[:count]...)
						session.down <- data
					}
					if readErr == io.EOF {
						return
					}
					if readErr != nil {
						return
					}
				}
			}
			data, err := io.ReadAll(request.Body)
			if err == nil && len(data) != 0 {
				session.down <- data
			}
			return
		}
		writer.WriteHeader(http.StatusNotFound)
	})}
	if err := http2.ConfigureServer(server, nil); err != nil {
		return fmt.Errorf("configure http2: %w", err)
	}
	fmt.Printf("READY: Go XHTTP server on %s\n", addr)
	if err := server.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

func runClient(addr string, mode string) error {
	transport := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // reference endpoint uses an ephemeral certificate.
	}
	client := &http.Client{Transport: transport}
	defer transport.CloseIdleConnections()
	if mode == "StreamOne" {
		return runStreamOneClient(client, addr)
	}
	return runSplitClient(client, addr, mode)
}

func runStreamOneClient(client *http.Client, addr string) error {
	request, err := http.NewRequest(http.MethodPost, "https://"+addr+"/", bytes.NewReader([]byte(payload)))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Content-Type", "text/event-stream")
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("http2 request: %w", err)
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
	fmt.Printf("PASS: Go HTTP/2 XHTTP reference client echo (%d bytes)\n", len(echo))
	return nil
}

func runSplitClient(client *http.Client, addr string, mode string) error {
	sessionID := "1"
	downRequest, err := http.NewRequest(http.MethodGet, "https://"+addr+"/"+sessionID, nil)
	if err != nil {
		return err
	}
	downResponse, err := client.Do(downRequest)
	if err != nil {
		return fmt.Errorf("downstream request: %w", err)
	}
	defer downResponse.Body.Close()
	if downResponse.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected downstream status %s", downResponse.Status)
	}

	if mode == "StreamUp" {
		upReader, upWriter := io.Pipe()
		upRequest, err := http.NewRequest(http.MethodPost, "https://"+addr+"/"+sessionID, upReader)
		if err != nil {
			return err
		}
		upDone := make(chan error, 1)
		go func() {
			response, requestErr := client.Do(upRequest)
			if response != nil {
				response.Body.Close()
			}
			upDone <- requestErr
		}()
		if _, err := upWriter.Write([]byte(payload)); err != nil {
			return err
		}
		if err := upWriter.Close(); err != nil {
			return err
		}
		if err := <-upDone; err != nil {
			return fmt.Errorf("upstream request: %w", err)
		}
	} else {
		upRequest, err := http.NewRequest(
			http.MethodPost, "https://"+addr+"/"+sessionID+"/0", bytes.NewReader([]byte(payload)))
		if err != nil {
			return err
		}
		upResponse, err := client.Do(upRequest)
		if err != nil {
			return fmt.Errorf("packet request: %w", err)
		}
		upResponse.Body.Close()
		if upResponse.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected packet status %s", upResponse.Status)
		}
	}

	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(downResponse.Body, echo); err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if !bytes.Equal(echo, []byte(payload)) {
		return fmt.Errorf("echo mismatch")
	}
	fmt.Printf("PASS: Go HTTP/2 XHTTP %s reference client echo (%d bytes)\n", mode, len(echo))
	return nil
}

func main() {
	addr := flag.String("addr", "127.0.0.1:19096", "TLS address")
	mode := flag.String("mode", "client", "client or server")
	xhttpMode := flag.String("xhttp-mode", "StreamOne", "StreamOne, StreamUp, or PacketUp")
	flag.Parse()
	var err error
	if *mode == "server" {
		err = runServer(*addr, *xhttpMode)
	} else if *mode == "client" {
		err = runClient(*addr, *xhttpMode)
	} else {
		err = fmt.Errorf("unsupported mode %q", *mode)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: XHTTP reference interop: %v\n", err)
		os.Exit(1)
	}
}
