package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
)

const (
	password = "anytls_password"
	payload  = "prism-anytls-external-interop-payload"
	padLen   = 16
)

func writeAll(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		written, err := conn.Write(data)
		if err != nil {
			return err
		}
		if written == 0 || written > len(data) {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func writeHandshake(conn net.Conn) error {
	hash := sha256.Sum256([]byte(password))
	frame := make([]byte, 32+2+padLen)
	copy(frame, hash[:])
	binary.BigEndian.PutUint16(frame[32:34], padLen)
	for index := 0; index < padLen; index++ {
		frame[34+index] = byte(index*13 + 7)
	}
	return writeAll(conn, frame)
}

func readHandshake(conn net.Conn) error {
	frame := make([]byte, 34)
	if _, err := io.ReadFull(conn, frame); err != nil {
		return err
	}
	length := int(binary.BigEndian.Uint16(frame[32:34]))
	padding := make([]byte, length)
	if _, err := io.ReadFull(conn, padding); err != nil {
		return err
	}
	hash := sha256.Sum256([]byte(password))
	if !bytes.Equal(frame[:32], hash[:]) {
		return fmt.Errorf("authentication failed")
	}
	return nil
}

func runServer(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()
	fmt.Printf("READY: Go AnyTLS reference server on %s\n", addr)
	if err := os.Stdout.Sync(); err != nil {
		return fmt.Errorf("flush ready: %w", err)
	}
	conn, err := listener.Accept()
	if err != nil {
		return fmt.Errorf("accept: %w", err)
	}
	defer conn.Close()
	if err := readHandshake(conn); err != nil {
		return fmt.Errorf("read handshake: %w", err)
	}
	buffer := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buffer); err != nil {
		return fmt.Errorf("read payload: %w", err)
	}
	if !bytes.Equal(buffer, []byte(payload)) {
		return fmt.Errorf("unexpected payload")
	}
	if err := writeAll(conn, buffer); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	fmt.Printf("PASS: Go AnyTLS reference server echo (%d bytes)\n", len(buffer))
	return nil
}

func runClient(addr string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	if err := writeHandshake(conn); err != nil {
		return fmt.Errorf("write handshake: %w", err)
	}
	if err := writeAll(conn, []byte(payload)); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	buffer := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buffer); err != nil {
		return fmt.Errorf("read payload: %w", err)
	}
	if !bytes.Equal(buffer, []byte(payload)) {
		return fmt.Errorf("unexpected payload")
	}
	fmt.Printf("PASS: Go AnyTLS reference client echo (%d bytes)\n", len(buffer))
	return nil
}

func main() {
	mode := flag.String("mode", "client", "client or server")
	addr := flag.String("addr", "127.0.0.1:19094", "TCP address")
	flag.Parse()

	var err error
	switch *mode {
	case "server":
		err = runServer(*addr)
	case "client":
		err = runClient(*addr)
	default:
		err = fmt.Errorf("unknown mode %q", *mode)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: AnyTLS reference interop: %v\n", err)
		os.Exit(1)
	}
}
