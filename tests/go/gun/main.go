package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

const payload = "prism-gun-lite-external-interop-payload"

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

func readHandshake(reader *bufio.Reader) error {
	header, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(header, "CONNECT ") || !strings.Contains(header, " HTTP/2\r\n") {
		return fmt.Errorf("invalid gun-lite handshake")
	}
	blank, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if blank != "\r\n" {
		return fmt.Errorf("invalid gun-lite header terminator")
	}
	return nil
}

func runServer(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()
	fmt.Printf("READY: Go gun-lite reference server on %s\n", addr)
	if err := os.Stdout.Sync(); err != nil {
		return fmt.Errorf("flush ready: %w", err)
	}
	conn, err := listener.Accept()
	if err != nil {
		return fmt.Errorf("accept: %w", err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	if err := readHandshake(reader); err != nil {
		return fmt.Errorf("read handshake: %w", err)
	}
	data := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, data); err != nil {
		return fmt.Errorf("read payload: %w", err)
	}
	if !bytes.Equal(data, []byte(payload)) {
		return fmt.Errorf("unexpected payload")
	}
	if err := writeAll(conn, data); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	fmt.Printf("PASS: Go gun-lite reference server echo (%d bytes)\n", len(data))
	return nil
}

func runClient(addr string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	header := "CONNECT example.com HTTP/2\r\n\r\n"
	if err := writeAll(conn, []byte(header)); err != nil {
		return fmt.Errorf("write handshake: %w", err)
	}
	if err := writeAll(conn, []byte(payload)); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	data := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, data); err != nil {
		return fmt.Errorf("read payload: %w", err)
	}
	if !bytes.Equal(data, []byte(payload)) {
		return fmt.Errorf("unexpected payload")
	}
	fmt.Printf("PASS: Go gun-lite reference client echo (%d bytes)\n", len(data))
	return nil
}

func main() {
	mode := flag.String("mode", "client", "client or server")
	addr := flag.String("addr", "127.0.0.1:19095", "TCP address")
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
		fmt.Fprintf(os.Stderr, "FAIL: gun-lite reference interop: %v\n", err)
		os.Exit(1)
	}
}
