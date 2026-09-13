package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

const payload = "prism-websocket-external-interop-payload"

type bufferedReadWriter struct {
	reader *bufio.Reader
	writer io.Writer
}

func (rw *bufferedReadWriter) Read(p []byte) (int, error) {
	return rw.reader.Read(p)
}

func (rw *bufferedReadWriter) Write(p []byte) (int, error) {
	return rw.writer.Write(p)
}

func runServer(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()
	fmt.Printf("READY: Go WebSocket reference server on %s\n", addr)
	if err := os.Stdout.Sync(); err != nil {
		return fmt.Errorf("flush ready: %w", err)
	}
	conn, err := listener.Accept()
	if err != nil {
		return fmt.Errorf("accept: %w", err)
	}
	defer conn.Close()
	if _, err := ws.Upgrade(conn); err != nil {
		return fmt.Errorf("upgrade: %w", err)
	}
	data, op, err := wsutil.ReadClientData(conn)
	if err != nil {
		return fmt.Errorf("read client frame: %w", err)
	}
	if op != ws.OpBinary || !bytes.Equal(data, []byte(payload)) {
		return fmt.Errorf("unexpected client payload")
	}
	if err := wsutil.WriteServerMessage(conn, ws.OpBinary, data); err != nil {
		return fmt.Errorf("write server frame: %w", err)
	}
	fmt.Printf("PASS: Go WebSocket reference server echo (%d bytes)\n", len(data))
	return nil
}

func runClient(addr string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, buffered, _, err := ws.Dial(ctx, "ws://"+addr+"/")
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	if buffered == nil {
		buffered = bufio.NewReader(conn)
	}
	rw := &bufferedReadWriter{reader: buffered, writer: conn}
	if err := wsutil.WriteClientMessage(conn, ws.OpBinary, []byte(payload)); err != nil {
		return fmt.Errorf("write client frame: %w", err)
	}
	data, op, err := wsutil.ReadServerData(rw)
	if err != nil {
		return fmt.Errorf("read server frame: %w", err)
	}
	if op != ws.OpBinary || !bytes.Equal(data, []byte(payload)) {
		return fmt.Errorf("unexpected server payload")
	}
	fmt.Printf("PASS: Go WebSocket reference client echo (%d bytes)\n", len(data))
	return nil
}

func main() {
	mode := flag.String("mode", "client", "client or server")
	addr := flag.String("addr", "127.0.0.1:19093", "TCP address")
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
		fmt.Fprintf(os.Stderr, "FAIL: WebSocket reference interop: %v\n", err)
		os.Exit(1)
	}
}
