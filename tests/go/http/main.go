// Package main 提供独立 HTTP/1.1 CONNECT reference client/server。
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

func runServer(listen string) error {
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	fmt.Printf("READY: Go HTTP CONNECT server on %s\n", listen)
	for {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return acceptErr
		}
		if err := serveConnection(connection); err != nil {
			_ = connection.Close()
			continue
		}
		_ = connection.Close()
		return nil
	}
}

func serveConnection(connection net.Conn) error {
	defer connection.Close()
	request, err := http.ReadRequest(bufio.NewReader(connection))
	if err != nil {
		return err
	}
	if request.Method != http.MethodConnect {
		return fmt.Errorf("unexpected method %s", request.Method)
	}
	if _, err = io.WriteString(connection, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return err
	}
	_, err = io.Copy(connection, connection)
	return err
}

func runClient(server, target string) error {
	connection, err := net.DialTimeout("tcp", server, 5*time.Second)
	if err != nil {
		return err
	}
	defer connection.Close()
	request, err := http.NewRequest(http.MethodConnect, "http://"+target, nil)
	if err != nil {
		return err
	}
	request.URL.Host = target
	if err = request.Write(connection); err != nil {
		return err
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), request)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("CONNECT rejected: %s", response.Status)
	}
	const payload = "prism-http-connect-external-interop-payload"
	if _, err = io.WriteString(connection, payload); err != nil {
		return err
	}
	_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
	echo := make([]byte, len(payload))
	if _, err = io.ReadFull(connection, echo); err != nil {
		return err
	}
	if string(echo) != payload {
		return fmt.Errorf("echo mismatch: got %q", string(echo))
	}
	fmt.Printf("PASS: Go HTTP CONNECT client echo (%d bytes)\n", len(echo))
	return nil
}

func main() {
	mode := flag.String("mode", "client", "client | server")
	listen := flag.String("listen", "127.0.0.1:19086", "server listen address")
	server := flag.String("server", "127.0.0.1:19086", "client server address")
	target := flag.String("target", "example.com:443", "CONNECT target")
	flag.Parse()

	var err error
	if *mode == "server" {
		err = runServer(*listen)
	} else {
		err = runClient(*server, *target)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
