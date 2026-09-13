// Package main 提供独立 SOCKS5 TCP reference client/server，供 Preview 外部矩阵使用。
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

func encodeAddress(target string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			result := append([]byte{1}, ip4...)
			return append(result, byte(port>>8), byte(port)), nil
		}
		result := append([]byte{4}, ip.To16()...)
		return append(result, byte(port>>8), byte(port)), nil
	}
	if len(host) == 0 || len(host) > 255 {
		return nil, fmt.Errorf("invalid domain")
	}
	result := []byte{3, byte(len(host))}
	result = append(result, host...)
	return append(result, byte(port>>8), byte(port)), nil
}

func readReply(connection net.Conn) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil {
		return err
	}
	if header[0] != 5 || header[1] != 0 {
		return fmt.Errorf("SOCKS5 reply rejected: %d", header[1])
	}
	var addressLength int
	switch header[3] {
	case 1:
		addressLength = 4
	case 3:
		length := make([]byte, 1)
		if _, err := io.ReadFull(connection, length); err != nil {
			return err
		}
		addressLength = int(length[0])
	case 4:
		addressLength = 16
	default:
		return fmt.Errorf("invalid SOCKS5 reply address type")
	}
	address := make([]byte, addressLength+2)
	_, err := io.ReadFull(connection, address)
	return err
}

func runServer(listen string) error {
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	fmt.Printf("READY: Go SOCKS5 server on %s\n", listen)
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
	header := make([]byte, 2)
	if _, err := io.ReadFull(connection, header); err != nil {
		return err
	}
	if header[0] != 5 {
		return fmt.Errorf("invalid SOCKS5 version")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(connection, methods); err != nil {
		return err
	}
	if !contains(methods, 0) {
		_, _ = connection.Write([]byte{5, 255})
		return fmt.Errorf("no anonymous method")
	}
	if _, err := connection.Write([]byte{5, 0}); err != nil {
		return err
	}
	requestHeader := make([]byte, 4)
	if _, err := io.ReadFull(connection, requestHeader); err != nil {
		return err
	}
	if requestHeader[0] != 5 || requestHeader[1] != 1 || requestHeader[2] != 0 {
		return fmt.Errorf("invalid SOCKS5 connect request")
	}
	switch requestHeader[3] {
	case 1:
		address := make([]byte, 6)
		if _, err := io.ReadFull(connection, address); err != nil {
			return err
		}
	case 3:
		length := make([]byte, 1)
		if _, err := io.ReadFull(connection, length); err != nil {
			return err
		}
		address := make([]byte, int(length[0])+2)
		if _, err := io.ReadFull(connection, address); err != nil {
			return err
		}
	case 4:
		address := make([]byte, 18)
		if _, err := io.ReadFull(connection, address); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid SOCKS5 request address type")
	}
	bind := make([]byte, 10)
	bind[0] = 5
	bind[3] = 1
	if _, err := connection.Write(bind); err != nil {
		return err
	}
	_, err := io.Copy(connection, connection)
	return err
}

func contains(values []byte, wanted byte) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func runClient(server, target string) error {
	connection, err := net.DialTimeout("tcp", server, 5*time.Second)
	if err != nil {
		return err
	}
	defer connection.Close()
	if _, err = connection.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	selection := make([]byte, 2)
	if _, err = io.ReadFull(connection, selection); err != nil {
		return err
	}
	if selection[0] != 5 || selection[1] != 0 {
		return fmt.Errorf("SOCKS5 method rejected")
	}
	address, err := encodeAddress(target)
	if err != nil {
		return err
	}
	request := append([]byte{5, 1, 0}, address...)
	if _, err = connection.Write(request); err != nil {
		return err
	}
	if err = readReply(connection); err != nil {
		return err
	}
	const payload = "prism-socks5-external-interop-payload"
	if _, err = connection.Write([]byte(payload)); err != nil {
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
	fmt.Printf("PASS: Go SOCKS5 client echo (%d bytes)\n", len(echo))
	return nil
}

func main() {
	mode := flag.String("mode", "client", "client | server")
	listen := flag.String("listen", "127.0.0.1:19085", "server listen address")
	server := flag.String("server", "127.0.0.1:19085", "client server address")
	target := flag.String("target", "example.com:443", "SOCKS5 target")
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
