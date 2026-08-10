// Package main 使用真实 metacubex/quic-go + metacubex/tls 复刻 mihomo
// tuic v5 客户端行为（uni 认证流 + bidi Connect 流），验证 Prism 的 TUIC 服务端。
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

const (
	serverAddr = "127.0.0.1:8081"
	password   = "tuic_password"
	uuidHex    = "123e4567-e89b-12d3-a456-426614174000"
)

// parseUUID 解析 36 字符 UUID 为 16 字节
func parseUUID(hex string) [16]byte {
	var out [16]byte
	idx := 0
	hi := true
	var nibble byte
	for i := 0; i < len(hex); i++ {
		c := hex[i]
		if c == '-' {
			continue
		}
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			panic("bad uuid")
		}
		if hi {
			nibble = d << 4
			hi = false
		} else {
			out[idx] = nibble | d
			idx++
			hi = true
		}
	}
	return out
}

func echoServer() (uint16, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func(c net.Conn) {
				io.Copy(c, c)
				c.Close()
			}(c)
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port), nil
}

func main() {
	port, err := echoServer()
	if err != nil {
		fmt.Printf("FAIL: echo server: %v\n", err)
		os.Exit(1)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
		ServerName:         "tuic",
	}
	quicConfig := &quic.Config{
		EnableDatagrams: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	quicConn, err := quic.DialAddr(ctx, serverAddr, tlsConfig, quicConfig)
	if err != nil {
		fmt.Printf("FAIL: quic dial: %v\n", err)
		os.Exit(1)
	}
	defer quicConn.CloseWithError(0, "")

	// 1. 认证（uni 流）：[VER 0x05][TYPE 0x00][UUID 16B][TOKEN 32B]
	uuid := parseUUID(uuidHex)
	cs := quicConn.ConnectionState()
	token, err := (&cs.TLS).ExportKeyingMaterial(string(uuid[:]), []byte(password), 32)
	if err != nil {
		fmt.Printf("FAIL: export keying material: %v\n", err)
		os.Exit(1)
	}

	authStream, err := quicConn.OpenUniStream()
	if err != nil {
		fmt.Printf("FAIL: open uni stream: %v\n", err)
		os.Exit(1)
	}
	auth := append([]byte{0x05, 0x00}, uuid[:]...)
	auth = append(auth, token...)
	if _, err := authStream.Write(auth); err != nil {
		fmt.Printf("FAIL: write auth: %v\n", err)
		os.Exit(1)
	}
	authStream.Close()

	// 2. Connect（bidi 流）：[VER 0x05][TYPE 0x01][ATYP 0x01][IPv4 4B][PORT 2B]
	connStream, err := quicConn.OpenStream()
	if err != nil {
		fmt.Printf("FAIL: open stream: %v\n", err)
		os.Exit(1)
	}
	connect := []byte{0x05, 0x01, 0x01, 127, 0, 0, 1, byte(port >> 8), byte(port & 0xFF)}
	if _, err := connStream.Write(connect); err != nil {
		fmt.Printf("FAIL: write connect: %v\n", err)
		os.Exit(1)
	}

	payload := "hello tuic v5 from go"
	if _, err := connStream.Write([]byte(payload)); err != nil {
		fmt.Printf("FAIL: write payload: %v\n", err)
		os.Exit(1)
	}

	buf := make([]byte, 128)
	connStream.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := connStream.Read(buf)
	if err != nil {
		fmt.Printf("FAIL: read echo: %v\n", err)
		os.Exit(1)
	}
	got := string(buf[:n])
	if got != payload {
		fmt.Printf("FAIL: echo mismatch: got %q want %q\n", got, payload)
		os.Exit(1)
	}
	fmt.Printf("PASS: tuic v5 echo ok (%d bytes)\n", n)
}
