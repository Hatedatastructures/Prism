// Package main 用 sing-shadowsocks v0.2.12（与 mihomo 同栈）提供真实 SS2022 客户端，
// 供 C++ common 服务端互操作验证。
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing-shadowsocks/shadowaead_2022"
)

const psk = "5n5ESu953i/pjIp02oZvHA=="

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
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}(c)
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port), nil
}

func main() {
	echoPort, err := echoServer()
	if err != nil {
		fmt.Printf("FAIL: echo server: %v\n", err)
		os.Exit(1)
	}

	method, err := shadowaead_2022.NewWithPassword("2022-blake3-aes-128-gcm", psk, time.Now)
	if err != nil {
		fmt.Printf("FAIL: CreateMethod: %v\n", err)
		os.Exit(1)
	}

	addr := "127.0.0.1:19080"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Printf("FAIL: dial: %v\n", err)
		os.Exit(1)
	}
	ss, err := method.DialConn(raw, M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", echoPort)))
	if err != nil {
		fmt.Printf("FAIL: DialConn: %v\n", err)
		os.Exit(1)
	}
	defer ss.Close()

	payload := "hello interop ss2022 from go"
	if _, err := ss.Write([]byte(payload)); err != nil {
		fmt.Printf("FAIL: write: %v\n", err)
		os.Exit(1)
	}
	buf := make([]byte, 128)
	ss.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := ss.Read(buf)
	if err != nil {
		fmt.Printf("FAIL: read: %v\n", err)
		os.Exit(1)
	}
	if string(buf[:n]) != payload {
		fmt.Printf("FAIL: echo mismatch: got %q\n", string(buf[:n]))
		os.Exit(1)
	}
	fmt.Printf("PASS: interop ss2022 echo ok (%d bytes)\n", n)
}
