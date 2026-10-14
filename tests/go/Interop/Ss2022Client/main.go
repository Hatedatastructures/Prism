// Package main 用 sing-shadowsocks v0.2.12（与 mihomo 同栈）提供真实 SS2022 客户端，
// 供 C++ common 服务端互操作验证。
package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/metacubex/sing-shadowsocks/shadowaead_2022"
	M "github.com/metacubex/sing/common/metadata"
)

const psk = "5n5ESu953i/pjIp02oZvHA=="

// OwnedConn 是唯一底层关闭 owner；标准库协议 reader/writer 可共享它，实际关闭只执行一次。
type OwnedConn struct {
	net.Conn
	Once       sync.Once
	CloseError error
	CloseCount int
}

func (c *OwnedConn) Close() error {
	c.Once.Do(func() {
		c.CloseCount++
		c.CloseError = c.Conn.Close()
	})
	return c.CloseError
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
	nativeTLS := false
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	for _, arg := range os.Args[2:] {
		if arg == "--native-tls" {
			nativeTLS = true
		}
	}
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Printf("FAIL: dial: %v\n", err)
		os.Exit(1)
	}
	underlying := raw
	var tlsConn *tls.Conn
	if nativeTLS {
		tlsConn = tls.Client(raw, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "ss2022.preview",
			MinVersion:         tls.VersionTLS13,
		})
		if err := tlsConn.Handshake(); err != nil {
			fmt.Printf("FAIL: native TLS handshake: %v\n", err)
			os.Exit(1)
		}
		raw = tlsConn
	}
	owner := &OwnedConn{Conn: raw}
	ss, err := method.DialConn(owner, M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", echoPort)))
	if err != nil {
		fmt.Printf("FAIL: DialConn: %v\n", err)
		os.Exit(1)
	}
	payload := "hello interop ss2022 from go"
	if _, err := ss.Write([]byte(payload)); err != nil {
		fmt.Printf("FAIL: write: %v\n", err)
		os.Exit(1)
	}
	buf := make([]byte, len(payload))
	ss.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := io.ReadFull(ss, buf)
	if err != nil {
		fmt.Printf("FAIL: read: %v\n", err)
		os.Exit(1)
	}
	if string(buf[:n]) != payload {
		fmt.Printf("FAIL: echo mismatch: got %q\n", string(buf[:n]))
		os.Exit(1)
	}
	if err := ss.Close(); err != nil {
		fmt.Printf("FAIL: SS close: %v\n", err)
		os.Exit(1)
	}
	if owner.CloseCount != 1 {
		fmt.Printf("FAIL: underlying close count: %d\n", owner.CloseCount)
		os.Exit(1)
	}
	var closedProbe [1]byte
	if _, err := underlying.Read(closedProbe[:]); !errors.Is(err, net.ErrClosed) {
		fmt.Printf("FAIL: underlying transport remains open: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("CLOSE: underlying=1 tls=%t descriptor_closed=true\n", nativeTLS)
	fmt.Printf("PASS: interop ss2022 echo ok (%d bytes)\n", n)
}
