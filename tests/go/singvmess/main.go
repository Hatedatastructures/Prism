// Package main 使用 metacubex/sing-vmess（mihomo 生产同栈，默认启用
// ChunkMasking + ChunkStream）验证 Prism VMess TCP/UDP 互操作。
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/metacubex/sing-vmess"
	M "github.com/metacubex/sing/common/metadata"
)

const (
	uuid = "123e4567-e89b-12d3-a456-426614174000"
	addr = "127.0.0.1:8081"
)

// serverAddr 服务端地址（可被命令行参数覆盖）
var serverAddr = addr

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

func udpEchoServer() (uint16, error) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, a, e := conn.ReadFrom(buf)
			if e != nil {
				return
			}
			_, _ = conn.WriteTo(buf[:n], a)
		}
	}()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port), nil
}

func testTCP() error {
	tcpPort, err := echoServer()
	if err != nil {
		return err
	}
	raw, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer raw.Close()

	client, err := vmess.NewClient(uuid, "auto", 0)
	if err != nil {
		return fmt.Errorf("NewClient: %w", err)
	}
	conn, err := client.DialConn(raw, M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", tcpPort)))
	if err != nil {
		return fmt.Errorf("DialConn: %w", err)
	}
	defer conn.Close()

	payload := "hello sing-vmess masking tcp"
	if _, err := conn.Write([]byte(payload)); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	buf := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if string(buf[:n]) != payload {
		return fmt.Errorf("echo mismatch: got %q", string(buf[:n]))
	}
	fmt.Printf("PASS: sing-vmess tcp echo ok (%d bytes)\n", n)
	return nil
}

func testUDP() error {
	udpPort, err := udpEchoServer()
	if err != nil {
		return err
	}
	raw, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer raw.Close()

	client, err := vmess.NewClient(uuid, "auto", 0)
	if err != nil {
		return fmt.Errorf("NewClient: %w", err)
	}
	pc, err := client.DialPacketConn(raw, M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", udpPort)))
	if err != nil {
		return fmt.Errorf("DialPacketConn: %w", err)
	}
	defer pc.Close()

	payload := "hello sing-vmess masking udp"
	pc.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := pc.Write([]byte(payload)); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	buf := make([]byte, 512)
	n, err := pc.Read(buf)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if string(buf[:n]) != payload {
		return fmt.Errorf("echo mismatch: got %q", string(buf[:n]))
	}
	fmt.Printf("PASS: sing-vmess udp echo ok (%d bytes)\n", n)
	return nil
}

func main() {
	if len(os.Args) > 1 {
		serverAddr = os.Args[1]
	}
	if err := testTCP(); err != nil {
		fmt.Printf("FAIL: tcp: %v\n", err)
		os.Exit(1)
	}
	if err := testUDP(); err != nil {
		fmt.Printf("FAIL: udp: %v\n", err)
		os.Exit(1)
	}
}
