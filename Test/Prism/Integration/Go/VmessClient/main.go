// Package main 用 mihomo transport/vmess（真实客户端实现）提供 VMess 客户端，
// 验证 Prism VMess TCP/UDP 生产互操作（SS2022 探测回退路径）。
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/metacubex/mihomo/transport/vmess"
)

const uuid = "123e4567-e89b-12d3-a456-426614174000"

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
			n, addr, e := conn.ReadFrom(buf)
			if e != nil {
				return
			}
			_, _ = conn.WriteTo(buf[:n], addr)
		}
	}()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port), nil
}

func testTCP(client *vmess.Client, addr string, echoPort uint16) error {
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer raw.Close()

	ss, err := client.StreamConn(raw, &vmess.DstAddr{
		UDP:      false,
		AddrType: vmess.AtypIPv4,
		Addr:     []byte{127, 0, 0, 1},
		Port:     uint(echoPort),
	})
	if err != nil {
		return fmt.Errorf("StreamConn: %w", err)
	}
	defer ss.Close()

	payload := "hello interop vmess from mihomo"
	if _, err := ss.Write([]byte(payload)); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	buf := make([]byte, 256)
	ss.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := ss.Read(buf)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if string(buf[:n]) != payload {
		return fmt.Errorf("echo mismatch: got %q", string(buf[:n]))
	}
	fmt.Printf("PASS: vmess tcp echo ok (%d bytes)\n", n)
	return nil
}

func testUDP(client *vmess.Client, addr string, echoPort uint16) error {
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer raw.Close()

	ss, err := client.StreamConn(raw, &vmess.DstAddr{
		UDP:      true,
		AddrType: vmess.AtypIPv4,
		Addr:     []byte{127, 0, 0, 1},
		Port:     uint(echoPort),
	})
	if err != nil {
		return fmt.Errorf("StreamConn: %w", err)
	}
	defer ss.Close()

	// VMess UDP：目标地址由请求头携带，数据包为裸载荷
	payload := "hello interop vmess udp"
	if _, err := ss.Write([]byte(payload)); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	buf := make([]byte, 512)
	ss.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := ss.Read(buf)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if string(buf[:n]) != payload {
		return fmt.Errorf("echo mismatch: got %q", string(buf[:n]))
	}
	fmt.Printf("PASS: vmess udp echo ok (%d bytes)\n", n)
	return nil
}

func main() {
	echoPort, err := echoServer()
	if err != nil {
		fmt.Printf("FAIL: echo server: %v\n", err)
		os.Exit(1)
	}
	udpPort, err := udpEchoServer()
	if err != nil {
		fmt.Printf("FAIL: udp echo server: %v\n", err)
		os.Exit(1)
	}

	client, err := vmess.NewClient(vmess.Config{
		UUID:     uuid,
		AlterID:  0,
		Security: "auto",
		IsAead:   true,
	})
	if err != nil {
		fmt.Printf("FAIL: NewClient: %v\n", err)
		os.Exit(1)
	}

	addr := "127.0.0.1:8081"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	if err := testTCP(client, addr, echoPort); err != nil {
		fmt.Printf("FAIL: tcp: %v\n", err)
		os.Exit(1)
	}
	if err := testUDP(client, addr, udpPort); err != nil {
		fmt.Printf("FAIL: udp: %v\n", err)
		os.Exit(1)
	}
}
