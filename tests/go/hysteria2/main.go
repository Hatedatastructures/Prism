// Package main 使用真实 sing-quic hysteria2 客户端（与 mihomo 同栈）验证
// Prism 的 Hysteria2 HTTP/3 认证与 TCP 转发。
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/metacubex/quic-go"
	qtls "github.com/metacubex/sing-quic"
	"github.com/metacubex/sing-quic/hysteria2"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/tls"
)

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
	server := flag.String("server", "127.0.0.1:8081", "Hysteria2 server address")
	password := flag.String("password", "hysteria2_password", "Hysteria2 password")
	udp := flag.Bool("udp", false, "run UDP authenticated echo instead of TCP")
	flag.Parse()

	port, err := echoServer()
	if err != nil {
		fmt.Printf("FAIL: echo server: %v\n", err)
		os.Exit(1)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
		ServerName:         "hysteria",
	}

	// QUIC 拨号器：sing-quic 无默认实现，必须显式提供
	quicDialer := qtls.QuicDialerFunc(func(ctx context.Context, addr string, pDialer qtls.PacketDialer, tlsCfg *tls.Config, cfg *quic.Config, early bool) (net.PacketConn, *quic.Conn, error) {
		addrPort, err := netip.ParseAddrPort(addr)
		if err != nil {
			return nil, nil, err
		}
		packetConn, err := pDialer.ListenPacket(ctx, "udp", "", addrPort)
		if err != nil {
			return nil, nil, err
		}
		transport := quic.Transport{Conn: packetConn}
		transport.SetCreatedConn(true)
		transport.SetSingleUse(true)
		var quicConn *quic.Conn
		if early {
			quicConn, err = transport.DialEarly(ctx, net.UDPAddrFromAddrPort(addrPort), tlsCfg, cfg)
		} else {
			quicConn, err = transport.Dial(ctx, net.UDPAddrFromAddrPort(addrPort), tlsCfg, cfg)
		}
		if err != nil {
			packetConn.Close()
			return nil, nil, err
		}
		return packetConn, quicConn, nil
	})

	// 包监听器：sing-quic 要求提供，否则 packetDialer 为 nil
	packetListener := qtls.PacketDialerFunc(func(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
		return net.ListenUDP(network, nil)
	})

	client, err := hysteria2.NewClient(hysteria2.ClientOptions{
		Context:        context.Background(),
		ServerAddress:  M.ParseSocksaddr(*server),
		Password:       *password,
		TLSConfig:      tlsConfig,
		PacketListener: packetListener,
		QuicDialer:     quicDialer,
		UdpMTU:         1200,
	})
	if err != nil {
		fmt.Printf("FAIL: NewClient: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if *udp {
		packetConn, err := client.ListenPacket(ctx)
		if err != nil {
			fmt.Printf("FAIL: ListenPacket: %v\n", err)
			os.Exit(1)
		}
		defer packetConn.Close()
		target, err := net.ResolveUDPAddr("udp", "127.0.0.1:53")
		if err != nil {
			fmt.Printf("FAIL: UDP target: %v\n", err)
			os.Exit(1)
		}
		payload := []byte("hello hysteria2 udp from go")
		if _, err := packetConn.WriteTo(payload, target); err != nil {
			fmt.Printf("FAIL: UDP write: %v\n", err)
			os.Exit(1)
		}
		buffer := make([]byte, 128)
		packetConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := packetConn.ReadFrom(buffer)
		if err != nil {
			fmt.Printf("FAIL: UDP read echo: %v\n", err)
			os.Exit(1)
		}
		if string(buffer[:n]) != string(payload) {
			fmt.Printf("FAIL: UDP echo mismatch: got %q want %q\n", string(buffer[:n]), string(payload))
			os.Exit(1)
		}
		fmt.Printf("PASS: hysteria2 UDP echo ok (%d bytes)\n", n)
		return
	}

	conn, err := client.DialConn(ctx, M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", port)))
	if err != nil {
		fmt.Printf("FAIL: DialConn: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	payload := "hello hysteria2 from go"
	if _, err := conn.Write([]byte(payload)); err != nil {
		fmt.Printf("FAIL: write: %v\n", err)
		os.Exit(1)
	}

	buf := make([]byte, 128)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Printf("FAIL: read echo: %v\n", err)
		os.Exit(1)
	}
	got := string(buf[:n])
	if got != payload {
		fmt.Printf("FAIL: echo mismatch: got %q want %q\n", got, payload)
		os.Exit(1)
	}
	fmt.Printf("PASS: hysteria2 echo ok (%d bytes)\n", n)
}
