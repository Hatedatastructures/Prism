// Package main 使用真实 sing-quic hysteria2 客户端（与 mihomo 同栈）验证
// Prism 的 Hysteria2 HTTP/3 认证、TCP 半关闭和 UDP 转发。
package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/quic-go"
	qtls "github.com/metacubex/sing-quic"
	"github.com/metacubex/sing-quic/hysteria2"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"github.com/metacubex/tls"
)

type tcpEcho struct {
	listener  net.Listener
	done      chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
	closed    bool
	conns     map[net.Conn]struct{}
	workers   sync.WaitGroup
	bytes     atomic.Uint64
	digest    hash.Hash
}

func startTCPEcho() (*tcpEcho, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	echo := &tcpEcho{
		listener: listener,
		done:     make(chan struct{}),
		conns:    make(map[net.Conn]struct{}),
		digest:   sha256.New(),
	}
	go echo.accept()
	return echo, nil
}

func (echo *tcpEcho) accept() {
	defer close(echo.done)
	for {
		conn, err := echo.listener.Accept()
		if err != nil {
			return
		}
		echo.mu.Lock()
		if echo.closed {
			echo.mu.Unlock()
			_ = conn.Close()
			continue
		}
		echo.conns[conn] = struct{}{}
		echo.workers.Add(1)
		echo.mu.Unlock()
		go echo.handle(conn)
	}
}

func (echo *tcpEcho) handle(conn net.Conn) {
	defer echo.workers.Done()
	defer func() {
		_ = conn.Close()
		echo.mu.Lock()
		delete(echo.conns, conn)
		echo.mu.Unlock()
	}()
	data := make([]byte, 0, 256)
	buffer := make([]byte, 4096)
	for {
		count, readErr := conn.Read(buffer)
		if count > 0 {
			data = append(data, buffer[:count]...)
			echo.mu.Lock()
			echo.bytes.Add(uint64(count))
			_, _ = echo.digest.Write(buffer[:count])
			echo.mu.Unlock()
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return
		}
	}
	if len(data) > 0 {
		_ = writeFull(conn, data)
	}
}

func (echo *tcpEcho) close() {
	echo.closeOnce.Do(func() {
		echo.mu.Lock()
		echo.closed = true
		conns := make([]net.Conn, 0, len(echo.conns))
		for conn := range echo.conns {
			conns = append(conns, conn)
		}
		echo.mu.Unlock()
		_ = echo.listener.Close()
		for _, conn := range conns {
			_ = conn.Close()
		}
		<-echo.done
		echo.workers.Wait()
	})
}

func (echo *tcpEcho) port() uint16 {
	return uint16(echo.listener.Addr().(*net.TCPAddr).Port)
}

func (echo *tcpEcho) summary() (uint64, string) {
	echo.mu.Lock()
	defer echo.mu.Unlock()
	return echo.bytes.Load(), fmt.Sprintf("%x", echo.digest.Sum(nil))
}

type udpEcho struct {
	conn      *net.UDPConn
	done      chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
	packets   atomic.Uint64
	bytes     atomic.Uint64
	digest    hash.Hash
}

func startUDPEcho() (*udpEcho, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	echo := &udpEcho{conn: conn, done: make(chan struct{}), digest: sha256.New()}
	go echo.serve()
	return echo, nil
}

func (echo *udpEcho) serve() {
	defer close(echo.done)
	buffer := make([]byte, 64*1024)
	for {
		count, peer, err := echo.conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		echo.mu.Lock()
		echo.packets.Add(1)
		echo.bytes.Add(uint64(count))
		_, _ = echo.digest.Write(buffer[:count])
		echo.mu.Unlock()
		written, err := echo.conn.WriteToUDP(buffer[:count], peer)
		if err != nil || written != count {
			return
		}
	}
}

func (echo *udpEcho) close() {
	echo.closeOnce.Do(func() {
		_ = echo.conn.Close()
		<-echo.done
	})
}

func (echo *udpEcho) port() uint16 {
	return uint16(echo.conn.LocalAddr().(*net.UDPAddr).Port)
}

func (echo *udpEcho) summary() (uint64, uint64, string) {
	echo.mu.Lock()
	defer echo.mu.Unlock()
	return echo.packets.Load(), echo.bytes.Load(), fmt.Sprintf("%x", echo.digest.Sum(nil))
}

func writeFull(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

func readUntilEOF(conn net.Conn) ([]byte, bool, error) {
	data := make([]byte, 0, 256)
	buffer := make([]byte, 4096)
	for {
		count, err := conn.Read(buffer)
		if count > 0 {
			data = append(data, buffer[:count]...)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return data, true, nil
			}
			return data, false, err
		}
	}
}

func payloadHash(payload []byte) string {
	sum := sha256.Sum256(payload)
	return fmt.Sprintf("%x", sum[:])
}

func newClient(server, password string) (*hysteria2.Client, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
		ServerName:         "hysteria",
	}
	quicDialer := qtls.QuicDialerFunc(func(ctx context.Context, addr string, pDialer qtls.PacketDialer, tlsCfg *tls.Config, cfg *quic.Config, early bool) (net.PacketConn, *quic.Conn, error) {
		addrPort, err := netip.ParseAddrPort(addr)
		if err != nil {
			return nil, nil, err
		}
		packetConn, err := net.ListenUDP("udp4", nil)
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
			_ = packetConn.Close()
			return nil, nil, err
		}
		return packetConn, quicConn, nil
	})
	packetListener := qtls.PacketDialerFunc(func(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
		return net.ListenUDP(network, nil)
	})
	return hysteria2.NewClient(hysteria2.ClientOptions{
		Context:        context.Background(),
		ServerAddress:  M.ParseSocksaddr(server),
		Password:       password,
		TLSConfig:      tlsConfig,
		PacketListener: packetListener,
		QuicDialer:     quicDialer,
		UdpMTU:         1200,
	})
}

func runTCP(server, password string) error {
	echo, err := startTCPEcho()
	if err != nil {
		return fmt.Errorf("start TCP echo: %w", err)
	}
	defer echo.close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client, err := newClient(server, password)
	if err != nil {
		return fmt.Errorf("new Hysteria2 client: %w", err)
	}
	conn, err := client.DialConn(ctx, M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", echo.port())))
	if err != nil {
		return fmt.Errorf("DialConn: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = conn.Close()
		}
	}()
	payload := []byte("hello hysteria2 from go")
	if err := writeFull(conn, payload[:len(payload)/2]); err != nil {
		return fmt.Errorf("write first TCP payload segment: %w", err)
	}
	if err := writeFull(conn, payload[len(payload)/2:]); err != nil {
		return fmt.Errorf("write second TCP payload segment: %w", err)
	}
	if _, ok := conn.(N.WriteCloser); !ok {
		return fmt.Errorf("Hysteria2 TCP connection has no CloseWrite contract")
	}
	if err := N.CloseWrite(conn); err != nil {
		return fmt.Errorf("send TCP FIN: %w", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return fmt.Errorf("set TCP read deadline: %w", err)
	}
	got, peerEOF, err := readUntilEOF(conn)
	if err != nil {
		return fmt.Errorf("read TCP echo: %w", err)
	}
	if !peerEOF || string(got) != string(payload) {
		return fmt.Errorf("TCP echo mismatch bytes=%d eof=%t", len(got), peerEOF)
	}
	targetBytes, targetHash := echo.summary()
	if targetBytes != uint64(len(payload)) || targetHash != payloadHash(payload) {
		return fmt.Errorf("TCP target observed bytes=%d hash=%s", targetBytes, targetHash)
	}
	if err := conn.Close(); err != nil {
		return fmt.Errorf("close TCP connection: %w", err)
	}
	closed = true
	fmt.Printf("PAYLOAD TCP bytes=%d SHA256=%s FIN_SENT=true PEER_EOF=%t TARGET_BYTES=%d TARGET_SHA256=%s CLOSE_OWNER=GO_CLIENT\n",
		len(got), payloadHash(got), peerEOF, targetBytes, targetHash)
	fmt.Printf("PASS: Hysteria2 authenticated TCP echo with half-close bytes=%d\n", len(got))
	return nil
}

func runUDP(server, password string) error {
	echo, err := startUDPEcho()
	if err != nil {
		return fmt.Errorf("start UDP echo: %w", err)
	}
	defer echo.close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client, err := newClient(server, password)
	if err != nil {
		return fmt.Errorf("new Hysteria2 client: %w", err)
	}
	packetConn, err := client.ListenPacket(ctx)
	if err != nil {
		return fmt.Errorf("ListenPacket: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = packetConn.Close()
		}
	}()
	payload := []byte("hello hysteria2 udp from go")
	target, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("127.0.0.1:%d", echo.port()))
	if err != nil {
		return fmt.Errorf("resolve UDP target: %w", err)
	}
	if _, err := packetConn.WriteTo(payload, target); err != nil {
		return fmt.Errorf("write UDP payload: %w", err)
	}
	if err := packetConn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return fmt.Errorf("set UDP read deadline: %w", err)
	}
	buffer := make([]byte, 128)
	count, _, err := packetConn.ReadFrom(buffer)
	if err != nil {
		return fmt.Errorf("read UDP echo: %w", err)
	}
	got := buffer[:count]
	if string(got) != string(payload) {
		return fmt.Errorf("UDP echo mismatch: got %q want %q", got, payload)
	}
	targetPackets, targetBytes, targetHash := echo.summary()
	if targetPackets != 1 || targetBytes != uint64(len(payload)) || targetHash != payloadHash(payload) {
		return fmt.Errorf("UDP target observed packets=%d bytes=%d hash=%s", targetPackets, targetBytes, targetHash)
	}
	if err := packetConn.Close(); err != nil {
		return fmt.Errorf("close UDP packet connection: %w", err)
	}
	closed = true
	fmt.Printf("PAYLOAD UDP bytes=%d SHA256=%s TARGET_PACKETS=%d TARGET_BYTES=%d TARGET_SHA256=%s CLOSE_OWNER=GO_CLIENT\n",
		len(got), payloadHash(got), targetPackets, targetBytes, targetHash)
	fmt.Printf("PASS: Hysteria2 authenticated UDP echo bytes=%d\n", len(got))
	return nil
}

func runBadAuthentication(server, password string) error {
	echo, err := startTCPEcho()
	if err != nil {
		return fmt.Errorf("start bad-auth TCP echo: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := newClient(server, password)
	if err != nil {
		return fmt.Errorf("new bad-auth Hysteria2 client: %w", err)
	}
	conn, dialErr := client.DialConn(ctx, M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", echo.port())))
	if dialErr == nil {
		_ = conn.Close()
		echo.close()
		return fmt.Errorf("bad authentication unexpectedly opened a TCP egress connection")
	}
	echo.close()
	targetBytes, targetHash := echo.summary()
	emptyHash := payloadHash(nil)
	if targetBytes != 0 || targetHash != emptyHash {
		return fmt.Errorf("bad authentication forwarded TCP bytes=%d hash=%s", targetBytes, targetHash)
	}
	fmt.Printf("BAD_AUTH_CLOSE=dial_rejected egress=none target_bytes=%d TARGET_SHA256=%s CLOSE_OWNER=GO_CLIENT\n",
		targetBytes, targetHash)
	fmt.Printf("PASS: Hysteria2 bad authentication no egress target_bytes=0\n")
	return nil
}

func main() {
	server := flag.String("server", "127.0.0.1:8081", "Hysteria2 server address")
	password := flag.String("password", "hysteria2_password", "Hysteria2 password")
	mode := flag.String("mode", "", "tcp, udp, or bad-auth")
	legacyUDP := flag.Bool("udp", false, "legacy alias for authenticated UDP echo")
	flag.Parse()
	selectedMode := *mode
	if selectedMode == "" {
		if *legacyUDP {
			selectedMode = "udp"
		} else {
			selectedMode = "tcp"
		}
	}
	var err error
	switch selectedMode {
	case "tcp":
		err = runTCP(*server, *password)
	case "udp":
		err = runUDP(*server, *password)
	case "bad-auth":
		err = runBadAuthentication(*server, *password)
	default:
		err = fmt.Errorf("unknown Hysteria2 mode %q", selectedMode)
	}
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
		os.Exit(1)
	}
}
