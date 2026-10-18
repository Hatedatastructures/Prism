// Package main 使用真实 metacubex/quic-go + metacubex/tls 复刻 mihomo
// tuic v5 客户端行为（uni 认证流 + bidi Connect 流），验证 Prism 的 TUIC 服务端。
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

const (
	serverAddr = "127.0.0.1:8081"
	password   = "tuic_password"
	uuidHex    = "123e4567-e89b-12d3-a456-426614174000"
	serverName = "tuic"
)

type clientOptions struct {
	Server     string
	Password   string
	Uuid       string
	ServerName string
	Mode       string
	Target     string
	Streams    int
	LocalPort  int
	Retry      int
	Transport  *quic.Transport
}

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

type tcpEcho struct {
	listener  net.Listener
	done      chan struct{}
	mu        sync.Mutex
	closed    bool
	conns     map[net.Conn]struct{}
	workers   sync.WaitGroup
	closeOnce sync.Once
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
			conn.Close()
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
		conn.Close()
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
			if errors.Is(readErr, io.EOF) && len(data) > 0 {
				_ = writeFull(conn, data)
			}
			return
		}
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
		echo.listener.Close()
		for _, conn := range conns {
			conn.Close()
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
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return nil, err
	}
	echo := &udpEcho{conn: conn, done: make(chan struct{}), digest: sha256.New()}
	go echo.serve()
	return echo, nil
}

func (echo *udpEcho) serve() {
	defer close(echo.done)
	buffer := make([]byte, 2048)
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
		echo.conn.Close()
		<-echo.done
	})
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

func connectFrame(port uint16) []byte {
	return []byte{0x05, 0x01, 0x01, 127, 0, 0, 1, byte(port >> 8), byte(port)}
}

func dialQUIC(ctx context.Context, options clientOptions) (*quic.Conn, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
		ServerName:         options.ServerName,
	}
	quicConfig := &quic.Config{EnableDatagrams: true}
	var conn *quic.Conn
	var err error
	if options.Transport != nil {
		remote, resolveErr := net.ResolveUDPAddr("udp4", options.Server)
		if resolveErr != nil {
			return nil, fmt.Errorf("resolve QUIC remote %s: %w", options.Server, resolveErr)
		}
		conn, err = options.Transport.Dial(ctx, remote, tlsConfig, quicConfig)
		if err != nil {
			return nil, fmt.Errorf("quic dial local=%s remote=%s: %w",
				options.Transport.Conn.LocalAddr(), remote, err)
		}
	} else {
		conn, err = quic.DialAddr(ctx, options.Server, tlsConfig, quicConfig)
		if err != nil {
			return nil, fmt.Errorf("quic dial remote=%s: %w", options.Server, err)
		}
	}
	local := conn.LocalAddr()
	if local == nil {
		conn.CloseWithError(1, "missing local address")
		return nil, fmt.Errorf("quic dial mode=%s returned no local address", options.Mode)
	}
	fmt.Printf("DIAL_ATTEMPT=1 RETRY=%d mode=%s\n", options.Retry, options.Mode)
	fmt.Printf("QUIC_LOCAL_ADDR mode=%s local=%s\n", options.Mode, local.String())
	return conn, nil
}

func openAuthenticated(ctx context.Context, options clientOptions, credential string) (*quic.Conn, error) {
	conn, err := dialQUIC(ctx, options)
	if err != nil {
		return nil, err
	}
	if err := writeAuthentication(conn, options.Uuid, credential); err != nil {
		conn.CloseWithError(1, "authentication stream failure")
		return nil, err
	}
	return conn, nil
}

func writeAuthentication(conn *quic.Conn, uuidText, credential string) error {
	uuid := parseUUID(uuidText)
	connectionState := conn.ConnectionState()
	token, err := (&connectionState.TLS).ExportKeyingMaterial(
		string(uuid[:]), []byte(credential), 32)
	if err != nil {
		return fmt.Errorf("export keying material: %w", err)
	}
	stream, err := conn.OpenUniStream()
	if err != nil {
		return fmt.Errorf("open auth stream: %w", err)
	}
	frame := append([]byte{0x05, 0x00}, uuid[:]...)
	frame = append(frame, token...)
	if err := writeFull(stream, frame); err != nil {
		return fmt.Errorf("write auth: %w", err)
	}
	return stream.Close()
}

type tcpExchangeResult struct {
	Bytes   int
	SHA256  string
	FinSent bool
	PeerEOF bool
}

func exchangeTCP(conn *quic.Conn, port uint16, payload []byte) (tcpExchangeResult, error) {
	result := tcpExchangeResult{Bytes: len(payload), SHA256: fmt.Sprintf("%x", sha256.Sum256(payload))}
	stream, err := conn.OpenStream()
	if err != nil {
		return result, fmt.Errorf("open bidi stream: %w", err)
	}
	defer func() { _ = stream.Close() }()
	request := append(connectFrame(port), payload...)
	if err := writeFull(stream, request); err != nil {
		return result, fmt.Errorf("write connect payload: %w", err)
	}
	if err := stream.Close(); err != nil {
		return result, fmt.Errorf("send TCP FIN: %w", err)
	}
	result.FinSent = true
	if err := stream.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return result, fmt.Errorf("set stream read deadline: %w", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, got); err != nil {
		return result, fmt.Errorf("read TCP echo: %w", err)
	}
	if !bytes.Equal(got, payload) {
		return result, fmt.Errorf("TCP echo mismatch: got %q want %q", got, payload)
	}
	probe := []byte{0}
	count, err := stream.Read(probe)
	if count != 0 || !errors.Is(err, io.EOF) {
		return result, fmt.Errorf("peer EOF not observed: bytes=%d error=%v", count, err)
	}
	result.PeerEOF = true
	return result, nil
}

func runTCP(options clientOptions, streamCount int) error {
	echo, err := startTCPEcho()
	if err != nil {
		return fmt.Errorf("start TCP echo: %w", err)
	}
	defer echo.close()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	conn, err := openAuthenticated(ctx, options, options.Password)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = conn.CloseWithError(0, "test complete")
		}
	}()

	type result struct {
		Index    int
		Exchange tcpExchangeResult
		Err      error
	}
	results := make(chan result, streamCount)
	var expectedBytes atomic.Uint64
	var firstErr error
	for index := 0; index < streamCount; index++ {
		go func(streamIndex int) {
			payload := []byte(fmt.Sprintf("prism-tuic-app-tcp-%d", streamIndex))
			if streamCount == 1 {
				payload = []byte("hello tuic v5 from go")
			}
			expectedBytes.Add(uint64(len(payload)))
			exchange, exchangeErr := exchangeTCP(conn, echo.port(), payload)
			results <- result{
				Index:    streamIndex,
				Exchange: exchange,
				Err:      exchangeErr,
			}
		}(index)
	}
	for index := 0; index < streamCount; index++ {
		streamResult := <-results
		if streamResult.Err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("bidi stream %d: %w", streamResult.Index, streamResult.Err)
			}
			continue
		}
		fmt.Printf("PAYLOAD tcp_stream=%d bytes=%d SHA256=%s FIN_SENT=%t PEER_EOF=%t FIN_OWNER=GO_CLIENT_STREAM\n",
			streamResult.Index, streamResult.Exchange.Bytes, streamResult.Exchange.SHA256,
			streamResult.Exchange.FinSent, streamResult.Exchange.PeerEOF)
	}
	echo.close()
	if firstErr != nil {
		return firstErr
	}
	targetBytes, targetHash := echo.summary()
	if got, want := targetBytes, expectedBytes.Load(); got != want {
		return fmt.Errorf("TCP target received %d bytes, want %d", got, want)
	}
	if err := conn.CloseWithError(0, "test complete"); err != nil {
		return fmt.Errorf("close authenticated TCP QUIC connection: %w", err)
	}
	closed = true
	fmt.Printf("TCP_TARGET_SUMMARY bytes=%d SHA256=%s CLOSE_OWNER=GO_CLIENT_QUIC\n", targetBytes, targetHash)
	if streamCount == 1 {
		fmt.Printf("PASS: tuic v5 echo ok (%d bytes) FIN/EOF observed\n", targetBytes)
	} else {
		fmt.Printf("PASS: tcp bidi streams=%d target_bytes=%d FIN/EOF observed\n", streamCount, targetBytes)
	}
	return nil
}

func runBadAuthentication(options clientOptions) error {
	echo, err := startTCPEcho()
	if err != nil {
		return fmt.Errorf("start TCP echo: %w", err)
	}
	defer echo.close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := dialQUIC(ctx, options)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = conn.CloseWithError(0, "bad credential probe complete")
		}
	}()

	stream, err := conn.OpenStream()
	if err != nil {
		return fmt.Errorf("open bidi stream before bad authentication: %w", err)
	}
	defer stream.Close()
	payload := []byte("must-not-reach-tcp-target")
	request := append(connectFrame(echo.port()), payload...)
	if err := writeFull(stream, request); err != nil {
		return fmt.Errorf("write bidi request before bad authentication: %w", err)
	}
	if err := stream.SetReadDeadline(time.Now().Add(8 * time.Second)); err != nil {
		return fmt.Errorf("set bad-auth stream read deadline: %w", err)
	}
	if err := writeAuthentication(conn, options.Uuid, options.Password+"-invalid"); err != nil {
		return fmt.Errorf("write bad authentication uni frame: %w", err)
	}
	fmt.Printf("BAD_AUTH_QUIC_ESTABLISHED=true AUTH_UNI_FRAME_WRITE_COMPLETE=true\n")

	got := make([]byte, len(payload))
	readBytes, readErr := io.ReadFull(stream, got)
	if readErr == nil {
		return fmt.Errorf("invalid credential was accepted; received %q", got)
	}
	var timeoutError net.Error
	if readBytes != 0 || !errors.As(readErr, &timeoutError) || !timeoutError.Timeout() {
		return fmt.Errorf("invalid credential did not produce a zero-byte silent timeout (read=%d): %w",
			readBytes, readErr)
	}
	fmt.Printf("BAD_AUTH_CLOSE=silent_timeout payload_read=%d egress=none\n", readBytes)

	if err := conn.CloseWithError(0, "bad credential rejected"); err != nil {
		return fmt.Errorf("close bad-auth QUIC connection: %w", err)
	}
	closed = true
	echo.close()
	forwarded, targetHash := echo.summary()
	if forwarded != 0 {
		return fmt.Errorf("invalid credential forwarded %d TCP payload bytes hash=%s", forwarded, targetHash)
	}
	fmt.Printf("PASS: bad credential silent timeout / no egress; target_payload_bytes=0 TARGET_SHA256=%s CLOSE_OWNER=GO_CLIENT_QUIC\n", targetHash)
	return nil
}

func makeDatagramFrame(target *net.UDPAddr, payload []byte) ([]byte, error) {
	ip := target.IP.To4()
	if ip == nil || len(payload) > 65535 {
		return nil, fmt.Errorf("TUIC test datagram requires an IPv4 target and payload <= 65535 bytes")
	}
	frame := []byte{0x05, 0x02, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00}
	frame = append(frame, 0x01)
	frame = append(frame, ip...)
	frame = append(frame, byte(target.Port>>8), byte(target.Port))
	binary.BigEndian.PutUint16(frame[8:10], uint16(len(payload)))
	return append(frame, payload...), nil
}

func readDatagramPayload(frame, expected []byte) ([]byte, error) {
	if len(frame) < 17 || frame[0] != 0x05 || frame[1] != 0x02 {
		return nil, fmt.Errorf("malformed TUIC UDP echo frame (%d bytes)", len(frame))
	}
	size := int(binary.BigEndian.Uint16(frame[8:10]))
	if len(frame) < 17+size {
		return nil, fmt.Errorf("truncated TUIC UDP echo frame (%d bytes)", len(frame))
	}
	got := frame[17 : 17+size]
	if !bytes.Equal(got, expected) {
		return nil, fmt.Errorf("UDP echo mismatch: got %q want %q", got, expected)
	}
	return got, nil
}

func runUDPOnly(options clientOptions) error {
	echo, err := startUDPEcho()
	if err != nil {
		return fmt.Errorf("start UDP echo: %w", err)
	}
	defer echo.close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := openAuthenticated(ctx, options, options.Password)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = conn.CloseWithError(0, "UDP-only test complete")
		}
	}()

	payload := []byte("prism-tuic-app-udp-only")
	frame, err := makeDatagramFrame(echo.conn.LocalAddr().(*net.UDPAddr), payload)
	if err != nil {
		return err
	}
	if err := conn.SendDatagram(frame); err != nil {
		return fmt.Errorf("send UDP-only datagram: %w", err)
	}
	response, err := conn.ReceiveDatagram(ctx)
	if err != nil {
		return fmt.Errorf("receive UDP-only echo: %w", err)
	}
	got, err := readDatagramPayload(response, payload)
	if err != nil {
		return err
	}
	targetPackets, targetBytes, targetHash := echo.summary()
	if targetPackets != 1 || targetBytes != uint64(len(payload)) || targetHash != fmt.Sprintf("%x", sha256.Sum256(payload)) {
		return fmt.Errorf("UDP echo observed packets=%d bytes=%d hash=%s", targetPackets, targetBytes, targetHash)
	}
	if err := conn.CloseWithError(0, "UDP-only test complete"); err != nil {
		return fmt.Errorf("close UDP-only QUIC connection: %w", err)
	}
	closed = true
	fmt.Printf("PAYLOAD udp_only packets=1 bytes=%d SHA256=%x TARGET_PACKETS=%d TARGET_BYTES=%d TARGET_SHA256=%s CLOSE_OWNER=GO_CLIENT_QUIC\n",
		len(got), sha256.Sum256(got), targetPackets, targetBytes, targetHash)
	fmt.Printf("PASS: uni-auth UDP-only echo target_packets=%d target_bytes=%d\n",
		targetPackets, targetBytes)
	return nil
}

// runLegacyUDP preserves the old runner's fixed DNS echo target; Prism interop uses udp-only.
func runLegacyUDP(options clientOptions) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := openAuthenticated(ctx, options, options.Password)
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "legacy UDP test complete")

	payload := []byte("hello tuic v5 udp from go")
	target := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
	frame, err := makeDatagramFrame(target, payload)
	if err != nil {
		return err
	}
	if err := conn.SendDatagram(frame); err != nil {
		return fmt.Errorf("send legacy UDP packet: %w", err)
	}
	response, err := conn.ReceiveDatagram(ctx)
	if err != nil {
		return fmt.Errorf("receive legacy UDP echo: %w", err)
	}
	got, err := readDatagramPayload(response, payload)
	if err != nil {
		return err
	}
	fmt.Printf("PASS: tuic v5 UDP echo ok (%d bytes)\n", len(got))
	return nil
}

func runPendingUDP(options clientOptions) error {
	target, err := net.ResolveUDPAddr("udp4", options.Target)
	if err != nil {
		return fmt.Errorf("resolve pending UDP sink: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	conn, err := openAuthenticated(ctx, options, options.Password)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = conn.CloseWithError(0, "pending UDP test complete")
		}
	}()
	payload := []byte("prism-tuic-pending-egress")
	frame, err := makeDatagramFrame(target, payload)
	if err != nil {
		return err
	}
	if err := conn.SendDatagram(frame); err != nil {
		return fmt.Errorf("send pending UDP datagram: %w", err)
	}
	fmt.Printf("PENDING_UDP_SENT target=%s bytes=%d SHA256=%x\n", target.String(), len(payload), sha256.Sum256(payload))

	command, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return fmt.Errorf("wait for runner close gate: %w", err)
	}
	if command != "close\n" && command != "close\r\n" {
		return fmt.Errorf("unexpected runner close command %q", command)
	}
	if err := conn.CloseWithError(0, "cancel pending datagram egress"); err != nil {
		return fmt.Errorf("close pending UDP QUIC connection: %w", err)
	}
	closed = true
	fmt.Printf("PASS: pending UDP connection closed after sink receipt CLOSE_OWNER=GO_CLIENT_QUIC\n")
	return nil
}

func runAuthClose(options clientOptions) error {
	echo, err := startTCPEcho()
	if err != nil {
		return fmt.Errorf("start auth-close TCP egress probe: %w", err)
	}
	defer echo.close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := openAuthenticated(ctx, options, options.Password)
	if err != nil {
		return err
	}
	if err := conn.CloseWithError(0, "authenticated connection close probe"); err != nil {
		return fmt.Errorf("close auth-close QUIC connection: %w", err)
	}
	echo.close()
	targetBytes, targetHash := echo.summary()
	if targetBytes != 0 {
		return fmt.Errorf("auth-close produced TCP egress bytes=%d hash=%s", targetBytes, targetHash)
	}
	fmt.Printf("AUTH_CLOSE_EGRESS=0 TARGET_BYTES=%d TARGET_SHA256=%s CLOSE_OWNER=GO_CLIENT_QUIC\n", targetBytes, targetHash)
	fmt.Printf("PASS: authenticated uni-only connection closed without egress\n")
	return nil
}

func run(options clientOptions) error {
	if options.Retry != 0 {
		return fmt.Errorf("retry must be 0 for the Application runner contract, got %d", options.Retry)
	}
	if options.ServerName == "" {
		options.ServerName = serverName
	}
	switch options.Mode {
	case "tcp":
		return runTCP(options, 1)
	case "concurrent-bidi":
		if options.Streams < 2 || options.Streams > 16 {
			return fmt.Errorf("concurrent-bidi requires -streams between 2 and 16")
		}
		return runTCP(options, options.Streams)
	case "bad-auth":
		return runBadAuthentication(options)
	case "udp-only":
		return runUDPOnly(options)
	case "legacy-udp":
		return runLegacyUDP(options)
	case "udp-pending":
		if options.Target == "" {
			return fmt.Errorf("udp-pending requires -target host:port")
		}
		return runPendingUDP(options)
	case "auth-close":
		return runAuthClose(options)
	default:
		return fmt.Errorf("unknown TUIC mode %q", options.Mode)
	}
}

func runWithLocalPort(options clientOptions) (runErr error) {
	if options.LocalPort < 0 || options.LocalPort > 65535 {
		return fmt.Errorf("invalid QUIC local UDP port %d", options.LocalPort)
	}
	if options.LocalPort == 0 {
		return run(options)
	}
	localAddress := fmt.Sprintf("127.0.0.1:%d", options.LocalPort)
	packetConn, err := net.ListenPacket("udp4", localAddress)
	if err != nil {
		return fmt.Errorf("bind QUIC local UDP %s: %w", localAddress, err)
	}
	transport := &quic.Transport{Conn: packetConn}
	options.Transport = transport
	defer func() {
		if err := transport.Close(); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("close QUIC transport: %w", err))
		}
		if err := packetConn.Close(); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("close QUIC local UDP socket: %w", err))
		}
	}()
	return run(options)
}

func main() {
	server := flag.String("server", serverAddr, "TUIC server address")
	pass := flag.String("password", password, "TUIC password")
	uuidValue := flag.String("uuid", uuidHex, "TUIC UUID")
	name := flag.String("servername", serverName, "TLS server name")
	mode := flag.String("mode", "", "tcp, concurrent-bidi, bad-auth, udp-only, udp-pending, or auth-close")
	target := flag.String("target", "", "target for udp-pending")
	streams := flag.Int("streams", 4, "concurrent bidi stream count")
	localPort := flag.Int("local-port", 0, "optional loopback UDP source port")
	retry := flag.Int("retry", 0, "dial retry count; Application runner requires zero")
	legacyUDP := flag.Bool("udp", false, "legacy alias for the original UDP DNS echo probe")
	flag.Parse()
	selectedMode := *mode
	if selectedMode == "" {
		if *legacyUDP {
			selectedMode = "legacy-udp"
		} else {
			selectedMode = "tcp"
		}
	}
	options := clientOptions{
		Server:     *server,
		Password:   *pass,
		Uuid:       *uuidValue,
		ServerName: *name,
		Mode:       selectedMode,
		Target:     *target,
		Streams:    *streams,
		LocalPort:  *localPort,
		Retry:      *retry,
	}
	if err := runWithLocalPort(options); err != nil {
		fmt.Printf("FAIL: %v\n", err)
		os.Exit(1)
	}
}
