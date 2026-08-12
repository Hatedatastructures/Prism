// trojan 互操作测试工具（对齐 mihomo transport/trojan wire 格式）
//
// 服务端模式：-mode server -listen 127.0.0.1:port -pass pw
//   TCP：握手后隧道回显（io.Copy 双向）
//   UDP：ReadPacket/WritePacket 回显
// 客户端模式：-mode client -server 127.0.0.1:port -pass pw -target host:port [-udp]
//   握手后与 stdin/stdout 转发（由外部驱动数据流）
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

const (
	cmdTCP = byte(1)
	cmdUDP = byte(3)
)

// 凭据：SHA224 hex（56 字符）
func credential(password string) string {
	sum := sha256.Sum224([]byte(password))
	return hex.EncodeToString(sum[:])
}

// 地址编码（SOCKS5 ATYP：1=IPv4 3=Domain 4=IPv6）
func encodeAddr(host string, port int) []byte {
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		b := []byte{1}
		b = append(b, ip4...)
		return append(b, byte(port>>8), byte(port))
	}
	if ip != nil {
		b := []byte{4}
		return append(append(b, ip.To16()...), byte(port>>8), byte(port))
	}
	b := []byte{3, byte(len(host))}
	b = append(b, host...)
	return append(b, byte(port>>8), byte(port))
}

// 客户端握手：hex + CRLF + cmd + addr + CRLF
func writeHeader(w io.Writer, hexCred string, cmd byte, host string, port int) error {
	buf := append([]byte(hexCred), '\r', '\n', cmd)
	buf = append(buf, encodeAddr(host, port)...)
	buf = append(buf, '\r', '\n')
	_, err := w.Write(buf)
	return err
}

// 服务端握手：读并校验
func readHeader(r io.Reader, wantCred string) (byte, string, int, error) {
	hdr := make([]byte, 56+2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, "", 0, err
	}
	if string(hdr[:56]) != wantCred {
		return 0, "", 0, fmt.Errorf("bad credential")
	}
	if hdr[56] != '\r' || hdr[57] != '\n' {
		return 0, "", 0, fmt.Errorf("bad crlf")
	}
	one := make([]byte, 1)
	if _, err := io.ReadFull(r, one); err != nil {
		return 0, "", 0, err
	}
	cmd := one[0]
	atyp := make([]byte, 1)
	if _, err := io.ReadFull(r, atyp); err != nil {
		return 0, "", 0, err
	}
	var host string
	switch atyp[0] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return 0, "", 0, err
		}
		host = net.IP(b).String()
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return 0, "", 0, err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return 0, "", 0, err
		}
		host = string(b)
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return 0, "", 0, err
		}
		host = net.IP(b).String()
	default:
		return 0, "", 0, fmt.Errorf("bad atyp")
	}
	portB := make([]byte, 2)
	if _, err := io.ReadFull(r, portB); err != nil {
		return 0, "", 0, err
	}
	port := int(binary.BigEndian.Uint16(portB))
	crlf := make([]byte, 2)
	if _, err := io.ReadFull(r, crlf); err != nil {
		return 0, "", 0, err
	}
	if crlf[0] != '\r' || crlf[1] != '\n' {
		return 0, "", 0, fmt.Errorf("bad tail crlf")
	}
	return cmd, host, port, nil
}

// UDP 帧：读 [addr][len 2][CRLF][payload]
func readPacket(r io.Reader, max int) ([]byte, []byte, error) {
	buf := make([]byte, 0, 512)
	atyp := make([]byte, 1)
	if _, err := io.ReadFull(r, atyp); err != nil {
		return nil, nil, err
	}
	buf = append(buf, atyp[0])
	var hostLen int
	switch atyp[0] {
	case 1:
		hostLen = 4
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return nil, nil, err
		}
		buf = append(buf, l[0])
		hostLen = int(l[0])
	case 4:
		hostLen = 16
	default:
		return nil, nil, fmt.Errorf("bad atyp")
	}
	b := make([]byte, hostLen+2)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, nil, err
	}
	buf = append(buf, b...)
	addr := buf
	lenB := make([]byte, 2)
	if _, err := io.ReadFull(r, lenB); err != nil {
		return nil, nil, err
	}
	total := int(binary.BigEndian.Uint16(lenB))
	if total > max {
		return nil, nil, fmt.Errorf("packet too large")
	}
	crlf := make([]byte, 2)
	if _, err := io.ReadFull(r, crlf); err != nil {
		return nil, nil, err
	}
	payload := make([]byte, total)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, nil, err
	}
	return addr, payload, nil
}

// UDP 帧：写 [addr][len 2][CRLF][payload]
func writePacket(w io.Writer, addr, payload []byte) error {
	buf := make([]byte, 0, len(addr)+4+len(payload))
	buf = append(buf, addr...)
	buf = append(buf, byte(len(payload)>>8), byte(len(payload)), '\r', '\n')
	buf = append(buf, payload...)
	_, err := w.Write(buf)
	return err
}

// 服务端：TCP 回显 / UDP 回显
func runServer(listen, pass string) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	fmt.Printf("server listening on %s\n", listen)
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			cmd, _, _, err := readHeader(c, credential(pass))
			if err != nil {
				fmt.Printf("handshake fail: %v\n", err)
				return
			}
			if cmd == cmdUDP {
				for {
					addr, payload, err := readPacket(c, 64*1024)
					if err != nil {
						return
					}
					if err := writePacket(c, addr, payload); err != nil {
						return
					}
				}
			}
			// TCP 隧道回显
			_, _ = io.Copy(c, c)
		}(c)
	}
}

// 单向流水模式：server 持续读 total 字节统计（真实代理语义）
func runFlowServer(listen, pass string, total int) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	c, err := ln.Accept()
	if err != nil {
		return err
	}
	defer c.Close()
	cmd, _, _, err := readHeader(c, credential(pass))
	if err != nil {
		return err
	}
	if cmd != cmdTCP {
		return fmt.Errorf("flow only supports tcp")
	}
	buf := make([]byte, 256*1024)
	got := 0
	start := time.Now()
	for got < total {
		n, err := c.Read(buf)
		if err != nil || n == 0 {
			break
		}
		got += n
	}
	elapsed := time.Since(start)
	mbps := float64(got) / (1024 * 1024) / elapsed.Seconds()
	fmt.Printf("GO-FLOW server got=%d elapsed=%v throughput=%.1f MB/s\n", got, elapsed, mbps)
	return nil
}

// 单向流水模式：client 持续写 total 字节（不等回显）
func runFlowClient(server, pass, target string, total int) error {
	c, err := net.Dial("tcp", server)
	if err != nil {
		return err
	}
	defer c.Close()
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}
	if err := writeHeader(c, credential(pass), cmdTCP, host, port); err != nil {
		return err
	}
	payload := make([]byte, 256*1024)
	for i := range payload {
		payload[i] = byte(i * 31)
	}
	sent := 0
	start := time.Now()
	for sent < total {
		n, err := c.Write(payload)
		if err != nil {
			return err
		}
		sent += n
	}
	elapsed := time.Since(start)
	mbps := float64(sent) / (1024 * 1024) / elapsed.Seconds()
	fmt.Printf("GO-FLOW client sent=%d elapsed=%v throughput=%.1f MB/s\n", sent, elapsed, mbps)
	return nil
}

// 客户端：拨号 + 握手 + 与 stdin/stdout 转发
func runClient(server, pass, target string, udp bool) error {
	c, err := net.Dial("tcp", server)
	if err != nil {
		return err
	}
	defer c.Close()
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}
	cmd := cmdTCP
	if udp {
		cmd = cmdUDP
	}
	if err := writeHeader(c, credential(pass), cmd, host, port); err != nil {
		return err
	}
	if udp {
		// UDP：stdin 每行一个 payload（hex），回显到 stdout（hex）
		buf := make([]byte, 4096)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				addr := encodeAddr("127.0.0.1", 1)
				if err := writePacket(c, addr, buf[:n]); err != nil {
					return err
				}
				_, payload, err := readPacket(c, 64*1024)
				if err != nil {
					return err
				}
				os.Stdout.Write(payload)
			}
			if err != nil {
				return nil
			}
		}
	}
	_, _ = io.Copy(os.Stdout, c)
	return nil
}

// selftest：连接后自动收发校验（互操作测试用）
func selftest(server, pass, target string, udp bool, total, block int) error {
	c, err := net.Dial("tcp", server)
	if err != nil {
		return err
	}
	defer c.Close()
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}
	cmd := cmdTCP
	if udp {
		cmd = cmdUDP
	}
	if err := writeHeader(c, credential(pass), cmd, host, port); err != nil {
		return err
	}
	payload := make([]byte, block)
	for i := range payload {
		payload[i] = byte(i * 31)
	}
	sum := sha256.Sum256(payload)
	start := time.Now()
	if udp {
		addr := encodeAddr(host, port)
		ok := true
		for sent := 0; sent < total; sent += block {
			if err := writePacket(c, addr, payload); err != nil {
				return err
			}
			_, echo, err := readPacket(c, 64*1024)
			if err != nil {
				return err
			}
			if len(echo) != len(payload) || sha256.Sum256(echo) != sum {
				ok = false
			}
		}
		elapsed := time.Since(start)
		mbps := float64(total) / (1024 * 1024) / elapsed.Seconds()
		fmt.Printf("udp total=%d ok=%v elapsed=%v throughput=%.1f MB/s hash=%x\n", total, ok, elapsed, mbps, sum)
		return nil
	}
	sent := 0
	for sent < total {
		n := len(payload)
		if sent+n > total {
			n = total - sent
		}
		if _, err := c.Write(payload[:n]); err != nil {
			return err
		}
		echo := make([]byte, n)
		if _, err := io.ReadFull(c, echo); err != nil {
			return err
		}
		if sha256.Sum256(echo) != sha256.Sum256(payload[:n]) {
			fmt.Printf("hash mismatch at %d\n", sent)
			return nil
		}
		sent += n
	}
	elapsed := time.Since(start)
	mbps := float64(total) / (1024 * 1024) / elapsed.Seconds()
	fmt.Printf("tcp total=%d ok=true elapsed=%v throughput=%.1f MB/s hash=%x\n", total, elapsed, mbps, sum)
	return nil
}

func main() {
	mode := flag.String("mode", "server", "server | client | selftest | flow-server | flow-client")
	listen := flag.String("listen", "127.0.0.1:18443", "server listen addr")
	server := flag.String("server", "127.0.0.1:18443", "client server addr")
	pass := flag.String("pass", "prism", "password")
	target := flag.String("target", "127.0.0.1:443", "client target")
	udp := flag.Bool("udp", false, "use udp command")
	total := flag.Int("total", 64*1024*1024, "selftest total bytes")
	block := flag.Int("block", 64*1024, "selftest block size")
	flag.Parse()

	var err error
	switch *mode {
	case "server":
		err = runServer(*listen, *pass)
	case "selftest":
		err = selftest(*server, *pass, *target, *udp, *total, *block)
	case "flow-server":
		err = runFlowServer(*listen, *pass, *total)
	case "flow-client":
		err = runFlowClient(*server, *pass, *target, *total)
	default:
		err = runClient(*server, *pass, *target, *udp)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
