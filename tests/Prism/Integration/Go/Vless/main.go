// Package main 提供独立 VLESS TCP client/server 与 XUDP reference server。
package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	vmess "github.com/metacubex/sing-vmess"
	"github.com/metacubex/sing-vmess/vless"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

const defaultUUID = "123e4567-e89b-12d3-a456-426614174000"

func parseUUID(value string) ([16]byte, error) {
	var result [16]byte
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return result, fmt.Errorf("invalid UUID")
	}
	compact := make([]byte, 0, 32)
	for index := range value {
		if value[index] != '-' {
			compact = append(compact, value[index])
		}
	}
	if _, err := hex.Decode(result[:], compact); err != nil {
		return result, err
	}
	return result, nil
}

type xudpEchoHandler struct{}

var _ vless.Handler = xudpEchoHandler{}

func (xudpEchoHandler) NewConnection(_ context.Context, connection net.Conn, _ M.Metadata) error {
	defer connection.Close()
	return fmt.Errorf("TCP is unsupported by the VLESS XUDP reference server")
}

func (xudpEchoHandler) NewPacketConnection(_ context.Context, connection N.PacketConn, _ M.Metadata) error {
	defer connection.Close()
	packetConn, ok := connection.(N.NetPacketConn)
	if !ok {
		return fmt.Errorf("unsupported VLESS packet connection type %T", connection)
	}
	packet := make([]byte, 65535)
	for {
		size, destination, err := packetConn.ReadFrom(packet)
		if err != nil {
			return err
		}
		written, err := packetConn.WriteTo(packet[:size], destination)
		if err != nil {
			return err
		}
		if written != size {
			return io.ErrShortWrite
		}
	}
}

func (xudpEchoHandler) NewError(_ context.Context, err error) {
	logXudpError("packet handler", err)
}

func logXudpError(stage string, err error) {
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) &&
		!errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "VLESS XUDP reference %s: %v\n", stage, err)
	}
}

func runXudpConnection(connection net.Conn, expected [16]byte) error {
	defer connection.Close()
	request, err := vless.ReadRequest(connection)
	if err != nil {
		return err
	}
	if request.UUID != expected {
		return fmt.Errorf("invalid UUID")
	}
	if request.Command != vmess.CommandMux {
		return fmt.Errorf("unsupported VLESS command %d", request.Command)
	}
	if request.Flow != "" {
		return fmt.Errorf("unsupported VLESS flow %q", request.Flow)
	}
	response := []byte{vless.Version, 0}
	for len(response) > 0 {
		written, writeErr := connection.Write(response)
		if writeErr != nil {
			return writeErr
		}
		if written <= 0 || written > len(response) {
			return io.ErrShortWrite
		}
		response = response[written:]
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	return vmess.HandleMuxConnection(ctx, connection,
		M.Metadata{Destination: request.Destination}, xudpEchoHandler{})
}

func runServer(listen, uuid string) error {
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	expected, err := parseUUID(uuid)
	if err != nil {
		return err
	}
	fmt.Printf("READY: Go VLESS server on %s\n", listen)
	for {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return acceptErr
		}
		request, requestErr := vless.ReadRequest(connection)
		if requestErr != nil || request.UUID != expected {
			_ = connection.Close()
			continue
		}
		if request.Command == 2 {
			if _, writeErr := connection.Write([]byte{0, 0}); writeErr != nil {
				_ = connection.Close()
				return writeErr
			}
			for {
				var length uint16
				if readErr := binary.Read(connection, binary.BigEndian, &length); readErr != nil {
					_ = connection.Close()
					return readErr
				}
				packet := make([]byte, int(length))
				if _, readErr := io.ReadFull(connection, packet); readErr != nil {
					_ = connection.Close()
					return readErr
				}
				if writeErr := binary.Write(connection, binary.BigEndian, length); writeErr != nil {
					_ = connection.Close()
					return writeErr
				}
				if _, writeErr := connection.Write(packet); writeErr != nil {
					_ = connection.Close()
					return writeErr
				}
			}
		}
		if request.Command != 1 {
			_ = connection.Close()
			continue
		}
		if _, writeErr := connection.Write([]byte{0, 0}); writeErr != nil {
			_ = connection.Close()
			return writeErr
		}
		_, copyErr := io.Copy(connection, connection)
		_ = connection.Close()
		return copyErr
	}
}

func runXudpServer(listen, uuid string) error {
	expected, err := parseUUID(uuid)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer listener.Close()

	fmt.Printf("READY: Go VLESS XUDP server on %s\n", listener.Addr())
	for {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return acceptErr
		}
		go func(connection net.Conn) {
			if connectionErr := runXudpConnection(connection, expected); connectionErr != nil {
				logXudpError("connection", connectionErr)
			}
		}(connection)
	}
}

func runClient(server, uuid, target string, udp bool) error {
	raw, err := net.DialTimeout("tcp", server, 5*time.Second)
	if err != nil {
		return err
	}
	defer raw.Close()
	client, err := vless.NewClient(uuid, "", nil)
	if err != nil {
		return err
	}
	if udp {
		packetConn, packetErr := client.DialPacketConn(raw, M.ParseSocksaddr(target))
		if packetErr != nil {
			return packetErr
		}
		defer packetConn.Close()
		const payload = "prism-vless-external-udp-payload"
		if _, packetErr = packetConn.Write([]byte(payload)); packetErr != nil {
			return packetErr
		}
		echo := make([]byte, len(payload))
		_ = packetConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, packetErr = io.ReadFull(packetConn, echo); packetErr != nil {
			return packetErr
		}
		if string(echo) != payload {
			return fmt.Errorf("UDP echo mismatch: got %q", string(echo))
		}
		fmt.Printf("PASS: Go VLESS UDP echo (%d bytes)\n", len(echo))
		return nil
	}
	connection, err := client.DialConn(raw, M.ParseSocksaddr(target))
	if err != nil {
		return err
	}
	defer connection.Close()
	const payload = "prism-vless-external-interop-payload"
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
	fmt.Printf("PASS: Go VLESS client echo (%d bytes)\n", len(echo))
	return nil
}

func main() {
	mode := flag.String("mode", "client", "client | server | xudp-server")
	listen := flag.String("listen", "127.0.0.1:19084", "server listen address")
	server := flag.String("server", "127.0.0.1:19084", "client server address")
	uuid := flag.String("uuid", defaultUUID, "VLESS UUID")
	target := flag.String("target", "example.com:443", "VLESS target")
	udp := flag.Bool("udp", false, "use VLESS UDP packet framing")
	flag.Parse()

	var err error
	switch *mode {
	case "server":
		err = runServer(*listen, *uuid)
	case "xudp-server":
		err = runXudpServer(*listen, *uuid)
	case "client":
		err = runClient(*server, *uuid, *target, *udp)
	default:
		err = fmt.Errorf("unknown mode %q", *mode)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
