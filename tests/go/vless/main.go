// Package main 提供独立 VLESS TCP reference client/server，供 Preview 外部矩阵使用。
package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/metacubex/sing-vmess/vless"
	M "github.com/metacubex/sing/common/metadata"
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
	mode := flag.String("mode", "client", "client | server")
	listen := flag.String("listen", "127.0.0.1:19084", "server listen address")
	server := flag.String("server", "127.0.0.1:19084", "client server address")
	uuid := flag.String("uuid", defaultUUID, "VLESS UUID")
	target := flag.String("target", "example.com:443", "VLESS target")
	udp := flag.Bool("udp", false, "use VLESS UDP packet framing")
	flag.Parse()

	var err error
	if *mode == "server" {
		err = runServer(*listen, *uuid)
	} else {
		err = runClient(*server, *uuid, *target, *udp)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
