// Package main 提供独立 sing-vmess reference server，供 Preview 外部矩阵使用。
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	vmess "github.com/metacubex/sing-vmess"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

const defaultUUID = "123e4567-e89b-12d3-a456-426614174000"

type echoHandler struct{}

func (echoHandler) NewConnection(_ context.Context, conn net.Conn, _ M.Metadata) error {
	defer conn.Close()
	if _, err := conn.Write(nil); err != nil {
		return err
	}
	_, err := io.Copy(conn, conn)
	return err
}

func (echoHandler) NewPacketConnection(_ context.Context, conn N.PacketConn, _ M.Metadata) error {
	defer conn.Close()
	reader, ok := conn.(N.NetPacketReader)
	if !ok {
		return fmt.Errorf("reference packet connection has no NetPacketReader")
	}
	writer, ok := conn.(N.NetPacketWriter)
	if !ok {
		return fmt.Errorf("reference packet connection has no NetPacketWriter")
	}
	if _, err := writer.WriteTo(nil, nil); err != nil {
		return err
	}
	buffer := make([]byte, 65535)
	for {
		n, addr, err := reader.ReadFrom(buffer)
		if err != nil {
			return err
		}
		if _, err = writer.WriteTo(buffer[:n], addr); err != nil {
			return err
		}
	}
}

func (echoHandler) NewError(_ context.Context, _ error) {}

func main() {
	listen := flag.String("listen", "127.0.0.1:19083", "server listen address")
	uuid := flag.String("uuid", defaultUUID, "VMess UUID")
	flag.Parse()

	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: listen: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()

	service := vmess.NewService[string](echoHandler{})
	if err := service.UpdateUsers([]string{"default"}, []string{*uuid}, []int{0}); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: update users: %v\n", err)
		os.Exit(1)
	}
	if err := service.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: start service: %v\n", err)
		os.Exit(1)
	}
	defer service.Close()

	fmt.Printf("READY: Go VMess reference server on %s\n", *listen)
	for {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		go func() {
			if err := service.NewConnection(context.Background(), conn, M.Metadata{}); err != nil {
				_ = conn.Close()
			}
		}()
	}
}
