// Package main provides a real SS2022 server (sing-shadowsocks, same stack as mihomo)
// for C++ common client interop verification.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"github.com/metacubex/sing-shadowsocks/shadowaead_2022"
)

const psk = "5n5ESu953i/pjIp02oZvHA=="

type echoHandler struct{}

func (echoHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	_, _ = io.Copy(conn, conn)
	_ = conn.Close()
	return nil
}

func (echoHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	return nil
}

func (echoHandler) NewError(ctx context.Context, err error) {}

func main() {
	service, err := shadowaead_2022.NewServiceWithPassword(
		"2022-blake3-aes-128-gcm", psk, 60, echoHandler{}, time.Now)
	if err != nil {
		panic(err)
	}

	addr := "127.0.0.1:19080"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		panic(err)
	}
	fmt.Printf("server listening on %s\n", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			break
		}
		go func(c net.Conn) {
			if err := service.NewConnection(context.Background(), c, M.Metadata{}); err != nil {
				fmt.Printf("server conn error: %v\n", err)
			}
		}(conn)
	}
}
