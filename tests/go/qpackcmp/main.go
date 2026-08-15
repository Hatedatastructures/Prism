// Package main QPACK 编解码对照工具：用 metacubex/qpack（quic-go 同栈）
// 编码一组已知 header，输出 hex 字节，供 C++ 侧 qpack 解码验证互通。
// 用法: qpackcmp.exe <encode|decode> [hex...]
package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/metacubex/qpack"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: qpackcmp <encode|decode>")
		os.Exit(1)
	}
	switch os.Args[1] {
	case "encode":
		// 编码 hysteria2 认证头（对齐 h3_auth 场景）
		fields := []qpack.HeaderField{
			{Name: ":method", Value: "POST"},
			{Name: ":path", Value: "/auth"},
			{Name: ":authority", Value: "hysteria"},
			{Name: "hysteria-auth", Value: "password123"},
			{Name: "hysteria-cc-rx", Value: "0"},
		}
		enc := qpack.NewEncoder(&hexWriter{})
		for _, f := range fields {
			if err := enc.WriteField(f); err != nil {
				fmt.Fprintf(os.Stderr, "encode error: %v\n", err)
				os.Exit(1)
			}
		}
		fmt.Println()
	case "decode":
		if len(os.Args) < 3 {
			fmt.Println("usage: qpackcmp decode <hex>")
			os.Exit(1)
		}
		data, err := hex.DecodeString(os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "hex error: %v\n", err)
			os.Exit(1)
		}
		dec := qpack.NewDecoder()
		next := dec.Decode(data)
		for {
			f, err := next()
			if err == io.EOF {
				break
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "decode error: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("%s: %s\n", f.Name, f.Value)
		}
	default:
		fmt.Println("unknown mode")
		os.Exit(1)
	}
}

// hexWriter 将字节以 hex 输出
type hexWriter struct{}

func (w *hexWriter) Write(p []byte) (int, error) {
	fmt.Print(hex.EncodeToString(p))
	return len(p), nil
}
