// Package main 是 TrustTunnel 认证的 Go 参考实现（对齐 mihomo transport/trusttunnel 与
// C++ src/prism/handshake/trusttunnel/scheme.cpp）：
//   - basicAuth：Basic base64(user:pass)
//   - parseBasicAuth：解析校验 "Basic <base64>"
// 用固定测试向量输出参考字节，供 C++ TrustTunnel 测试比对。
package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// basicAuth：构造 Authorization 头值 "Basic base64(user:pass)"
func basicAuth(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}

// parseBasicAuth：解析校验，返回 (username, password, ok)
func parseBasicAuth(authorization string) (string, string, bool) {
	if !strings.HasPrefix(authorization, "Basic ") {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(authorization[len("Basic "):])
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func main() {
	username := "user1"
	password := "password1"

	auth := basicAuth(username, password)
	u, p, ok := parseBasicAuth(auth)

	fmt.Printf("auth_header     = %s\n", auth)
	fmt.Printf("base64          = %s\n", hex.EncodeToString([]byte(auth)))
	fmt.Printf("parsed_user     = %s\n", u)
	fmt.Printf("parsed_pass     = %s\n", p)
	fmt.Printf("parse_ok        = %v\n", ok)
	if ok && u == username && p == password {
		fmt.Printf("PASS: trusttunnel basic auth reference ok\n")
	} else {
		fmt.Printf("FAIL: basic auth mismatch\n")
	}
}
