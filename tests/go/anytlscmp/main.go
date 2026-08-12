// Package main 是 AnyTLS 认证帧的 Go 参考实现（对齐 mihomo transport/anytls 与
// C++ src/prism/handshake/anytls/scheme.cpp）：
//   认证帧 = [SHA-256(password) 32B][PadLen 2B BE][Padding]
// 用固定测试向量输出参考字节，供 C++ Anytls 测试比对。
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// buildAuthFrame：构造认证帧
// [password_hash 32B][pad_len 2B BE][padding]
func buildAuthFrame(password string, padLen uint16) []byte {
	hash := sha256.Sum256([]byte(password))
	frame := make([]byte, 0, 32+2+int(padLen))
	frame = append(frame, hash[:]...)
	var padBuf [2]byte
	binary.BigEndian.PutUint16(padBuf[:], padLen)
	frame = append(frame, padBuf[:]...)
	for i := uint16(0); i < padLen; i++ {
		frame = append(frame, byte(i*13+7))
	}
	return frame
}

// parseAuthFrame：解析认证帧，返回 (hash, padLen, ok)
func parseAuthFrame(frame []byte) ([32]byte, uint16, bool) {
	var hash [32]byte
	if len(frame) < 34 {
		return hash, 0, false
	}
	copy(hash[:], frame[:32])
	padLen := binary.BigEndian.Uint16(frame[32:34])
	if len(frame) < 34+int(padLen) {
		return hash, 0, false
	}
	return hash, padLen, true
}

func main() {
	password := "anytls_password"
	padLen := uint16(16)

	frame := buildAuthFrame(password, padLen)
	hash, parsedPad, ok := parseAuthFrame(frame)

	hashHex := hex.EncodeToString(hash[:])
	fmt.Printf("password_hash   = %s\n", hashHex)
	fmt.Printf("frame_len       = %d\n", len(frame))
	fmt.Printf("pad_len         = %d\n", parsedPad)
	fmt.Printf("parse_ok        = %v\n", ok)
	if ok && parsedPad == padLen && len(frame) == 32+2+int(padLen) {
		fmt.Printf("PASS: anytls auth frame reference ok\n")
	} else {
		fmt.Printf("FAIL: auth frame mismatch\n")
	}
}
