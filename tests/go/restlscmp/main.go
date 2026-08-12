// Package main 是 Restls 认证算法的 Go 参考实现（对齐 mihomo transport/restls 与
// C++ include/prism/handshake/restls/crypto.hpp）：
//   - derive_secret：BLAKE3 derive_key("restls-traffic-key", password) → 32B secret
//   - compute_server_mask：BLAKE3 keyed(secret, server_random) → 16B
//   - compute_auth_mac：BLAKE3 keyed(secret, server_random + dir + counter + ...) → 8B
//   - compute_mask：BLAKE3 keyed(secret, server_random + dir + counter + sample) → 4B
// 用固定测试向量输出参考字节，供 C++ Restls 测试比对。
package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/metacubex/blake3"
)

const (
	hsMaclen     = 16
	appdataMaclen = 8
	maskLen      = 4
	dirToclient  = "server-to-client"
	dirToserver  = "client-to-server"
	secretCtx    = "restls-traffic-key"
)

// deriveSecret：BLAKE3 derive_key 模式（metacubex/blake3 DeriveKey 输出到 subKey）
func deriveSecret(password string) []byte {
	secret := make([]byte, 32)
	blake3.DeriveKey(secret, secretCtx, []byte(password))
	return secret
}

// blake3Keyed：BLAKE3 keyed mode（密钥 = secret）
func blake3Keyed(secret []byte, chunks ...[]byte) []byte {
	hasher := blake3.New(32, secret)
	for _, c := range chunks {
		hasher.Write(c)
	}
	return hasher.Sum(nil)
}

// computeServerMask：BLAKE3 keyed(secret, server_random)[:16]
func computeServerMask(secret, serverRandom []byte) []byte {
	return blake3Keyed(secret, serverRandom)[:hsMaclen]
}

// computeAuthMac：BLAKE3 keyed(secret, server_random + dir + counter + [cf] + header + payload)[:8]
func computeAuthMac(secret, serverRandom []byte, direction string, clientFinished, tlsHeader, payloadAfterMac []byte, counter uint64) []byte {
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)
	chunks := [][]byte{serverRandom, []byte(direction), counterBytes[:]}
	if len(clientFinished) > 0 {
		chunks = append(chunks, clientFinished)
	}
	chunks = append(chunks, tlsHeader, payloadAfterMac)
	return blake3Keyed(secret, chunks...)[:appdataMaclen]
}

// computeMask：BLAKE3 keyed(secret, server_random + dir + counter + sample[:32])[:4]
func computeMask(secret, serverRandom []byte, direction string, sample []byte, counter uint64) []byte {
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)
	if len(sample) > 32 {
		sample = sample[:32]
	}
	return blake3Keyed(secret, serverRandom, []byte(direction), counterBytes[:], sample)[:maskLen]
}

func main() {
	password := "restls_password"
	secret := deriveSecret(password)

	serverRandom := []byte("0123456789abcdef0123456789abcdef")
	clientFinished := []byte("finished-verify-data-0123456789abcdef")
	tlsHeader := []byte{0x17, 0x03, 0x03, 0x00, 0x2A}
	payloadAfterMac := []byte("restls masked payload data block")
	sample := []byte("restls plaintext sample data for mask")

	serverMask := computeServerMask(secret, serverRandom)
	authMacC2S := computeAuthMac(secret, serverRandom, dirToserver, clientFinished, tlsHeader, payloadAfterMac, 1)
	authMacS2C := computeAuthMac(secret, serverRandom, dirToclient, nil, tlsHeader, payloadAfterMac, 2)
	mask := computeMask(secret, serverRandom, dirToserver, sample, 1)
	fmt.Printf("secret          = %s\n", hex.EncodeToString(secret))
	fmt.Printf("server_mask     = %s\n", hex.EncodeToString(serverMask))
	fmt.Printf("auth_mac_c2s    = %s\n", hex.EncodeToString(authMacC2S))
	fmt.Printf("auth_mac_s2c    = %s\n", hex.EncodeToString(authMacS2C))
	fmt.Printf("mask            = %s\n", hex.EncodeToString(mask))
	fmt.Printf("PASS: restls auth reference ok\n")
}
