// Package main 是 Reality 认证流程的 Go 参考实现（对齐 mihomo component/tls/reality.go 与
// C++ src/prism/handshake/reality/util/auth.cpp）：
//   X25519 ECDH → HKDF-Extract(salt=client_random[:20], ikm=shared_secret)
//   → HKDF-Expand(PRK, info="REALITY", 32) → AES-256-GCM seal session_id
// 用固定测试向量输出参考字节，供 C++ RealityAuth 测试比对。
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/hkdf"
)// 固定客户端 X25519 私钥（与 C++ 测试约定一致）
func clientPriv() []byte {
	priv, _ := hex.DecodeString("2222222222222222222222222222222222222222222222222222222222222222")
	return priv
}

// 固定服务端 X25519 私钥
func serverPriv() []byte {
	priv, _ := hex.DecodeString("1111111111111111111111111111111111111111111111111111111111111111")
	return priv
}

// 固定 ClientHello.random（40 字节：前 20 = HKDF salt，后 12 = AEAD nonce）
func clientRandom() []byte {
	random, _ := hex.DecodeString("303132333435363738396162636465666768696a6b6c6d6e6f70717273747576")
	return random
}

// 固定 ClientHello 原始消息（AAD，session_id 区域偏移 39 清零）
func rawHello() []byte {
	msg := make([]byte, 128)
	for i := range msg {
		msg[i] = byte(i)
	}
	return msg
}

// 明文 session_id：version(1) + random(7) + short_id(8) + padding(16) = 32 字节
// （与 C++ AuthenticateFullSuccess 一致：authenticate 解密出 16 字节）
func plaintextSid() []byte {
	plain := make([]byte, 16)
	plain[0] = 0x01 // version marker
	for i := 8; i < 16; i++ {
		plain[i] = 0x42 // short_id
	}
	return plain
}

func main() {
	privBytes := serverPriv()
	clientPrivBytes := clientPriv()

	// X25519 密钥对（服务端）
	serverKey, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		fmt.Printf("FAIL: server key: %v\n", err)
		return
	}
	// X25519 密钥对（客户端）
	clientKey, err := ecdh.X25519().NewPrivateKey(clientPrivBytes)
	if err != nil {
		fmt.Printf("FAIL: client key: %v\n", err)
		return
	}

	// 客户端视角共享密钥 = 客户端私钥 × 服务端公钥
	shared, err := clientKey.ECDH(serverKey.PublicKey())
	if err != nil {
		fmt.Printf("FAIL: ECDH: %v\n", err)
		return
	}

	random := clientRandom()
	hello := rawHello()

	// HKDF-Extract(salt=random[:20], ikm=shared) + HKDF-Expand(info="REALITY", 32)
	authKey := make([]byte, 32)
	hk := hkdf.New(sha256.New, shared, random[:20], []byte("REALITY"))
	if _, err := hk.Read(authKey); err != nil {
		fmt.Printf("FAIL: hkdf: %v\n", err)
		return
	}

	// AES-256-GCM seal session_id（AAD = hello 原始消息，session_id 区域已清零）
	aad := make([]byte, len(hello))
	copy(aad, hello)
	// reality.go: session ID 位于 raw[39:71]（sid_len=32 时）
	for i := 39; i < 39+32 && i < len(aad); i++ {
		aad[i] = 0
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		fmt.Printf("FAIL: aes: %v\n", err)
		return
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("FAIL: gcm: %v\n", err)
		return
	}
	encryptedSid := aead.Seal(nil, random[20:32], plaintextSid(), aad)

	// 自校验：解密回明文
	dec, err := aead.Open(nil, random[20:32], encryptedSid, aad)
	if err != nil || string(dec) != string(plaintextSid()) {
		fmt.Printf("FAIL: seal/open roundtrip mismatch\n")
		return
	}

	fmt.Printf("server_pub      = %s\n", hex.EncodeToString(serverKey.PublicKey().Bytes()))
	fmt.Printf("client_pub      = %s\n", hex.EncodeToString(clientKey.PublicKey().Bytes()))
	fmt.Printf("shared_secret   = %s\n", hex.EncodeToString(shared))
	fmt.Printf("auth_key        = %s\n", hex.EncodeToString(authKey))
	fmt.Printf("encrypted_sid   = %s\n", hex.EncodeToString(encryptedSid))
	fmt.Printf("PASS: reality auth reference ok\n")
}
