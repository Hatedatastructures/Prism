// Package main 复刻 mihomo recvResponse（AEAD 双段 GCM）解密 C++ build_response 输出，
// 验证响应头是否与 mihomo 客户端期望一致。
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
)

// sing-vmess KDF（嵌套哈希）
func kdf(key []byte, paths ...string) []byte {
	type hmacCreator struct {
		parent *hmacCreator
		value  []byte
	}
	var create func(h *hmacCreator) func() hash.Hash
	create = func(h *hmacCreator) func() hash.Hash {
		if h.parent == nil {
			return func() hash.Hash { return hmac.New(sha256.New, h.value) }
		}
		return func() hash.Hash { return hmac.New(create(h.parent), h.value) }
	}
	cur := &hmacCreator{value: []byte("VMess AEAD KDF")}
	for _, p := range paths {
		cur = &hmacCreator{parent: cur, value: []byte(p)}
	}
	h := create(cur)()
	h.Write(key)
	return h.Sum(nil)
}

func main() {
	respKeyHex := "86dfd382d184e6a1a3b638ca05a88a89"
	respNonceHex := "d6944ddcdeccc7dc0d7a3eca82c56548"
	respHex := "2bcffd9ff4e55093bc14b057eb498c7a0c0e16f5de819ebd8ab087df2e3ef6e621b93e0c8e0b"

	// respBodyKey = SHA256(request_key)[:16]，respBodyIV = SHA256(request_nonce)[:16]
	reqKey, _ := hex.DecodeString(respKeyHex)
	reqNonce, _ := hex.DecodeString(respNonceHex)
	hk := sha256.Sum256(reqKey)
	hn := sha256.Sum256(reqNonce)
	respBodyKey := hk[:16]
	respBodyIV := hn[:16]
	resp, _ := hex.DecodeString(respHex)

	// mihomo recvResponse AEAD：
	lenKey := kdf(respBodyKey, "AEAD Resp Header Len Key")[:16]
	lenIV := kdf(respBodyIV, "AEAD Resp Header Len IV")[:12]
	block, _ := aes.NewCipher(lenKey)
	aead, _ := cipher.NewGCM(block)
	dec, err := aead.Open(nil, lenIV, resp[:18], nil)
	if err != nil {
		fmt.Println("FAIL: len block decrypt:", err)
		return
	}
	length := binary.BigEndian.Uint16(dec)
	fmt.Printf("decrypted length=%d\n", length)

	payloadKey := kdf(respBodyKey, "AEAD Resp Header Key")[:16]
	payloadIV := kdf(respBodyIV, "AEAD Resp Header IV")[:12]
	block2, _ := aes.NewCipher(payloadKey)
	aead2, _ := cipher.NewGCM(block2)
	payload, err := aead2.Open(nil, payloadIV, resp[18:18+length+16], nil)
	if err != nil {
		fmt.Println("FAIL: payload decrypt:", err)
		return
	}
	fmt.Printf("response header plaintext: %x\n", payload)
	fmt.Printf("expected [respV][option][0][0]: ok=%v\n", len(payload) == 4 && payload[2] == 0 && payload[3] == 0)
}
