// Package main 是 ShadowTLS v3 认证算法的 Go 参考实现（对齐 sing-shadowtls 与
// C++ src/prism/handshake/shadowtls/util/auth.cpp）：
//   - generateSessionID：HMAC-SHA1(password, clientHello[:sidStart] + sessionID + clientHello[sidEnd:])[:4]
//   - verifyClientHello：sessionID 最后 4 字节 HMAC 校验
//   - hmacVerify/hmacAdd：HMAC-SHA1(password, serverRandom + "C"/"S" + payload)[:4]
// 用固定测试向量输出参考字节，供 C++ Shadowtls 测试比对。
package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
)

const (
	tlsHdrsize       = 5
	hsTypeClientHello = 1
	tlsRndSize       = 32
	tlsSessionIDSize = 32
	hmacSize         = 4
)

// sessionIDStart = 1(handshake type) + 3(len) + 2(version) + 32(random) + 1(sid len)
const sessionIDStart = 1 + 3 + 2 + tlsRndSize + 1

// generateSessionID：sing-shadowtls v3_client.go generateSessionID 同款
func generateSessionID(password string, clientHello []byte, sessionID []byte) {
	for i := 0; i < tlsSessionIDSize-hmacSize; i++ {
		sessionID[i] = byte(i*7 + 3) // 固定伪随机（测试用确定性向量）
	}
	h := hmac.New(sha1.New, []byte(password))
	h.Write(clientHello[:sessionIDStart])
	h.Write(sessionID)
	h.Write(clientHello[sessionIDStart+tlsSessionIDSize:])
	sum := h.Sum(nil)
	copy(sessionID[tlsSessionIDSize-hmacSize:], sum[:hmacSize])
}

// verifyClientHello：与 C++ auth.cpp verify_client_hello 同款
// （data = clientHello[5:]，sessionID 内 HMAC 4 字节置零后计算 HMAC-SHA1）
func verifyClientHello(password string, clientHello []byte) bool {
	if len(clientHello) < tlsHdrsize+1+3+2+tlsRndSize+1+tlsSessionIDSize {
		return false
	}
	if clientHello[0] != 0x16 || clientHello[5] != hsTypeClientHello {
		return false
	}
	sidLenIdx := tlsHdrsize + 1 + 3 + 2 + tlsRndSize
	if clientHello[sidLenIdx] != tlsSessionIDSize {
		return false
	}
	dataSize := len(clientHello) - tlsHdrsize
	hmacData := make([]byte, dataSize)
	copy(hmacData, clientHello[tlsHdrsize:])
	// sessionID 在握手数据（去 TLS 头）中起始 = sessionIDStart，HMAC 在最后 4 字节
	hmacOffsetInData := sessionIDStart + tlsSessionIDSize - hmacSize
	for i := 0; i < hmacSize; i++ {
		hmacData[hmacOffsetInData+i] = 0
	}
	h := hmac.New(sha1.New, []byte(password))
	h.Write(hmacData)
	expected := h.Sum(nil)[:hmacSize]
	clientHMACOffset := sidLenIdx + 1 + tlsSessionIDSize - hmacSize
	clientTag := clientHello[clientHMACOffset : clientHMACOffset+hmacSize]
	return hmac.Equal(expected, clientTag)
}

// hmacVerify / hmacAdd：HMAC-SHA1(password, serverRandom + tag + payload)[:4]
func frameHMAC(password string, serverRandom []byte, tag byte, payload []byte) []byte {
	h := hmac.New(sha1.New, []byte(password))
	h.Write(serverRandom)
	h.Write([]byte{tag})
	h.Write(payload)
	return h.Sum(nil)[:hmacSize]
}

func main() {
	password := "shadowtls_password"

	// 构造固定 ClientHello：TLS 记录头(5) + 握手头(4) + version(2) + random(32) + sidLen(1) + sid(32)
	clientHello := make([]byte, tlsHdrsize+sessionIDStart+tlsSessionIDSize+16)
	clientHello[0] = 0x16 // content_handshake
	clientHello[5] = hsTypeClientHello
	clientHello[tlsHdrsize+sessionIDStart-1] = tlsSessionIDSize
	for i := 0; i < tlsRndSize; i++ {
		clientHello[tlsHdrsize+1+3+2+i] = byte(i) // random
	}
	// generateSessionID 输入为不含 TLS 头的握手数据（sing 同款）
	handshake := clientHello[tlsHdrsize:]
	sessionID := make([]byte, tlsSessionIDSize)
	generateSessionID(password, handshake, sessionID)
	copy(handshake[sessionIDStart:sessionIDStart+tlsSessionIDSize], sessionID)

	// 校验（verifyClientHello 输入为含 TLS 头的完整消息）
	ok := verifyClientHello(password, clientHello)

	// frame HMAC（post-handshake 认证）
	serverRandom := []byte("0123456789abcdef0123456789abcdef")
	payload := []byte("hello shadowtls data")
	hmacC := frameHMAC(password, serverRandom, 'C', payload)
	hmacS := frameHMAC(password, serverRandom, 'S', payload)

	fmt.Printf("session_id      = %s\n", hex.EncodeToString(sessionID))
	fmt.Printf("verify_hello    = %v\n", ok)
	fmt.Printf("hmac_client     = %s\n", hex.EncodeToString(hmacC))
	fmt.Printf("hmac_server     = %s\n", hex.EncodeToString(hmacS))
	if ok {
		fmt.Printf("PASS: shadowtls v3 auth reference ok\n")
	} else {
		fmt.Printf("FAIL: session id hmac mismatch\n")
	}
}
