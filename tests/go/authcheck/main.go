// Package main 复刻 C++ open_auth_header（AES-ECB 解密 + CRC + ts），
// 用 mihomo transport/vmess 生成的真实认证头验证 C++ 解密逻辑是否正确。
package main

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"hash/crc32"
	"net"
	"time"

	"github.com/metacubex/mihomo/transport/vmess"
	singvmess "github.com/metacubex/sing-vmess"
)

// kdf 直接翻译 mihomo/sing-vmess 的 hmacCreator 结构
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

// 复刻 C++ open_auth_header
func openAuthHeader(cmdKey []byte, authID []byte) (valid bool, ts int64, ok bool) {
	key := kdf(cmdKey, "AES Auth ID Encryption")
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return false, 0, false
	}
	plain := make([]byte, 16)
	block.Decrypt(plain, authID)
	ts = int64(binary.BigEndian.Uint64(plain[:8]))
	expected := crc32.ChecksumIEEE(plain[:12])
	actual := binary.BigEndian.Uint32(plain[12:16])
	return actual == expected, ts, true
}

type noopConn struct{}

func (c *noopConn) Read(b []byte) (int, error)  { return 0, fmt.Errorf("noop") }
func (c *noopConn) Write(b []byte) (int, error) { fakeWrite.bytes = append(fakeWrite.bytes, b...); return len(b), nil }
func (c *noopConn) Close() error                { return nil }
func (c *noopConn) LocalAddr() net.Addr         { return nil }
func (c *noopConn) RemoteAddr() net.Addr        { return nil }
func (c *noopConn) SetDeadline(t time.Time) error      { return nil }
func (c *noopConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *noopConn) SetWriteDeadline(t time.Time) error { return nil }

var fakeWrite struct{ bytes []byte }

func main() {
	client, err := vmess.NewClient(vmess.Config{
		UUID:     "123e4567-e89b-12d3-a456-426614174000",
		AlterID:  0,
		Security: "auto",
		IsAead:   true,
	})
	if err != nil {
		panic(err)
	}
	// StreamConn 时 newConn 内部 writeRequest 立即写出认证头
	_, err = client.StreamConn(&noopConn{}, &vmess.DstAddr{
		UDP:      false,
		AddrType: vmess.AtypIPv4,
		Addr:     []byte{127, 0, 0, 1},
		Port:     8080,
	})
	if err != nil {
		panic(err)
	}

	wire := fakeWrite.bytes
	fmt.Printf("wire len=%d hex=%x\n", len(wire), wire)
	if len(wire) < 16 {
		fmt.Printf("FAIL: wire too short: %d\n", len(wire))
		return
	}
	authID := wire[:16]

	// C++ 侧 cmdKey = MD5(uuid || "c48619fe-8f02-49e0-b9e9-edf763e17e21")
	md5h := md5.New()
	md5h.Write([]byte{
		0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3,
		0xa4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00})
	md5h.Write([]byte("c48619fe-8f02-49e0-b9e9-edf763e17e21"))
	cmdKey := md5h.Sum(nil)

	// 用 sing-vmess 的官方 KDF 计算 authID 加密密钥，验证复刻是否正确
	authKeyOfficial := vmessKDF(cmdKey, "AES Auth ID Encryption")
	authKeyReplica := kdf(cmdKey, "AES Auth ID Encryption")
	fmt.Printf("official key=%x\nreplica   key=%x\n", authKeyOfficial[:16], authKeyReplica[:16])
	match := hmac.Equal(authKeyOfficial[:16], authKeyReplica[:16])
	fmt.Printf("kdf replica == sing-vmess official: %v\n", match)

	valid, ts, ok := openAuthHeader(cmdKey, authID)
	if !ok {
		fmt.Println("FAIL: open failed")
		return
	}
	diff := time.Now().Unix() - ts
	fmt.Printf("auth ts=%d now=%d diff=%ds valid=%v\n", ts, time.Now().Unix(), diff, valid)
	if !valid {
		fmt.Println("FAIL: CRC mismatch (C++ open_auth_header logic vs mihomo seal)")
		return
	}
	fmt.Println("PASS: open_auth_header logic OK (KDF+ECB+CRC all match mihomo)")
}

// sing-vmess 官方 KDF 导出函数
func vmessKDF(key []byte, salt string, path ...[]byte) []byte {
	return singvmess.KDF(key, salt, path...)
}
