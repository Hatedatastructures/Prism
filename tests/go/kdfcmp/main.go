// Package main 对比 hmacCreator 结构 vs 数学展开，找出嵌套 HMAC 的真实行为。
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"
)

func kdfCreator(key []byte, paths ...string) []byte {
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

func xorPad(k []byte, pad byte) []byte {
	out := make([]byte, 64)
	for i := range out {
		out[i] = k[i%len(k)] ^ pad
	}
	return out
}

// 数学展开：Hn(msg) = Hn-1((path⊕opad) || Hn-1((path⊕ipad) || msg))
func kdfExpanded(key []byte, paths ...string) []byte {
	h0 := func(msg []byte) []byte {
		m := hmac.New(sha256.New, []byte("VMess AEAD KDF"))
		m.Write(msg)
		return m.Sum(nil)
	}
	h := h0
	for _, p := range paths {
		parent := h
		pp := []byte(p)
		ip := xorPad(pp, 0x36)
		op := xorPad(pp, 0x5c)
		h = func(msg []byte) []byte {
			return parent(append(op, parent(append(ip, msg...))...))
		}
	}
	return h(key)
}

func main() {
	key := []byte("secret-key-123456")
	pathsList := [][]string{
		{"AES Auth ID Encryption"},
		{"VMess Header AEAD Key"},
		{"VMess Header AEAD Key", "authid16bytes!"},
	}
	for _, paths := range pathsList {
		a := kdfCreator(key, paths...)
		b := kdfExpanded(key, paths...)
		same := hmac.Equal(a, b)
		fmt.Printf("paths=%v creator=%x\n       expanded=%x same=%v\n", paths, a, b, same)
	}
}
