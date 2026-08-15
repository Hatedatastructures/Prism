// Package main 性能对标：Go 实现（metacubex/qpack + AEAD）
// 与 C++ CorePerf（tests/perf/CorePerf.cpp）同指标对比，
// 验证 C++ 实现性能不低于 Go 版本。
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"time"

	"github.com/metacubex/qpack"
)

func main() {
	benchQpackEncode()
	benchQpackDecode()
	benchAeadSeal16KB()
	benchSocks5EncodeAddress()
	benchSocks5BuildRequest()
	benchTrojanBuildRequest()
	benchVlessBuildRequest()
	benchHysteria2BuildUdp()
	benchTuicBuildPacket()
}

// ── 协议编解码对照（与 C++ CodecPerf 同指标）──

func benchSocks5EncodeAddress() {
	// [ATYP][ADDR][PORT 2B]：域名 example.com:443
	host := []byte("example.com")
	port := uint16(443)
	iters := 200000
	start := time.Now()
	total := 0
	for i := 0; i < iters; i++ {
		out := make([]byte, 0, 1+len(host)+2)
		out = append(out, 0x03)
		out = append(out, byte(len(host)))
		out = append(out, host...)
		out = append(out, byte(port>>8), byte(port))
		total += len(out)
	}
	elapsed := time.Since(start)
	fmt.Printf("Go Socks5EncodeAddress: %d iters, %.2f ns/op (sink=%d)\n", iters,
		float64(elapsed.Nanoseconds())/float64(iters), total)
}

func benchSocks5BuildRequest() {
	host := []byte("example.com")
	port := uint16(443)
	iters := 200000
	start := time.Now()
	total := 0
	for i := 0; i < iters; i++ {
		out := make([]byte, 0, 3+1+len(host)+2)
		out = append(out, 0x05, 0x01, 0x00) // ver cmd rsv
		out = append(out, 0x03, byte(len(host)))
		out = append(out, host...)
		out = append(out, byte(port>>8), byte(port))
		total += len(out)
	}
	elapsed := time.Since(start)
	fmt.Printf("Go Socks5BuildRequest: %d iters, %.2f ns/op (sink=%d)\n", iters,
		float64(elapsed.Nanoseconds())/float64(iters), total)
}

func benchTrojanBuildRequest() {
	cred := "d41d8cd98f00b204e9800998ecf8427e" // sha224 hex 占位
	host := []byte("example.com")
	port := uint16(443)
	iters := 200000
	start := time.Now()
	total := 0
	for i := 0; i < iters; i++ {
		out := make([]byte, 0, len(cred)+1+1+1+len(host)+2+2)
		out = append(out, cred...)
		out = append(out, '\r', '\n')
		out = append(out, 0x01) // CONNECT
		out = append(out, 0x03, byte(len(host)))
		out = append(out, host...)
		out = append(out, byte(port>>8), byte(port))
		out = append(out, '\r', '\n')
		total += len(out)
	}
	elapsed := time.Since(start)
	fmt.Printf("Go TrojanBuildRequest: %d iters, %.2f ns/op (sink=%d)\n", iters,
		float64(elapsed.Nanoseconds())/float64(iters), total)
}

func benchVlessBuildRequest() {
	uuid := make([]byte, 16)
	host := []byte("example.com")
	port := uint16(443)
	iters := 200000
	start := time.Now()
	total := 0
	for i := 0; i < iters; i++ {
		out := make([]byte, 0, 1+16+1+1+2+1+len(host))
		out = append(out, 0x00) // version
		out = append(out, uuid...)
		out = append(out, 0x00)          // addons len
		out = append(out, 0x01)          // tcp
		out = append(out, byte(port>>8), byte(port))
		out = append(out, 0x03, byte(len(host)))
		out = append(out, host...)
		total += len(out)
	}
	elapsed := time.Since(start)
	fmt.Printf("Go VlessBuildRequest: %d iters, %.2f ns/op (sink=%d)\n", iters,
		float64(elapsed.Nanoseconds())/float64(iters), total)
}

func benchHysteria2BuildUdp() {
	host := []byte("example.com")
	port := uint16(443)
	payload := make([]byte, 128)
	iters := 100000
	start := time.Now()
	total := 0
	for i := 0; i < iters; i++ {
		out := make([]byte, 0, 4+1+1+len(host)+2+len(payload))
		out = append(out, 0x02) // kind udp
		out = append(out, 0x01, 0x00, 0x00) // session_id
		out = append(out, 0x03, byte(len(host)))
		out = append(out, host...)
		out = append(out, byte(port>>8), byte(port))
		out = append(out, payload...)
		total += len(out)
	}
	elapsed := time.Since(start)
	fmt.Printf("Go Hysteria2BuildUdp: %d iters, %.2f ns/op (sink=%d)\n", iters,
		float64(elapsed.Nanoseconds())/float64(iters), total)
}

func benchTuicBuildPacket() {
	host := []byte("example.com")
	port := uint16(443)
	payload := make([]byte, 128)
	iters := 100000
	start := time.Now()
	total := 0
	for i := 0; i < iters; i++ {
		out := make([]byte, 0, 2+4+4+1+len(host)+2+len(payload))
		out = append(out, 0x00, 0x04)                          // ver + packet
		out = append(out, 0x01, 0x00, 0x00, 0x00)              // assoc_id
		out = append(out, 0x02, 0x00, 0x00, 0x00)              // pkt_id
		out = append(out, byte(port>>8), byte(port))
		out = append(out, 0x03, byte(len(host)))
		out = append(out, host...)
		out = append(out, payload...)
		total += len(out)
	}
	elapsed := time.Since(start)
	fmt.Printf("Go TuicBuildPacket: %d iters, %.2f ns/op (sink=%d)\n", iters,
		float64(elapsed.Nanoseconds())/float64(iters), total)
}

func benchQpackEncode() {
	fields := []qpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":path", Value: "/auth"},
		{Name: "hysteria-auth", Value: "password123"},
	}
	start := time.Now()
	iters := 100000
	for i := 0; i < iters; i++ {
		enc := qpack.NewEncoder(discardWriter{})
		for _, f := range fields {
			enc.WriteField(f)
		}
	}
	elapsed := time.Since(start)
	fmt.Printf("Go QpackEncode: %d iters in %v, %.2f ns/op\n", iters, elapsed,
		float64(elapsed.Nanoseconds())/float64(iters))
}

func benchQpackDecode() {
	// 先编码一份数据供解码
	var buf []byte
	enc := qpack.NewEncoder(&sliceWriter{&buf})
	enc.WriteField(qpack.HeaderField{Name: ":method", Value: "POST"})
	enc.WriteField(qpack.HeaderField{Name: "hysteria-auth", Value: "password123"})

	start := time.Now()
	iters := 10000
	for i := 0; i < iters; i++ {
		dec := qpack.NewDecoder()
		next := dec.Decode(buf)
		for {
			_, err := next()
			if err != nil {
				break
			}
		}
	}
	elapsed := time.Since(start)
	fmt.Printf("Go QpackDecode: %d iters in %v, %.2f ns/op\n", iters, elapsed,
		float64(elapsed.Nanoseconds())/float64(iters))
}

func benchAeadSeal16KB() {
	key := make([]byte, 16)
	for i := range key {
		key[i] = 0x42
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	plain := make([]byte, 16384)
	for i := range plain {
		plain[i] = byte(i)
	}

	start := time.Now()
	iters := 10000
	total := 0
	for i := 0; i < iters; i++ {
		out := gcm.Seal(nil, nonce, plain, nil)
		total += len(out)
	}
	elapsed := time.Since(start)
	bytesPerSec := float64(total) / elapsed.Seconds()
	fmt.Printf("Go AeadSeal16KB: %d iters in %v, %.2f MiB/s (%d bytes)\n", iters, elapsed,
		bytesPerSec/1024/1024, total)
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

type sliceWriter struct{ buf *[]byte }

func (w *sliceWriter) Write(p []byte) (int, error) {
	*w.buf = append(*w.buf, p...)
	return len(p), nil
}
