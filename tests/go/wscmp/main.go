// Package main 是 WebSocket 帧编解码的 Go 参考实现（对齐 mihomo transport/ws 与
// C++ include/prism/handshake/ws/codec.hpp，RFC 6455）：
//   - compute_accept：SHA1(key + GUID) → base64（Sec-WebSocket-Accept）
//   - encode_frame：FIN|RSV|opcode + MASK|len + [ext len] + [mask] + payload（masked XOR）
//   - parse_frame_header：帧头解析（2/4/10 字节头）
// 用固定测试向量输出参考字节，供 C++ Ws 测试比对。
package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// computeAccept：Sec-WebSocket-Accept = base64(SHA1(key + GUID))
func computeAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

// encodeFrame：服务端帧（不 mask）；masked 参数模拟客户端帧
func encodeFrame(op byte, fin bool, masked bool, payload []byte) []byte {
	out := make([]byte, 0, 14+len(payload))
	b0 := op
	if fin {
		b0 |= 0x80
	}
	out = append(out, b0)
	len7 := len(payload)
	switch {
	case len7 < 126:
		out = append(out, byte(len7))
	case len7 <= 0xFFFF:
		out = append(out, 126, byte(len7>>8), byte(len7))
	default:
		out = append(out, 127)
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len7))
		out = append(out, l[:]...)
	}
	if masked {
		out[1] |= 0x80
		mask := []byte{0x12, 0x34, 0x56, 0x78}
		out = append(out, mask...)
		payload = applyMask(payload, mask)
	}
	return append(out, payload...)
}

// applyMask：32bit 循环 XOR
func applyMask(payload, mask []byte) []byte {
	out := make([]byte, len(payload))
	for i := range payload {
		out[i] = payload[i] ^ mask[i%4]
	}
	return out
}

// parseFrameHeader：帧头解析，返回 (fin, opcode, masked, payloadLen, headerLen)
func parseFrameHeader(in []byte) (bool, byte, bool, uint64, int, bool) {
	if len(in) < 2 {
		return false, 0, false, 0, 0, false
	}
	fin := in[0]&0x80 != 0
	op := in[0] & 0x0F
	masked := in[1]&0x80 != 0
	len7 := in[1] & 0x7F
	off := 2
	var payloadLen uint64
	switch {
	case len7 < 126:
		payloadLen = uint64(len7)
	case len7 == 126:
		if len(in) < 4 {
			return false, 0, false, 0, 0, false
		}
		payloadLen = uint64(binary.BigEndian.Uint16(in[2:4]))
		off = 4
	case len7 == 127:
		if len(in) < 10 {
			return false, 0, false, 0, 0, false
		}
		payloadLen = binary.BigEndian.Uint64(in[2:10])
		off = 10
	}
	if masked {
		off += 4
	}
	return fin, op, masked, payloadLen, off, true
}

func main() {
	// Sec-WebSocket-Accept
	key := "dGhlIHNhbXBsZSBub25jZQ=="
	accept := computeAccept(key)

	// 帧编解码
	payload := []byte("hello websocket frame data 0123456789")
	frame := encodeFrame(0x02, true, false, payload)      // 服务端 binary FIN
	clientFrame := encodeFrame(0x01, true, true, payload) // 客户端 text FIN masked

	fin, op, masked, plen, hlen, ok := parseFrameHeader(frame)
	_, _, cmasked, cplen, chlen, cok := parseFrameHeader(clientFrame)

	fmt.Printf("ws_accept       = %s\n", accept)
	fmt.Printf("server_frame    = %s\n", hex.EncodeToString(frame))
	fmt.Printf("client_frame    = %s\n", hex.EncodeToString(clientFrame))
	fmt.Printf("srv fin=%v op=%d masked=%v plen=%d hlen=%d ok=%v\n", fin, op, masked, plen, hlen, ok)
	fmt.Printf("cli masked=%v plen=%d hlen=%d ok=%v\n", cmasked, cplen, chlen, cok)
	if ok && cok && !masked && cmasked && plen == uint64(len(payload)) && cplen == uint64(len(payload)) {
		fmt.Printf("PASS: websocket frame reference ok\n")
	} else {
		fmt.Printf("FAIL: websocket frame mismatch\n")
	}
}
