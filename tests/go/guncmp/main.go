// Package main 是 gRPC (gun) 帧编解码的 Go 参考实现（对齐 mihomo transport/gun 与
// C++ include/prism/handshake/gun/codec.hpp，gun-lite 兼容）：
//   写：[0x00 压缩标志][u32 BE 长度][0x0A protobuf field1][uvarint][payload]
//   长度 = 1 + varintLen + payloadLen；uvarint 为 protobuf LEB128。
// 用固定测试向量输出参考字节，供 C++ Gun 测试比对。
package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

const headerFixedLen = 6

// encodeVarint：protobuf LEB128
func encodeVarint(value uint32) []byte {
	out := make([]byte, 0, 5)
	for value >= 0x80 {
		out = append(out, byte(value&0x7F|0x80))
		value >>= 7
	}
	return append(out, byte(value))
}

// decodeVarint：protobuf LEB128 解码
func decodeVarint(in []byte) (uint32, int) {
	var v uint32
	for i := 0; i < len(in) && i < 5; i++ {
		v |= uint32(in[i]&0x7F) << (7 * i)
		if in[i]&0x80 == 0 {
			return v, i + 1
		}
	}
	return 0, 0
}

// encodeFrame：gun 帧 [0x00][u32 BE len][0x0A][uvarint][payload]
func encodeFrame(payload []byte) []byte {
	varint := encodeVarint(uint32(len(payload)))
	frame := make([]byte, 0, headerFixedLen+len(varint)+len(payload))
	frame = append(frame, 0x00)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(1+len(varint)+len(payload)))
	frame = append(frame, l[:]...)
	frame = append(frame, 0x0A)
	frame = append(frame, varint...)
	return append(frame, payload...)
}

// parseFrameHeader：解析帧头（跳过 6 字节定长头 → uvarint → payload_len）
func parseFrameHeader(in []byte) (int, int, bool) {
	if len(in) < headerFixedLen+1 {
		return 0, 0, false
	}
	if in[0] != 0x00 || in[5] != 0x0A {
		return 0, 0, false
	}
	totalLen := binary.BigEndian.Uint32(in[1:5])
	plen, vlen := decodeVarint(in[headerFixedLen:])
	if vlen == 0 || uint32(1+vlen)+plen != totalLen {
		return 0, 0, false
	}
	return int(plen), headerFixedLen + vlen, true
}

func main() {
	payload := []byte("hello gun grpc payload 0123456789abcdef")
	frame := encodeFrame(payload)

	plen, hlen, ok := parseFrameHeader(frame)

	fmt.Printf("gun_frame       = %s\n", hex.EncodeToString(frame))
	fmt.Printf("payload_len     = %d\n", plen)
	fmt.Printf("header_len      = %d\n", hlen)
	fmt.Printf("parse_ok        = %v\n", ok)
	if ok && plen == len(payload) && len(frame) == hlen+plen {
		fmt.Printf("PASS: gun frame reference ok\n")
	} else {
		fmt.Printf("FAIL: gun frame mismatch\n")
	}
}
