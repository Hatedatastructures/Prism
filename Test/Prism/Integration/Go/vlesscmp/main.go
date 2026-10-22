package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func buildRequest() []byte {
	uuid := make([]byte, 16)
	for index := range uuid {
		uuid[index] = byte(index + 1)
	}
	domain := []byte("example.com")
	request := []byte{0x00}
	request = append(request, uuid...)
	request = append(request, 0x00, 0x01, 0x01, 0xBB, 0x03, byte(len(domain)))
	request = append(request, domain...)
	return request
}

func parseRequest(wire []byte) bool {
	if len(wire) < 22 || wire[0] != 0x00 || wire[17] != 0x00 || wire[18] != 0x01 {
		return false
	}
	if binary.BigEndian.Uint16(wire[19:21]) != 443 || wire[21] != 0x03 {
		return false
	}
	if len(wire) <= 22 || int(wire[22]) != len(wire)-23 {
		return false
	}
	return bytes.Equal(wire[23:], []byte("example.com"))
}

func main() {
	wire := buildRequest()
	if parseRequest(wire) {
		fmt.Println("PASS: VLESS reference vector ok")
		return
	}
	fmt.Println("FAIL: VLESS reference vector mismatch")
}
