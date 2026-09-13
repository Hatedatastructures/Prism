package main

import (
	"bytes"
	"fmt"
)

func main() {
	greeting := []byte{0x05, 0x01, 0x00}
	methodReply := []byte{0x05, 0x00}
	target := []byte("example.com")
	request := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(target))}, target...)
	request = append(request, 0x01, 0xBB) // 443
	success := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xBB}
	valid := bytes.Equal(greeting, []byte{0x05, 0x01, 0x00}) &&
		bytes.Equal(methodReply, []byte{0x05, 0x00}) &&
		len(request) == 5+len(target)+2 && request[3] == 0x03 &&
		bytes.Equal(success[:4], []byte{0x05, 0x00, 0x00, 0x01}) &&
		success[len(success)-2] == 0x01 && success[len(success)-1] == 0xBB
	if valid {
		fmt.Println("PASS: SOCKS5 reference vector ok")
		return
	}
	fmt.Println("FAIL: SOCKS5 reference vector mismatch")
}
