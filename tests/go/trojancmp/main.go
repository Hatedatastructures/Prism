package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func credential(password string) []byte {
	sum := sha256.Sum224([]byte(password))
	return []byte(hex.EncodeToString(sum[:]))
}

func encodeDomainRequest(password, domain string, port uint16) []byte {
	request := append([]byte{}, credential(password)...)
	request = append(request, '\r', '\n', 0x01, 0x03, byte(len(domain)))
	request = append(request, domain...)
	request = append(request, byte(port>>8), byte(port), '\r', '\n')
	return request
}

func main() {
	wire := encodeDomainRequest("trojan_password", "example.com", 443)
	cred := credential("trojan_password")
	valid := len(wire) == 56+2+1+1+1+len("example.com")+2+2 &&
		bytes.Equal(wire[:56], cred) && bytes.Equal(wire[56:58], []byte("\r\n")) &&
		wire[58] == 0x01 && wire[59] == 0x03 &&
		wire[60] == byte(len("example.com")) &&
		bytes.Equal(wire[61:72], []byte("example.com")) &&
		bytes.Equal(wire[len(wire)-4:], []byte{0x01, 0xBB, '\r', '\n'})
	if valid {
		fmt.Println("PASS: Trojan reference vector ok")
		return
	}
	fmt.Println("FAIL: Trojan reference vector mismatch")
}
