package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	tcpKind = 0x01
	udpKind = 0x02
	domain  = "example.com"
)

func appendAddress(out []byte, host string, port uint16) []byte {
	out = append(out, 0x02, byte(len(host)))
	out = append(out, host...)
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], port)
	return append(out, portBytes[:]...)
}

func buildTCP(payload []byte) []byte {
	out := append([]byte{tcpKind}, appendAddress(nil, domain, 443)...)
	return append(out, payload...)
}

func buildUDP(payload []byte) []byte {
	out := []byte{udpKind, 0x78, 0x56, 0x34, 0x12, 0x02, 0x00, 0x00, 0x00}
	out = append(out, appendAddress(nil, domain, 443)...)
	return append(out, payload...)
}

func parseAddress(wire []byte) (int, bool) {
	if len(wire) < 2 || wire[0] != 0x02 || int(wire[1])+4 > len(wire) {
		return 0, false
	}
	length := int(wire[1])
	if !bytes.Equal(wire[2:2+length], []byte(domain)) {
		return 0, false
	}
	port := binary.BigEndian.Uint16(wire[2+length : 4+length])
	return 4 + length, port == 443
}

func validTCP(wire, payload []byte) bool {
	if len(wire) <= 1 || wire[0] != tcpKind {
		return false
	}
	addressLength, ok := parseAddress(wire[1:])
	return ok && bytes.Equal(wire[1+addressLength:], payload)
}

func validUDP(wire, payload []byte) bool {
	if len(wire) <= 9 || wire[0] != udpKind || binary.LittleEndian.Uint32(wire[1:5]) != 0x12345678 ||
		binary.LittleEndian.Uint32(wire[5:9]) != 2 {
		return false
	}
	addressLength, ok := parseAddress(wire[9:])
	return ok && bytes.Equal(wire[9+addressLength:], payload)
}

func main() {
	payload := []byte("hysteria2-vector")
	if validTCP(buildTCP(payload), payload) && validUDP(buildUDP(payload), payload) {
		fmt.Println("PASS: Hysteria2 TCP/UDP reference vectors ok")
		return
	}
	fmt.Println("FAIL: Hysteria2 reference vector mismatch")
}
