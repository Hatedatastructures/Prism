package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	version = 0x05
	connect = 0x01
	packet  = 0x02
)

func appendDomain(out []byte, host string, port uint16) []byte {
	out = append(out, 0x00, byte(len(host)))
	out = append(out, host...)
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], port)
	return append(out, portBytes[:]...)
}

func buildAuthenticate() []byte {
	wire := []byte{version, 0x00}
	for index := 0; index < 16; index++ {
		wire = append(wire, byte(index))
	}
	for index := 0; index < 32; index++ {
		wire = append(wire, byte(0xa0+index))
	}
	return wire
}

func buildConnect() []byte {
	return append([]byte{version, connect}, appendDomain(nil, "example.com", 443)...)
}

func buildPacket(payload []byte) []byte {
	wire := []byte{version, packet, 0x12, 0x34, 0x01, 0x02, 0x02, 0x00,
		byte(len(payload) >> 8), byte(len(payload))}
	wire = append(wire, appendDomain(nil, "example.com", 443)...)
	return append(wire, payload...)
}

func validAuthenticate(wire []byte) bool {
	return len(wire) == 50 && wire[0] == version && wire[1] == 0x00 && wire[2] == 0x00 &&
		wire[17] == 0x0f && wire[18] == 0xa0 && wire[49] == 0xbf
}

func validConnect(wire []byte) bool {
	return len(wire) == 2+2+len("example.com")+2 && wire[0] == version && wire[1] == connect &&
		wire[2] == 0x00 && wire[3] == byte(len("example.com")) &&
		bytes.Equal(wire[4:4+len("example.com")], []byte("example.com")) &&
		binary.BigEndian.Uint16(wire[len(wire)-2:]) == 443
}

func validPacket(wire, payload []byte) bool {
	const header = 10
	if len(wire) < header+2 || wire[0] != version || wire[1] != packet ||
		binary.BigEndian.Uint16(wire[2:4]) != 0x1234 || binary.BigEndian.Uint16(wire[4:6]) != 0x0102 ||
		wire[6] != 2 || wire[7] != 0 || int(binary.BigEndian.Uint16(wire[8:10])) != len(payload) {
		return false
	}
	address := appendDomain(nil, "example.com", 443)
	return bytes.Equal(wire[10:10+len(address)], address) &&
		bytes.Equal(wire[10+len(address):], payload)
}

func main() {
	payload := []byte("tuic-vector")
	if validAuthenticate(buildAuthenticate()) && validConnect(buildConnect()) &&
		validPacket(buildPacket(payload), payload) {
		fmt.Println("PASS: TUIC v5 reference vectors ok")
		return
	}
	fmt.Println("FAIL: TUIC v5 reference vector mismatch")
}
