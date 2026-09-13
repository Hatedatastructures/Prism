package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func fnv1a(data []byte) uint32 {
	hash := uint32(0x811c9dc5)
	for _, value := range data {
		hash ^= uint32(value)
		hash *= 0x01000193
	}
	return hash
}

func buildRequestHeader() []byte {
	wire := []byte{0x01}
	wire = append(wire, bytes.Repeat([]byte{0x11}, 16)...)
	wire = append(wire, bytes.Repeat([]byte{0x22}, 16)...)
	wire = append(wire, 0x42, 0x00, 0x02, 0x00, 0x01)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], 53)
	wire = append(wire, port[:]...)
	wire = append(wire, 0x02, byte(len("example.com")))
	wire = append(wire, []byte("example.com")...)
	for index := 0; index < 3; index++ {
		wire = append(wire, 0x00)
	}
	checksum := fnv1a(wire)
	var sum [4]byte
	binary.BigEndian.PutUint32(sum[:], checksum)
	return append(wire, sum[:]...)
}

func validRequestHeader(wire []byte) bool {
	const fixed = 41
	if len(wire) < fixed+1+len("example.com")+4 || wire[0] != 0x01 ||
		!bytes.Equal(wire[1:17], bytes.Repeat([]byte{0x11}, 16)) ||
		!bytes.Equal(wire[17:33], bytes.Repeat([]byte{0x22}, 16)) || wire[33] != 0x42 ||
		wire[34] != 0x00 || wire[35] != 0x02 || wire[37] != 0x01 ||
		binary.BigEndian.Uint16(wire[38:40]) != 53 || wire[40] != 0x02 || wire[41] != byte(len("example.com")) {
		return false
	}
	if !bytes.Equal(wire[42:42+len("example.com")], []byte("example.com")) {
		return false
	}
	bodyEnd := len(wire) - 4
	if !bytes.Equal(wire[42+len("example.com"):bodyEnd], []byte{0, 0, 0}) {
		return false
	}
	return binary.BigEndian.Uint32(wire[bodyEnd:]) == fnv1a(wire[:bodyEnd])
}

func main() {
	if validRequestHeader(buildRequestHeader()) {
		fmt.Println("PASS: VMess request-header reference vector ok")
		return
	}
	fmt.Println("FAIL: VMess request-header reference vector mismatch")
}
