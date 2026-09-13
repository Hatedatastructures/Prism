package main

import (
	"bytes"
	"fmt"

	"golang.org/x/net/http2/hpack"
)

const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

func frame(kind byte, flags byte, stream uint32, payload []byte) []byte {
	wire := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), kind, flags,
		byte(stream >> 24), byte(stream >> 16), byte(stream >> 8), byte(stream)}
	return append(wire, payload...)
}

func buildHeaders() ([]byte, error) {
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, field := range []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":path", Value: "/"},
		{Name: "content-type", Value: "text/event-stream"},
	} {
		if err := encoder.WriteField(field); err != nil {
			return nil, err
		}
	}
	return block.Bytes(), nil
}

func main() {
	block, err := buildHeaders()
	if err != nil {
		fmt.Println("FAIL: XHTTP HPACK encode")
		return
	}
	wire := append([]byte(preface), frame(0x04, 0x00, 0, nil)...)
	wire = append(wire, frame(0x01, 0x04, 1, block)...)
	if len(wire) <= len(preface)+18 || !bytes.Equal(wire[:len(preface)], []byte(preface)) {
		fmt.Println("FAIL: XHTTP connection preface")
		return
	}
	frameOffset := len(preface) + 9
	if wire[frameOffset] != 0x01 || wire[frameOffset+1] != 0x04 || wire[frameOffset+5] != 0x00 ||
		wire[frameOffset+6] != 0x00 || wire[frameOffset+7] != 0x00 || wire[frameOffset+8] != 0x01 {
		fmt.Println("FAIL: XHTTP HEADERS frame")
		return
	}
	var fields []hpack.HeaderField
	decoder := hpack.NewDecoder(4096, func(field hpack.HeaderField) {
		fields = append(fields, field)
	})
	if _, err := decoder.Write(wire[frameOffset+9:]); err != nil || len(fields) != 3 ||
		fields[0].Name != ":method" || fields[0].Value != "POST" ||
		fields[1].Name != ":path" || fields[1].Value != "/" ||
		fields[2].Name != "content-type" || fields[2].Value != "text/event-stream" {
		fmt.Println("FAIL: XHTTP HPACK fields")
		return
	}
	fmt.Println("PASS: XHTTP HTTP/2 reference vector ok")
}
