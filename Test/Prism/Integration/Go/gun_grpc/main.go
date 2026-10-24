// Package main provides a minimal standard HTTP/2 gRPC h2c reference.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const payload = "prism-standard-grpc-gun-payload"

func encodeHeaders(fields []hpack.HeaderField) ([]byte, error) {
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, field := range fields {
		if err := encoder.WriteField(field); err != nil {
			return nil, err
		}
	}
	return block.Bytes(), nil
}

func decodeHeaders(frame *http2.MetaHeadersFrame) map[string]string {
	result := make(map[string]string)
	for _, field := range frame.Fields {
		result[field.Name] = field.Value
	}
	return result
}

func grpcMessage(value []byte) []byte {
	result := make([]byte, 5+len(value))
	result[4] = byte(len(value))
	copy(result[5:], value)
	return result
}

func readSettingsAndRequest(conn net.Conn, framer *http2.Framer) (uint32, []byte, error) {
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		return 0, nil, err
	}
	if string(preface) != http2.ClientPreface {
		return 0, nil, fmt.Errorf("invalid HTTP/2 preface")
	}
	var streamID uint32
	var body []byte
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			return 0, nil, err
		}
		switch value := frame.(type) {
		case *http2.SettingsFrame:
			if !value.IsAck() {
				if err := framer.WriteSettingsAck(); err != nil {
					return 0, nil, err
				}
			}
		case *http2.MetaHeadersFrame:
			if streamID != 0 {
				return 0, nil, fmt.Errorf("multiple request streams")
			}
			headers := decodeHeaders(value)
			if headers[":method"] != "POST" || headers[":path"] != "/GunService/Tun" ||
				headers["content-type"] != "application/grpc" || headers["te"] != "trailers" ||
				headers[":authority"] == "" {
				return 0, nil, fmt.Errorf("invalid gRPC request headers: %#v", headers)
			}
			streamID = value.StreamID
		case *http2.DataFrame:
			if value.StreamID != streamID {
				return 0, nil, fmt.Errorf("unexpected DATA stream")
			}
			body = append(body, value.Data()...)
			if value.StreamEnded() {
				if len(body) < 5 || body[0] != 0 || int(body[1])<<24|int(body[2])<<16|int(body[3])<<8|int(body[4]) != len(body)-5 {
					return 0, nil, fmt.Errorf("invalid gRPC message envelope")
				}
				return streamID, body[5:], nil
			}
		}
	}
}

func writeResponse(framer *http2.Framer, streamID uint32, data []byte) error {
	headerBlock, err := encodeHeaders([]hpack.HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-type", Value: "application/grpc"},
	})
	if err != nil {
		return err
	}
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID: streamID, BlockFragment: headerBlock, EndHeaders: true,
	}); err != nil {
		return err
	}
	if err := framer.WriteData(streamID, false, grpcMessage(data)); err != nil {
		return err
	}
	trailerBlock, err := encodeHeaders([]hpack.HeaderField{
		{Name: "grpc-status", Value: "0"},
		{Name: "grpc-message", Value: ""},
	})
	if err != nil {
		return err
	}
	return framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID: streamID, BlockFragment: trailerBlock, EndHeaders: true, EndStream: true,
	})
}

func runServer(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	fmt.Printf("READY: Go standard gRPC h2c server on %s\n", addr)
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	framer := http2.NewFramer(conn, conn)
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	streamID, request, err := readSettingsAndRequest(conn, framer)
	if err != nil {
		return err
	}
	if err := writeResponse(framer, streamID, request); err != nil {
		return err
	}
	fmt.Printf("PASS: Go standard gRPC h2c server status=0 payload=%d\n", len(request))
	return nil
}

func runClient(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	framer := http2.NewFramer(conn, conn)
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		return err
	}
	if err := framer.WriteSettings(); err != nil {
		return err
	}
	headerBlock, err := encodeHeaders([]hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "http"},
		{Name: ":path", Value: "/GunService/Tun"},
		{Name: ":authority", Value: "edge.example"},
		{Name: "content-type", Value: "application/grpc"},
		{Name: "te", Value: "trailers"},
	})
	if err != nil {
		return err
	}
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1, BlockFragment: headerBlock, EndHeaders: true,
	}); err != nil {
		return err
	}
	if err := framer.WriteData(1, true, grpcMessage([]byte(payload))); err != nil {
		return err
	}
	var response []byte
	status := ""
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			return err
		}
		switch value := frame.(type) {
		case *http2.SettingsFrame:
			if !value.IsAck() {
				if err := framer.WriteSettingsAck(); err != nil {
					return err
				}
			}
		case *http2.MetaHeadersFrame:
			for _, field := range value.Fields {
				if field.Name == ":status" && field.Value != "200" {
					return fmt.Errorf("unexpected HTTP status %s", field.Value)
				}
				if field.Name == "grpc-status" {
					status = field.Value
				}
			}
			if value.StreamEnded() {
				if status != "0" {
					return fmt.Errorf("unexpected grpc-status %s", status)
				}
				break
			}
		case *http2.DataFrame:
			response = append(response, value.Data()...)
		}
		if status == "0" {
			break
		}
	}
	if len(response) != 5+len(payload) || response[0] != 0 ||
		int(response[1])<<24|int(response[2])<<16|int(response[3])<<8|int(response[4]) != len(payload) ||
		string(response[5:]) != payload {
		return fmt.Errorf("unexpected gRPC response payload")
	}
	fmt.Printf("PASS: Go standard gRPC h2c client status=%s payload=%d\n", status, len(payload))
	return nil
}

func main() {
	mode := flag.String("mode", "client", "client or server")
	addr := flag.String("addr", "127.0.0.1:19098", "TCP address")
	flag.Parse()
	var err error
	if *mode == "server" {
		err = runServer(*addr)
	} else {
		err = runClient(*addr)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: standard gRPC h2c: %v\n", err)
		os.Exit(1)
	}
}
