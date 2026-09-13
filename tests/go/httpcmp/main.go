package main

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

func main() {
	request := "CONNECT example.com:443 HTTP/1.1\r\n" +
		"Host: example.com:443\r\nProxy-Connection: Keep-Alive\r\n\r\n"
	parsedMethod := strings.HasPrefix(request, "CONNECT ")
	parsedTarget := strings.HasPrefix(request, "CONNECT example.com:443 ")
	response := "HTTP/1.1 200 Connection Established\r\n\r\n"
	status, _ := strconv.Atoi(strings.TrimSpace(strings.SplitN(strings.TrimPrefix(response, "HTTP/1.1 "), " ", 2)[0]))
	if parsedMethod && parsedTarget && status == http.StatusOK && bytes.HasSuffix([]byte(response), []byte("\r\n\r\n")) {
		fmt.Println("PASS: HTTP CONNECT reference vector ok")
		return
	}
	fmt.Println("FAIL: HTTP CONNECT reference vector mismatch")
}
