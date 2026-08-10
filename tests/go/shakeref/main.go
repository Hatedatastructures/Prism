// Package main 输出 sha3.Shake128 的参考字节流，用于对比 Prism shake_stream
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"golang.org/x/crypto/sha3"
)

func main() {
	seed := os.Args[1]
	h := sha3.NewShake128()
	h.Write([]byte(seed))
	out := make([]byte, 64)
	_, _ = h.Read(out)
	fmt.Println(hex.EncodeToString(out))
}
