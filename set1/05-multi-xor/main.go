package main

import (
	"encoding/hex"
	"fmt"
)

func xorBytes(a, b []byte) []byte {
	var j int
	r := make([]byte, len(a), len(a))
	for i := 0; i < len(a); i++ {
		r[i] = a[i] ^ b[j]
		j = (j + 1) % len(b)
	}
	return r
}

func main() {
	txt := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	k := "ICE"
	res := xorBytes([]byte(txt), []byte(k))
	fmt.Printf("%s\n", hex.EncodeToString(res))
}
