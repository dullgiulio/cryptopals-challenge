package main

import (
	"encoding/hex"
	"fmt"
	"log"
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

func hexDec(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		log.Fatalf("cannot decode hex string %s: %v", s, err)
	}
	return b
}

func main() {
	a := "1c0111001f010100061a024b53535009181c"
	k := "686974207468652062756c6c277320657965"
	res := xorBytes(hexDec(a), hexDec(k))
	fmt.Printf("%s\n", hex.EncodeToString(res))
}
