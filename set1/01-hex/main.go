package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
)

func main() {
	s := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	bs, err := hex.DecodeString(s)
	if err != nil {
		log.Fatalf("cannot parse hex string: %v", err)
	}
	nb64 := base64.StdEncoding.EncodeToString(bs)
	fmt.Printf("%s\n", nb64)
}
