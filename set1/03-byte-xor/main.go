package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
)

type hist []byte

func asciiFreq(text []byte) hist {
	hst := make([]byte, 256, 256)
	for i := 0; i < len(text); i++ {
		v := text[i]
		if 'A' <= v && v <= 'Z' {
			v = 'Z' - v
		}
		hst[int(v)]++
	}
	return hist(hst)
}

func abs(a int) int {
	if a < 0 {
		return -a
	}
	return a
}

func histDistance(hst1, hst2 hist) int {
	if len(hst1) != len(hst2) {
		panic("histograms must have the same length")
	}
	var diff int
	for i := 0; i < len(hst1); i++ {
		diff = diff + abs(int(hst2[i])-int(hst1[i]))
	}
	return diff
}

func (h *hist) String() string {
	var buf bytes.Buffer
	for i := 0; i < len(*h); i++ {
		if (*h)[i] == 0 {
			continue
		}
		fmt.Fprintf(&buf, "%c = %d ", i, (*h)[i])
	}
	return buf.String()
}

func xorByte(bs []byte, k byte) []byte {
	r := make([]byte, len(bs), len(bs))
	for i := 0; i < len(bs); i++ {
		r[i] = bs[i] ^ k
	}
	return r
}

func main() {
	flag.Parse()
	fname := flag.Arg(0)
	if fname == "" {
		log.Fatal("first argument is the sample text filename")
	}
	sample, err := ioutil.ReadFile(fname)
	if err != nil {
		log.Fatalf("cannot read sample text file: %v", err)
	}
	ref := asciiFreq(sample)
	secret := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	sb, err := hex.DecodeString(secret)
	if err != nil {
		log.Fatalf("cannot decode hex string %s: %v", secret, err)
	}
	var (
		minDist int = -1
		minBs   []byte
	)
	for i := 0; i < 256; i++ {
		rsb := xorByte(sb, byte(i))
		hs := asciiFreq(rsb)
		d := histDistance(hs, ref)
		if minDist < 0 || d < minDist {
			minDist = d
			minBs = rsb
		}
	}
	fmt.Printf("%s\n", minBs)
}
