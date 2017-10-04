package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

// 04-dectect-xor ../03-byte-xor/english-sample.txt 4.txt

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

func loadCodes(fname string) ([]string, error) {
	fh, err := os.Open(fname)
	if err != nil {
		return nil, fmt.Errorf("cannot open codes file: %v", err)
	}
	defer fh.Close()
	scanner := bufio.NewScanner(fh)
	codes := make([]string, 0)
	for scanner.Scan() {
		codes = append(codes, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error while reading codes: %v", err)
	}
	return codes, nil
}

func singleByteBrute(code []byte, ref hist) (dist int, dec []byte) {
	var (
		minDist int = -1
		minBs   []byte
	)
	for i := 0; i < 256; i++ {
		rsb := xorByte(code, byte(i))
		hs := asciiFreq(rsb)
		d := histDistance(hs, ref)
		if minDist < 0 || d < minDist {
			minDist = d
			minBs = rsb
		}
	}
	return minDist, minBs
}

func main() {
	flag.Parse()
	sampleF := flag.Arg(0)
	if sampleF == "" {
		log.Fatal("first argument is the sample text filename")
	}
	codesF := flag.Arg(1)
	if codesF == "" {
		log.Fatal("second argument is the codes to detect")
	}
	sample, err := ioutil.ReadFile(sampleF)
	if err != nil {
		log.Fatalf("cannot read sample text file: %v", err)
	}
	codes, err := loadCodes(codesF)
	if err != nil {
		log.Fatalf("cannot load codes from file %s: %v", codesF, err)
	}
	ref := asciiFreq(sample)
	var (
		minDist int = -1
		minBs   []byte
		minCode string
	)
	for _, code := range codes {
		sb, err := hex.DecodeString(code)
		if err != nil {
			log.Fatalf("cannot decode hex string %s: %v", code, err)
		}
		dist, bs := singleByteBrute(sb, ref)
		if minDist < 0 || dist < minDist {
			minDist = dist
			minBs = bs
			minCode = code
		}
	}
	fmt.Printf("%s: %s\n", minCode, minBs)
}
