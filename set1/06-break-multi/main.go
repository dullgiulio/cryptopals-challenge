package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/bits"
	"os"
	"sort"
)

// 06-break-multi -input 6.txt -sample ../03-byte-xor/english-sample.txt

func hamming(a, b []byte) int {
	d := 0
	n := len(a)
	if len(a) != len(b) {
		if len(b) > n {
			d = (len(b) - len(a)) * 8
			b = b[0:len(a)]
		} else {
			n = len(b)
			d = (len(a) - len(b)) * 8
			a = a[0:len(b)]
		}
	}
	for i := 0; i < n; i++ {
		d = d + bits.OnesCount8(uint8(a[i]^b[i]))
	}
	return d
}

type hist []int

func asciiFreq(text []byte) hist {
	hst := make([]int, 256, 256)
	for i := 0; i < len(text); i++ {
		v := text[i]
		hst[int(v)]++
	}
	for i := 0; i < len(hst); i++ {
		hst[i] = int(hst[i]) * 2048 / len(text)
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
		diff = diff + abs(int(hst2[i])-int(hst1[i]))*(int(hst2[i])+1)
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

func xorBytes(a, b []byte) []byte {
	var j int
	r := make([]byte, len(a), len(a))
	for i := 0; i < len(a); i++ {
		r[i] = a[i] ^ b[j]
		j = (j + 1) % len(b)
	}
	return r
}

func readBase64(fname string) ([]byte, error) {
	fh, err := os.Open(fname)
	if err != nil {
		return nil, fmt.Errorf("cannot open base64 file: %v", err)
	}
	defer fh.Close()
	dec := base64.NewDecoder(base64.StdEncoding, fh)
	return ioutil.ReadAll(dec)
}

type keydist struct {
	size int
	dist float64
}

type keydists []keydist

func (k keydists) Len() int {
	return len(k)
}

func (k keydists) Less(i, j int) bool {
	return k[i].dist < k[j].dist
}

func (k keydists) Swap(i, j int) {
	k[i], k[j] = k[j], k[i]
}

func (k keydists) first(n int) []int {
	sort.Sort(&k)
	first := make([]int, 0)
	sizes := 0
	lastdst := 0.0
	for _, ks := range k {
		if ks.dist != lastdst {
			sizes++
			lastdst = ks.dist
		}
		first = append(first, ks.size)
		if sizes > n-1 {
			break
		}
	}
	return first
}

func keysizes(min, max int, data []byte) (keydists, error) {
	ks := keydists(make([]keydist, 0))
	for keysz := min; keysz < max; keysz++ {
		if len(data) < keysz*4 {
			return nil, fmt.Errorf("data too short for keysize %d", keysz)
		}
		a := data[0:keysz]
		b := data[keysz : keysz*2]
		c := data[keysz*2 : keysz*3]
		d := data[keysz*3 : keysz*4]
		dst := float64(hamming(a, b)+hamming(b, c)+hamming(c, d)) / float64(keysz*4)
		ks = append(ks, keydist{keysz, dst})
	}
	return ks, nil
}

func makeBlocks(data []byte, sz int) [][]byte {
	blocks := make([][]byte, sz, sz)
	for n := 0; n < sz; n++ {
		blocks[n] = make([]byte, 0)
		for i := n; i < len(data); i = i + sz {
			blocks[n] = append(blocks[n], data[i])
		}
	}
	return blocks
}

func refHistogram(fname string) hist {
	sample, err := ioutil.ReadFile(fname)
	if err != nil {
		log.Fatalf("cannot read sample text file: %v", err)
	}
	return asciiFreq(sample)
}

func bestPassword(ksize int, data []byte, ref hist) []byte {
	blocks := makeBlocks(data, ksize)
	pass := make([]byte, ksize, ksize)
	for n, block := range blocks {
		var (
			minDist int = -1
			minByte byte
		)
		for b := byte(1); b <= byte(254); b++ {
			xb := xorByte(block, b)
			hs := asciiFreq(xb)
			d := histDistance(hs, ref)
			if minDist < 0 || d < minDist {
				minDist = d
				minByte = b
			}
		}
		pass[n] = minByte
	}
	return pass
}

func forceAscii(bs []byte) []byte {
	var buf bytes.Buffer
	for _, b := range bs {
		if b != '\n' && b != ' ' && (b < byte(33) || b > byte(126)) {
			fmt.Fprintf(&buf, "\\x%02x", b)
			continue
		}
		buf.WriteByte(b)
	}
	return buf.Bytes()
}

func main() {
	/*
		a := []byte("this is a test")
		b := []byte("wokka wokka!!!")
		fmt.Printf("%d\n", hamming(a, b))
	*/
	sname := flag.String("sample", "", "sample file for word frequency")
	fname := flag.String("input", "", "input file to decrypt")
	flag.Parse()
	if *fname == "" {
		log.Fatal("you must specify an -input file")
	}
	if *sname == "" {
		log.Fatal("you must specify a -sample file")
	}
	ref := refHistogram(*sname)
	data, err := readBase64(*fname)
	if err != nil {
		log.Fatalf("cannot read file to decrypt %s: %v", *fname, err)
	}
	// Likely key sizes to try
	kds, err := keysizes(2, 41, data)
	if err != nil {
		log.Fatalf("cannot guess keysize: %v", err)
	}
	ks := kds.first(3)
	var (
		minDist int = -1
		minText []byte
		minPass []byte
	)
	for _, ksize := range ks {
		pass := bestPassword(ksize, data, ref)
		clear := xorBytes(data, pass)
		hs := asciiFreq(clear)
		d := histDistance(hs, ref)
		if minDist < 0 || d < minDist {
			minDist = d
			minText = clear
			minPass = pass
		}
	}
	fmt.Printf("PASSWORD: %s\n\n%s\n", string(forceAscii(minPass)), string(forceAscii(minText)))
}
