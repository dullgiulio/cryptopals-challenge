package main

import (
	"bufio"
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

type hist []byte

func asciiFreq(text []byte) hist {
	hst := make([]byte, 256, 256)
	for i := 0; i < len(text); i++ {
		v := text[i]
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
	buf := new(bytes.Buffer)
	scanner := bufio.NewScanner(fh)
	for scanner.Scan() {
		bs := scanner.Bytes()
		data := make([]byte, base64.StdEncoding.DecodedLen(len(bs)))
		n, err := base64.StdEncoding.Decode(data, bs)
		if err != nil {
			return nil, fmt.Errorf("cannot decode base64 line: %v", err)
		}
		if _, err := buf.Write(data[:n]); err != nil {
			return nil, fmt.Errorf("cannot write to buffer: %v", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error while reading codes: %v", err)
	}
	return buf.Bytes(), nil
}

type keydists struct {
	ks []int
	ds []int
}

func makeKeydists(w int) keydists {
	return keydists{
		ks: make([]int, w, w),
		ds: make([]int, w, w),
	}
}

func (k *keydists) add(i, val, dist int) {
	k.ks[i] = val
	k.ds[i] = dist
}

func (k *keydists) first(n int) []int {
	return k.ks[:n]
}

func (k *keydists) Len() int {
	return len(k.ks)
}

func (k *keydists) Less(i, j int) bool {
	return k.ds[i] < k.ds[j]
}

func (k *keydists) Swap(i, j int) {
	k.ds[i], k.ds[j] = k.ds[j], k.ds[i]
	k.ks[i], k.ks[j] = k.ks[j], k.ks[i]
}

func keysizes(min, max, n int, data []byte) ([]int, error) {
	w := max - min
	sz := makeKeydists(w)
	for i := 0; i < w; i++ {
		keysz := i + min
		if len(data) < keysz*2 {
			return nil, fmt.Errorf("data too small for keysize %d", keysz)
		}
		a := data[0 : keysz-1]
		b := data[keysz : keysz*2-1]
		dst := hamming(a, b) / keysz
		sz.add(i, keysz, dst)
	}
	sort.Sort(&sz)
	return sz.first(n), nil
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
		for b := byte('!'); b <= byte('~'); b++ {
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
	ks, err := keysizes(4, 200, 4, data)
	if err != nil {
		log.Fatalf("cannot guess keysize: %v", err)
	}
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
	fmt.Printf("PASSWORD: %s\n\n%s\n===================\n", string(minPass), string(minText))
}
