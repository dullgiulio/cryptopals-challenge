package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
)

func readHex(fname string) ([][]byte, error) {
	fh, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	lines := make([][]byte, 0)
	scanner := bufio.NewScanner(fh)
	for scanner.Scan() {
		bs := scanner.Bytes()
		n := hex.DecodedLen(len(bs))
		line := make([]byte, n, n)
		n, err = hex.Decode(line, bs)
		if err != nil {
			return nil, fmt.Errorf("cannot decode line %s: %v", string(bs), err)
		}
		lines = append(lines, line[:n])
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error while reading hex line: %v", err)
	}
	return lines, nil
}

func repeatsBlocks(bs []byte, n int) int {
	blks := make([][]byte, 0)
	for i := 16; i < len(bs); i += n {
		blks = append(blks, bs[i-16:i])
	}
	var eq int
	for i := range blks {
		for j := range blks {
			if i != j && bytes.Compare(blks[i], blks[j]) == 0 {
				eq++
			}
		}
	}
	return eq
}

func main() {
	flag.Parse()
	fname := flag.Arg(0)
	if fname == "" {
		log.Fatal("first argument is the file to guess")
	}
	lines, err := readHex(fname)
	if err != nil {
		log.Fatalf("cannot read hex lines file: %v", err)
	}
	var (
		max   int
		mline []byte
	)
	for _, line := range lines {
		n := repeatsBlocks(line, 16)
		if n > max {
			max = n
			mline = line
		}
	}
	fmt.Printf("%d %s\n", max, hex.EncodeToString(mline))
}
