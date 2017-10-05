package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
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

type cbcEnc struct {
	b  cipher.Block
	iv []byte
}

func newCbcEnc(b cipher.Block, iv []byte) *cbcEnc {
	return &cbcEnc{b, iv}
}

func (c *cbcEnc) BlockSize() int {
	return c.b.BlockSize()
}

func (c *cbcEnc) CryptBlocks(dst, src []byte) {
	blockSize := c.BlockSize()
	blk := c.iv
	for i := 0; i < len(src); i += blockSize {
		r := xorBytes(blk, src[i:i+blockSize])
		c.b.Encrypt(dst[i:], r)
		blk = dst[i : i+blockSize]
	}
}

type cbcDec cbcEnc

func newCbcDec(b cipher.Block, iv []byte) *cbcDec {
	return &cbcDec{b, iv}
}

func (c *cbcDec) BlockSize() int {
	return c.b.BlockSize()
}

func (c *cbcDec) CryptBlocks(dst, src []byte) {
	blockSize := c.BlockSize()
	blk := c.iv
	ndst := make([]byte, blockSize, blockSize)
	for i := 0; i < len(src); i += blockSize {
		nblk := src[i : i+blockSize]
		c.b.Decrypt(ndst, nblk)
		r := xorBytes(blk, ndst)
		copy(dst[i:], r)
		blk = nblk
	}
}

func decryptAesCbc(cph cipher.Block, data, iv []byte) []byte {
	dst := make([]byte, len(data), len(data))
	newCbcDec(cph, iv).CryptBlocks(dst, data)
	return dst
}

func encryptAesCbc(cph cipher.Block, data, iv []byte) []byte {
	dst := make([]byte, len(data), len(data))
	newCbcEnc(cph, iv).CryptBlocks(dst, data)
	return dst
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

func main() {
	flag.Parse()
	fname := flag.Arg(0)
	if fname == "" {
		log.Fatal("first argument is the file to decrypt")
	}
	data, err := readBase64(fname)
	if err != nil {
		log.Fatalf("cannot read encrypted file: %v", err)
	}
	cph, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	if err != nil {
		log.Fatalf("cannot create AES cipher: %v", err)
	}
	iv := make([]byte, 16, 16)
	clear := decryptAesCbc(cph, data, iv)
	ciph := encryptAesCbc(cph, clear, iv)
	fmt.Printf("%d\n", bytes.Compare(data, ciph))
}
