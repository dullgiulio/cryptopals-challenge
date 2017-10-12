package main

import (
	"crypto/aes"
	"crypto/cipher"
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

func decryptAesCbc(cph cipher.Block, data, iv []byte) ([]byte, bool) {
	dst := make([]byte, len(data), len(data))
	newCbcDec(cph, iv).CryptBlocks(dst, data)
	return dst, validAscii(dst)
}

func encryptAesCbc(cph cipher.Block, data, iv []byte) []byte {
	dst := make([]byte, len(data), len(data))
	newCbcEnc(cph, iv).CryptBlocks(dst, data)
	return dst
}

func validAscii(bs []byte) bool {
	for i := 0; i < len(bs); i++ {
		if bs[i] >= 127 {
			return false
		}
	}
	return true
}

func main() {
	key := []byte("YELLOW SUBMARINE")
	cph, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("cannot create AES cipher: %v", err)
	}
	data := []byte("yel=sub&comment=%20like%20a%20pound%20of%20bacon")
	iv := key
	ciph := encryptAesCbc(cph, data, iv)
	inject := make([]byte, len(data))
	copy(inject, ciph[:16])
	copy(inject[32:], ciph[:16])
	clear, ok := decryptAesCbc(cph, inject, iv)
	if ok {
		log.Fatalf("decrypt returned valid ASCII: %s", clear)
	}
	keyGuess := xorBytes(clear[:16], clear[32:])
	fmt.Printf("%s\n", keyGuess)
}
