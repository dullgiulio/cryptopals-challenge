package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
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

func (c *cbcDec) setIV(iv []byte) {
	c.iv = iv
}

func encryptAesCbc(cph cipher.Block, data, iv []byte) []byte {
	dst := make([]byte, len(data), len(data))
	newCbcEnc(cph, iv).CryptBlocks(dst, data)
	return dst
}

func validPkcs7(bs []byte) bool {
	if len(bs) > 16 {
		panic("length of given block too big")
	}
	b := bs[15]
	if b > byte(16) || b == 0 {
		return false
	}
	for i := byte(16) - b; i < byte(16); i++ {
		if bs[i] != b {
			return false
		}
	}
	return true
}

type cbcOracle struct {
	dec *cbcDec
}

func newOracle(dec *cbcDec) *cbcOracle {
	return &cbcOracle{dec: dec}
}

func (o *cbcOracle) decrypt(bs []byte) []byte {
	dst := make([]byte, len(bs))
	o.dec.CryptBlocks(dst, bs)
	return dst
}

func (o *cbcOracle) validPkcs7(bs []byte) bool {
	return validPkcs7(bs[len(bs)-16:])
}

func (o *cbcOracle) valid(bs, iv []byte) bool {
	o.dec.setIV(iv)
	return o.validPkcs7(o.decrypt(bs))
}

func bruteLastBlock(bs, iv []byte, o *cbcOracle) []byte {
	var (
		guessed int
		b1, b2  []byte
	)
	buf := make([]byte, 32)
	guess := make([]byte, 16)
	plain := make([]byte, 16)
	if len(bs) >= 32 {
		b1 = bs[len(bs)-32 : len(bs)-16]
		b2 = bs[len(bs)-16:]
	} else {
		b1 = iv
		b2 = bs
	}
	copy(buf[16:], b2)
	for pad := byte(1); pad <= byte(16); pad++ {
		for b := byte(1); b <= byte(255); b++ {
			buf[15-guessed] = b
			for i := 0; i < guessed; i++ {
				buf[15-i] = guess[15-i] ^ pad
			}
			for k := 0; k < 15-len(plain); k++ {
				buf[k] = b1[k]
			}
			if o.valid(buf, iv) {
				guess[15-guessed] = b ^ pad
				plain[15-guessed] = b1[15-guessed] ^ b ^ pad
				guessed++
				break
			}
		}
	}
	return plain
}

func brute(bs, iv []byte, o *cbcOracle) []byte {
	var plain []byte
	for len(bs) > 0 {
		plain = append(bruteLastBlock(bs, iv, o), plain...)
		bs = bs[:len(bs)-16]
	}
	return plain
}

func main() {
	// TODO: select from list of base64 strings
	buf := []byte("YELLOW0SUBMARINEYELLOW1SUBMARINE")
	key := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		log.Fatalf("cannot initialize random AES-128 key: %v", err)
	}
	iv := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Fatalf("cannot initialize IV: %v", err)
	}
	cph, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("cannot create AES cipher: %v", err)
	}
	secret := encryptAesCbc(cph, buf, iv)
	oracle := newOracle(newCbcDec(cph, iv))
	plain := brute(secret, iv, oracle)
	// TODO: strip pkcs7 padding from plain
	fmt.Printf("'%s'\n", plain)
}
