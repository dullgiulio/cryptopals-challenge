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

func decryptValid(bs []byte, dec *cbcDec) bool {
	dst := make([]byte, len(bs))
	dec.CryptBlocks(dst, bs)
	return validPkcs7(dst[len(dst)-16:])
}

func guessCBC(b1, b2, iv []byte, dec *cbcDec) []byte {
	buf := make([]byte, 32)
    guessed := 0
    guess := make([]byte, 16)
	plain := make([]byte, 16)
	copy(buf[16:], b2)
	for pad := byte(1); pad <= byte(16); pad++ {
		for b := 1; b <= 255; b++ {
			buf[15-guessed] = byte(b)
            for i := 0; i < guessed; i++ {
				buf[15-i] = guess[15-i] ^ pad
			}
			for k := 0; k < 15-len(plain); k++ {
				buf[k] = b1[k]
			}
			if decryptValid(buf, dec) {
                guess[15-guessed] = byte(b) ^ pad
                plain[15-guessed] = b1[15-guessed] ^ byte(b) ^ pad
				guessed++
                break
			}
		}
	}
	return plain
}

func testPkcs7() {
	data := []struct {
		bs       []byte
		expected bool
	}{
		{[]byte("0123456789\x06\x06\x06\x06\x06\x06"), true},
		{[]byte("0123456789\x06\x06\x00\x00\x00\x00"), true},
		{[]byte("0123456789\x06\x06\x00\x00\x00\x02"), false},
	}
	for i := range data {
		if res := validPkcs7(data[i].bs); res != data[i].expected {
			fmt.Printf("%v = %v (expected %v)\n", data[i].bs, res, data[i].expected)
		}
	}
}

func main() {
	// testPkcs7()
	buf := []byte("YELLOW SUBMARINEYELLOW SUBMARINE")
	cph, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	if err != nil {
		log.Fatalf("cannot create AES cipher: %v", err)
	}
	iv := make([]byte, 16, 16)
	secret := encryptAesCbc(cph, buf, iv)
	dec := newCbcDec(cph, iv)
	plain := guessCBC(secret[:16], secret[16:], iv, dec)
	fmt.Printf("%s\n", plain)
}
