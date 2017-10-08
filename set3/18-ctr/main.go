package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
)

func writeCRT(nonce, cnt uint64, buf []byte) {
	binary.LittleEndian.PutUint64(buf, nonce)
	binary.LittleEndian.PutUint64(buf[8:], cnt)
}

func xorBytes(dst, a, b []byte) {
	var j int
	for i := 0; i < len(a); i++ {
		dst[i] = a[i] ^ b[j]
		j = (j + 1) % len(b)
	}
}

type ctrEnc struct {
	b     cipher.Block
	nonce uint64
	cnt   uint64
	buf   []byte
}

func newCtrEnc(b cipher.Block, nonce uint64) *ctrEnc {
	return &ctrEnc{
		b:     b,
		nonce: nonce,
		buf:   make([]byte, 16),
	}
}

func (c *ctrEnc) BlockSize() int {
	return c.b.BlockSize()
}

func (c *ctrEnc) writeCtr(buf []byte, nonce, cnt uint64) {
	binary.LittleEndian.PutUint64(buf, nonce)
	binary.LittleEndian.PutUint64(buf[8:], cnt)
}

func (c *ctrEnc) CryptBlocks(dst, src []byte) {
	blockSize := c.BlockSize()
	for i := 0; i < len(src); i += blockSize {
		c.writeCtr(c.buf, c.nonce, c.cnt)
		c.b.Encrypt(c.buf, c.buf)
		end := i + blockSize
		if end > len(src) {
			end = len(src)
		}
		xorBytes(dst[i:], src[i:end], c.buf)
		c.cnt++
	}
}

func decryptAesCtr(cph cipher.Block, nonce uint64, data []byte) []byte {
	dst := make([]byte, len(data))
	newCtrEnc(cph, nonce).CryptBlocks(dst, data)
	return dst
}

func main() {
	nonce := uint64(0)
	key := []byte("YELLOW SUBMARINE")
	secret, err := base64.StdEncoding.DecodeString("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	if err != nil {
		log.Fatalf("cannot decode secret: %v", err)
	}
	cph, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("cannot create AES cipher: %v", err)
	}
	plain := decryptAesCtr(cph, nonce, secret)
	fmt.Printf("%s\n", plain)
}
