package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
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

type editor struct {
	cph cipher.Block
}

func newEditor() *editor {
	key := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		log.Fatalf("cannot generate random key: %v", err)
	}
	cph, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("cannot create AES cipher: %v", err)
	}
	return &editor{cph}
}

func (e *editor) edit(ctxt, newtxt []byte, offset int) []byte {
	if offset > len(ctxt) {
		return nil
	}
	enc := newCtrEnc(e.cph, 0)
	clear := make([]byte, len(ctxt))
	enc.CryptBlocks(clear, ctxt)
	dst := make([]byte, len(ctxt)+len(newtxt))
	copy(dst, clear[:offset])
	copy(dst[offset:], newtxt)
	copy(dst[offset+len(newtxt):], clear[offset:])
	cdst := make([]byte, len(dst))
	enc = newCtrEnc(e.cph, 0)
	enc.CryptBlocks(cdst, dst)
	return cdst
}

func main() {
	data := []byte("YELLOW-SUMMARINEEYLLOV SUBMARIEN")
	e := newEditor()
	c0 := e.edit(nil, data, 0)
	data1 := make([]byte, len(c0)) // just zeroes
	c := e.edit(c0, data1, 0)
	key := make([]byte, len(data1))
	xorBytes(key, c[:len(data1)], data1)
	clear := make([]byte, len(c0))
	xorBytes(clear, c0, key)
	fmt.Printf("%s\n", clear)
}
