package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"time"
)

func pad(bs []byte, fill byte, sz int) []byte {
	var end int
	for ; end < len(bs); end += sz {
	}
	dst := make([]byte, end, end)
	copy(dst, bs)
	for i := len(bs); i < end; i++ {
		dst[i] = fill
	}
	return dst
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

type cbc struct {
	b  cipher.Block
	iv []byte
}

func newCbc(b cipher.Block, iv []byte) *cbc {
	return &cbc{b, iv}
}

func (c *cbc) BlockSize() int {
	return c.b.BlockSize()
}

func (c *cbc) CryptBlocks(dst, src []byte) {
	blockSize := c.BlockSize()
	blk := c.iv
	for i := 0; i < len(src); i += blockSize {
		r := xorBytes(blk, src[i:i+blockSize])
		c.b.Encrypt(dst[i:], r)
		blk = dst[i : i+blockSize]
	}
}

type ecb struct {
	b cipher.Block
}

func newEcb(b cipher.Block) *ecb {
	return &ecb{b}
}

func (e *ecb) BlockSize() int {
	return e.b.BlockSize()
}

func (e *ecb) CryptBlocks(dst, src []byte) {
	blockSize := e.BlockSize()
	for i := 0; i < len(src); i += blockSize {
		e.b.Encrypt(dst[i:], src[i:])
	}
}

type encrypter struct {
	rnd *mrand.Rand
}

func newEncrypter() *encrypter {
	return &encrypter{
		rnd: mrand.New(mrand.NewSource(time.Now().UnixNano())),
	}
}

func (e *encrypter) encrypt(data []byte) (dst []byte, isEcb bool, err error) {
	isEcb = (e.rnd.Int()%2 == 0)
	padBefore := e.rnd.Intn(6) + 5
	padAfter := e.rnd.Intn(6) + 5
	data = pad(data, byte(0), 16)
	size := len(data) + padBefore + padAfter
	buf := make([]byte, size, size)
	if _, err := io.ReadFull(rand.Reader, buf[0:padBefore]); err != nil {
		return nil, false, fmt.Errorf("cannot pad left: %v", err)
	}
	key := make([]byte, 16, 16)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, false, fmt.Errorf("cannot generate random key: %v", err)
	}
	cph, err := aes.NewCipher(key)
	if err != nil {
		return nil, false, fmt.Errorf("cannot create AES cipher: %v", err)
	}
	var bm cipher.BlockMode
	if isEcb {
		bm = newEcb(cph)
	} else {
		iv := make([]byte, 16, 16)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, false, fmt.Errorf("cannot generate IV: %v", err)
		}
		bm = newCbc(cph, iv)
	}
	bm.CryptBlocks(data, data)
	copy(buf[padBefore:], data)
	if _, err := io.ReadFull(rand.Reader, buf[len(data):]); err != nil {
		return nil, false, fmt.Errorf("cannot pad right: %v", err)
	}
	return buf, isEcb, nil
}

func repeatBlocks(bs []byte, n int) int {
	blks := make([][]byte, 0)
	for i := n; i < len(bs); i += n {
		blks = append(blks, bs[i-n:i])
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

// returns the biggest repeated blocks number trying within a window min, max
func repeatBlocksWindow(bs []byte, min, max, width, nblocks int) int {
	best := 0
	ciphsz := width * nblocks
	for i := min; i <= max; i++ {
		score := repeatBlocks(bs[i:ciphsz+i], width)
		if score > best {
			best = score
		}
	}
	return best
}

func content() []byte {
	return bytes.Repeat([]byte("YELLOW SUBMARINE"), 16)
}

func main() {
	enc := newEncrypter()
	data, isEcb, err := enc.encrypt(content())
	if err != nil {
		log.Fatalf("cannot create encrypted data: %v", err)
	}
	for i := 0; i < 20; i++ {
		score := repeatBlocksWindow(data, 5, 10, 16, 16)
		if score > 0 {
			if !isEcb {
				log.Fatal("EBC NOT guessed")
			}
		} else {
			if isEcb {
				log.Fatal("ECB NOT guessed: no repeating blocks")
			}
		}
	}
}
