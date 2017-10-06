package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"sort"
)

const secretContent = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

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
	blocksize := e.BlockSize()
	for i := 0; i < len(src); i += blocksize {
		e.b.Encrypt(dst[i:], src[i:])
	}
}

type hash struct {
	keys [][]byte
	vals []byte
}

func newHash() *hash {
	return &hash{
		keys: make([][]byte, 0),
		vals: make([]byte, 0),
	}
}

func (h *hash) sort() {
	sort.Sort(h)
}

func (h *hash) get(k []byte) (byte, bool) {
	n := sort.Search(len(h.keys), func(i int) bool { return bytes.Compare(h.keys[i], k) <= 0 })
	if n < len(h.keys) && bytes.Compare(h.keys[n], k) == 0 {
		return h.vals[n], true
	}
	return byte(0), false
}

func (h *hash) put(k []byte, v byte) {
	h.keys = append(h.keys, k)
	h.vals = append(h.vals, v)
}

func (h *hash) Len() int {
	return len(h.keys)
}

func (h *hash) Less(i, j int) bool {
	return bytes.Compare(h.keys[i], h.keys[j]) >= 0
}

func (h *hash) Swap(i, j int) {
	h.keys[i], h.keys[j] = h.keys[j], h.keys[i]
	h.vals[i], h.vals[j] = h.vals[j], h.vals[i]
}

type encrypter struct {
	key    []byte
	secret []byte
	bm     cipher.BlockMode
}

func newEncrypter() *encrypter {
	secret, err := base64.StdEncoding.DecodeString(secretContent)
	if err != nil {
		log.Fatalf("cannot base64 decode secret content: %v", err)
	}
	e := &encrypter{
		key:    make([]byte, 16),
		secret: secret,
	}
	if _, err := io.ReadFull(rand.Reader, e.key); err != nil {
		log.Fatalf("cannot generate random key: %v", err)
	}
	cph, err := aes.NewCipher(e.key)
	if err != nil {
		log.Fatalf("cannot create AES cipher: %v", err)
	}
	e.bm = newEcb(cph)
	return e
}

func (e *encrypter) encrypt(prefix []byte) []byte {
	blocksize := 16
	size := len(prefix) + len(e.secret)
	size = size + blocksize - (size % blocksize)
	// padding is done by just allocating zeroes
	buf := make([]byte, size)
	copy(buf, prefix)
	copy(buf[len(prefix):], e.secret)
	e.bm.CryptBlocks(buf, buf)
	return buf
}

func guessSizes(e *encrypter) (secret, block int) {
	var n, nblks, first int
	for {
		prefix := make([]byte, n)
		for i := 0; i < n; i++ {
			prefix[i] = 'A'
		}
		res := e.encrypt(prefix)
		if nblks != 0 && len(res) > nblks {
			return nblks - n, len(res) - first
		}
		nblks = len(res)
		if first == 0 {
			first = nblks
		}
		n++
	}
}

func fillHash(h *hash, e *encrypter, prefix []byte) {
	end := len(prefix)
	for i := byte(0); i < byte(255); i++ {
		prefix[end-1] = i
		res := e.encrypt(prefix)
		h.put(res[0:end], i)
	}
	h.sort()
}

func makePrefix(secret []byte, blocksize int) []byte {
	lpad := blocksize - (len(secret) % blocksize) - 1
	prefix := make([]byte, len(secret)+lpad+1)
	copy(prefix[lpad:], secret)
	return prefix
}

func decrypt(e *encrypter, blocksize, slen int) []byte {
	secret := make([]byte, 0)
	for i := 0; i < slen; i++ {
		prefix := makePrefix(secret, blocksize)
		h := newHash()
		fillHash(h, e, prefix)
		res := e.encrypt(prefix[:len(prefix)-i-1])
		b, ok := h.get(res[:len(prefix)])
		if !ok {
			log.Fatalf("block %v not in hashmap", res[0:len(prefix)-i-1])
		}
		secret = append(secret, b)
	}
	return secret
}

func main() {
	enc := newEncrypter()
	slen, blksz := guessSizes(enc)
	// fmt.Printf("secret len = %d, blocksize = %d\n", slen, blksz)
	secret := decrypt(enc, blksz, slen)
	fmt.Printf("%s\n", string(secret))
}
