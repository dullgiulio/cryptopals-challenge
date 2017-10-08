package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
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

func encryptAesCtr(cph cipher.Block, nonce uint64, data []byte) []byte {
	dst := make([]byte, len(data))
	newCtrEnc(cph, nonce).CryptBlocks(dst, data)
	return dst
}

func likely(c byte) int {
	if c >= byte('0') && c <= byte('9') {
		return 2
	}
	if c == byte('\n') {
		return 2
	}
	if c == byte(' ') || c == byte('/') || c == byte('\'') {
		return 10
	}
	if c >= byte('A') && c <= byte('Z') {
		return 10
	}
	if c >= byte('a') && c <= byte('z') {
		return 10
	}
	return 0
}

func xorBlocks(lines [][]byte, key []byte) [][]byte {
	for i := range lines {
		if len(lines[i]) > len(key) {
			lines[i] = lines[i][:len(key)]
		}
		xorBytes(lines[i], lines[i], key)
	}
	return lines
}

func base64lines(fname string) ([][]byte, error) {
	r, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	lines := make([][]byte, 0)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line, err := base64.StdEncoding.DecodeString(sc.Text())
		if err != nil {
			return nil, err
		}
		lines = append(lines, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func guessXkey(lines [][]byte, size int) []byte {
	key := make([]byte, size)
	for i := 0; i < size; i++ {
		var (
			maxScore int
			maxVal   byte
		)
		for b := byte(0); b < byte(255); b++ {
			var score int
			for l := range lines {
				score = score + likely(lines[l][i]^b)
			}
			if score > maxScore {
				maxScore = score
				maxVal = b
			}
		}
		key[i] = maxVal
	}
	return key
}

func main() {
	flag.Parse()
	fname := flag.Arg(0)
	if fname == "" {
		log.Fatal("first argument is the file of encoded secrets")
	}
	lines, err := base64lines(fname)
	if err != nil {
		log.Fatalf("cannot read encoded secrets: %v", err)
	}
	nonce := uint64(0)
	key := []byte("YELLOW SUBMARINE")
	cph, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("cannot create AES cipher: %v", err)
	}
	proof := encryptAesCtr(cph, nonce, key)
	xorBytes(proof, key, proof)
	var shortest int
	for i := range lines {
		lines[i] = encryptAesCtr(cph, nonce, lines[i])
		if shortest == 0 || shortest > len(lines[i]) {
			shortest = len(lines[i])
		}
	}
	xkey := guessXkey(lines, shortest)
	for i := range lines {
		xorBytes(lines[i], xkey, lines[i])
		fmt.Printf("%s\n", lines[i][:shortest])
	}
}
