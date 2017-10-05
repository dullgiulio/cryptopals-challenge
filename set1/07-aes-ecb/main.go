package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

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
		e.b.Decrypt(dst[i:], src[i:])
	}
}

func decryptAesEcb(key, data []byte) ([]byte, error) {
	cph, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cannot create AES cipher: %v", err)
	}
	dst := make([]byte, len(data), len(data))
	newEcb(cph).CryptBlocks(dst, data)
	return dst, nil
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
	clear, err := decryptAesEcb([]byte("YELLOW SUBMARINE"), data)
	if err != nil {
		log.Fatalf("cannot decrypt: %v", err)
	}
	os.Stdout.Write(clear)
}
