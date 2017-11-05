package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
)

const px = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"

func hash(d []byte) []byte {
	b := sha1.Sum(d)
	return b[:]
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

type dh struct {
	r    *big.Int
	p    *big.Int
	g    *big.Int
	exp  *big.Int
	A, B *big.Int
	pga  bool
	key  []byte
}

func newDH(r int64) *dh {
	bs, _ := hex.DecodeString(px)
	p := &big.Int{}
	p.SetBytes(bs)
	dh := &dh{
		r: big.NewInt(r),
		p: p,
		g: big.NewInt(2),
	}
	dh.exp = &big.Int{}
	dh.exp.Mod(dh.r, dh.p)
	return dh
}

func (d *dh) pgA() dhmsg {
	d.pga = true
	d.A = &big.Int{}
	d.A.Exp(d.g, d.exp, d.p)
	return &dhPGA{d.p, d.g, d.A}
}

func (d *dh) setPGA(m *dhPGA) {
	d.p = m.p
	d.g = m.g
	d.A = m.A
}

func (d *dh) getB() dhmsg {
	d.B = &big.Int{}
	d.B.Exp(d.g, d.exp, d.p)
	return &dhB{d.B}
}

func (d *dh) setB(m *dhB) {
	d.B = m.B
}

func (d *dh) compute() {
	var s *big.Int
	if !d.pga {
		s = d.A
	} else {
		s = d.B
	}
	s.Exp(s, d.exp, d.p)
	d.key = s.Bytes()
	d.key = hash(d.key)[:16]
}

type dhmsg interface {
	apply(*dh)
}

type dhPGA struct {
	p, g, A *big.Int
}

func (m *dhPGA) apply(d *dh) {
	d.setPGA(m)
}

type dhB struct {
	B *big.Int
}

func (m *dhB) apply(d *dh) {
	d.setB(m)
}

func (d *dh) encrypt(data, iv []byte) []byte {
	cph, err := aes.NewCipher(d.key)
	if err != nil {
		log.Fatalf("cannot create AES cipher: %v", err)
	}
	return encryptAesCbc(cph, data, iv)
}

func (d *dh) decrypt(data, iv []byte) []byte {
	cph, err := aes.NewCipher(d.key)
	if err != nil {
		log.Fatalf("cannot create AES cipher: %v", err)
	}
	return decryptAesCbc(cph, data, iv)
}

func direct() {
	alice := newDH(mrand.Int63())
	bob := newDH(mrand.Int63())

	m := alice.pgA()
	m.apply(bob)

	m = bob.getB()
	m.apply(alice)

	alice.compute()
	bob.compute()

	iv := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Fatalf("cannot read random IV: %v", err)
	}

	enc := alice.encrypt([]byte("YELLOW SUBMARINE"), iv)
	plain := bob.decrypt(enc, iv)

	fmt.Printf("%s\n", plain)
}

func intercepted() {
	alice := newDH(mrand.Int63())
	bob := newDH(mrand.Int63())
	eve := newDH(mrand.Int63())

	m := alice.pgA()
	m.apply(eve)

	m = eve.pgA()
	if m1, ok := m.(*dhPGA); ok {
		m1.A = m1.p
		m = m1
	}
	m.apply(bob)

	m = bob.getB()
	m.apply(eve)

	if m1, ok := m.(*dhB); ok {
		m1.B = eve.p
		m = m1
	}
	m.apply(alice)

	alice.compute()
	bob.compute()

	eve.key = hash([]byte(""))[:16]

	iv := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Fatalf("cannot read random IV: %v", err)
	}

	enc := alice.encrypt([]byte("YELLOW SUBMARINE"), iv)
	plain := eve.decrypt(enc, iv)
	fmt.Printf("%s\n", plain)
	enc = eve.encrypt(plain, iv)
	plain = bob.decrypt(enc, iv)

	fmt.Printf("%s\n", plain)
}

func main() {
	direct()
	intercepted()
}
