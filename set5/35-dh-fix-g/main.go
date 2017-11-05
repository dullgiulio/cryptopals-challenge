package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"math/big"
	mrand "math/rand"
)

const px = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"

func hash(d []byte) []byte {
	b := sha1.Sum(d)
	return b[:]
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

func (d *dh) pg() dhmsg {
	d.pga = true
	return &dhPG{d.p, d.g}
}

func (d *dh) getA() dhmsg {
	d.A = &big.Int{}
	d.A.Exp(d.g, d.exp, d.p)
	return &dhA{d.A}
}

func (d *dh) setPG(m *dhPG) {
	d.p = m.p
	d.g = m.g
}

func (d *dh) setA(m *dhA) {
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

type dhPG struct {
	p, g *big.Int
}

func (m *dhPG) apply(d *dh) {
	d.setPG(m)
}

type dhA struct {
	A *big.Int
}

func (m *dhA) apply(d *dh) {
	d.setA(m)
}

type dhB struct {
	B *big.Int
}

func (m *dhB) apply(d *dh) {
	d.setB(m)
}

func tamperG(g, exp *big.Int) {
	alice := newDH(mrand.Int63())
	bob := newDH(mrand.Int63())

	m := alice.pg()
	if m1, ok := m.(*dhPG); ok {
		m1.g = g
		m = m1
	}
	m.apply(bob)

	m = alice.getA()
	m.apply(bob)

	m = bob.getB()
	m.apply(alice)

	alice.compute()
	bob.compute()

	// guess bob's side
	s := &big.Int{}
	s.Exp(alice.A, exp, alice.p)
	key := s.Bytes()
	keyB := hash(key)[:16]

	// guess alice's side
	s.Exp(bob.B, exp, bob.p)
	key = s.Bytes()
	keyA := hash(key)[:16]

	if bytes.Compare(alice.key, keyA) == 0 {
		fmt.Printf("Can decrypt A -> B\n")
	} else {
		fmt.Printf("Cannot decrypt A -> B\n")
	}
	if bytes.Compare(bob.key, keyB) == 0 {
		fmt.Printf("Can decrypt B -> A\n")
	} else {
		fmt.Printf("Cannot decrypt B -> A\n")
	}
	fmt.Println("")
}

func main() {
	bs, _ := hex.DecodeString(px)
	p := &big.Int{}
	p.SetBytes(bs)
	p1 := &big.Int{}
	p1.Add(p, big.NewInt(-1))

	fmt.Printf("g = 1:\n")
	tamperG(big.NewInt(1), big.NewInt(1))
	fmt.Printf("g = p:\n")
	tamperG(p, p1)
	fmt.Printf("g = p-1:\n")
	tamperG(p1, big.NewInt(1))
}
