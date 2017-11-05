package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
)

const px = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"

type dh struct {
	p *big.Int
	g *big.Int
}

func newDH() *dh {
	bs, _ := hex.DecodeString(px)
	p := &big.Int{}
	p.SetBytes(bs)
	return &dh{
		p: p,
		g: big.NewInt(2),
	}
}

func (d *dh) comp(r1, r2 *big.Int) bool {
	a := &big.Int{}
	a.Mod(r1, d.p)
	A := &big.Int{}
	A.Exp(d.g, a, d.p)
	b := &big.Int{}
	b.Mod(r2, d.p)
	B := &big.Int{}
	B.Exp(d.g, b, d.p)
	s1 := &big.Int{}
	s1.Exp(B, a, d.p)
	s2 := &big.Int{}
	s2.Exp(A, b, d.p)
	return s1.Cmp(s2) == 0
}

func main() {
	dh := newDH()
	fmt.Printf("%v\n", dh.comp(big.NewInt(rand.Int63()), big.NewInt(rand.Int63())))
}
