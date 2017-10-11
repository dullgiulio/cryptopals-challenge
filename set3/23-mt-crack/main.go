package main

import (
	"log"
	"math/rand"
)

const (
	N = 624
	M = 397
	R = 31

	MASK_LOWER = uint32(uint64(1)<<R - 1)
	MASK_UPPER = uint32(uint64(1) << R)
)

type rng struct {
	mt    []uint32
	index int
}

func newRNG(seed uint32) *rng {
	r := &rng{
		mt:    make([]uint32, N),
		index: N,
	}
	r.mt[0] = seed
	for i := uint32(1); i < N; i++ {
		r.mt[i] = 1812433253*(r.mt[i-1]^r.mt[i-1]>>30) + i
	}
	return r
}

func (r *rng) setState(mt []uint32) {
	r.mt = mt
}

func (r *rng) twist() {
	for i := 0; i < N; i++ {
		y := (r.mt[i] & 0x80000000) + (r.mt[(i+1)%N] & 0x7fffffff)
		x := y >> 1
		if y&1 != 0 {
			x ^= 0x9908b0df
		}
		r.mt[i] = r.mt[(i+397)%624] ^ x
	}
	r.index = 0
}

func (r *rng) next() uint32 {
	if r.index >= N {
		r.twist()
	}
	i := r.index
	y := r.mt[i]
	r.index = i + 1
	y = y ^ (y >> 11)
	y = y ^ ((y << 7) & 2636928640)
	y = y ^ ((y << 15) & 4022730752)
	y = y ^ (y >> 18)
	return y
}

func getMSB(x, n uint32) uint32 {
	return (x >> (31 - n)) & 1
}

func setMSB(x, n, b uint32) uint32 {
	return x | (b << (31 - n))
}

func getLSB(x, n uint32) uint32 {
	return (x >> n) & 1
}

func setLSB(x, n, b uint32) uint32 {
	return x | (b << n)
}

func undoLeftShiftXorAnd(y, s, k uint32) uint32 {
	z := uint32(0)
	for i := uint32(0); i < uint32(32); i++ {
		z = setLSB(z, i, getLSB(y, i)^(getLSB(z, i-s)&getLSB(k, i)))
	}
	return z
}

func undoRightShiftXor(y, s uint32) uint32 {
	z := uint32(0)
	for i := uint32(0); i < uint32(32); i++ {
		z = setMSB(z, i, getMSB(y, i)^getMSB(z, i-s))
	}
	return z
}

// note: untemper and undo*() from Fred Akalin (github.com/akalin/cryptopals-python3)
func untemper(y uint32) uint32 {
	y = undoRightShiftXor(y, 18)
	y = undoLeftShiftXorAnd(y, 15, 4022730752)
	y = undoLeftShiftXorAnd(y, 7, 2636928640)
	y = undoRightShiftXor(y, 11)
	return y
}

func main() {
	mt := make([]uint32, N)
	rng := newRNG(uint32(rand.Int31()))
	for i := 0; i < N; i++ {
		n := rng.next()
		mt[i] = untemper(n)
	}
	rng2 := newRNG(0)
	rng2.setState(mt)
	for i := 0; i < 100; i++ {
		a := rng.next()
		b := rng2.next()
		if a != b {
			log.Fatalf("iter %d: %d != %d\n", i, a, b)
		}
	}
}
