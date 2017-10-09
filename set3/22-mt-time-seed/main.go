package main

import (
	"fmt"
	"math/rand"
	"time"
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

func guessSeed(n uint32) uint32 {
	t := uint32(time.Now().Unix())
	for i := uint32(39); i < uint32(1010); i++ {
		rng := newRNG(t - i)
		if rng.next() == n {
			return t - i
		}
	}
	return 0
}

func main() {
	// no, I am not using my rng when I can avoid it
	trand := rand.New(rand.NewSource(time.Now().UnixNano()))
	min, max := int32(40), int32(1000)
	for {
		sleep := time.Duration(trand.Int31n(max-min)+min) * time.Second
		time.Sleep(sleep)
		seed := uint32(time.Now().Unix())
		rng := newRNG(seed)
		sleep = time.Duration(trand.Int31n(max-min)+min) * time.Second
		time.Sleep(sleep)
		n := rng.next()
		guess := guessSeed(n)
		if guess == seed {
			fmt.Printf("Guessed %d\n", guess)
			break
		}
	}
}
