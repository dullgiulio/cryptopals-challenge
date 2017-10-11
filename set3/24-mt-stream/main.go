package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
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

func writeCipher(rng *rng, buf []byte) {
	for i := 0; i < len(buf)/4; i += 4 {
		binary.LittleEndian.PutUint32(buf[i:], rng.next())
	}
	n := len(buf) % 4
	if len(buf)%4 != 0 {
		bs := make([]byte, 4)
		binary.LittleEndian.PutUint32(bs, rng.next())
		copy(buf[len(buf)-n:], bs[:n])
	}
}

func xorBytes(dst, a, b []byte) {
	var j int
	for i := 0; i < len(a); i++ {
		dst[i] = a[i] ^ b[j]
		j = (j + 1) % len(b)
	}
}

type ctrRng struct {
	rng *rng
}

func newRngEnc(key uint32) *ctrRng {
	return &ctrRng{
		rng: newRNG(key),
	}
}

func (c *ctrRng) crypt(dst, src []byte) {
	buf := make([]byte, len(src))
	writeCipher(c.rng, buf)
	xorBytes(dst, src, buf)
}

func trytime(expected, ctxt []byte, tmin, tmax time.Time) time.Time {
	if len(expected) != len(ctxt) {
		return time.Time{}
	}
	buf := make([]byte, len(ctxt))
	for t := tmin.Unix(); t <= tmax.Unix(); t++ {
		newRngEnc(uint32(t)).crypt(buf, ctxt)
		if bytes.Compare(buf, expected) == 0 {
			return time.Unix(t, 0)
		}
	}
	return time.Time{}
}

func main() {
	mail := []byte("test@example.com")
	t := uint32(time.Now().Unix())
	token := make([]byte, len(mail))
	newRngEnc(t).crypt(token, mail)
	tm := time.Now()
	tm = trytime(mail, token, tm.Add(-1*time.Minute), tm)
	fmt.Printf("%s\n", tm)
}
