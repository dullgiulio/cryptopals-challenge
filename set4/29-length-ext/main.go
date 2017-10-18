package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"time"
)

const (
	h0 = 0x67452301
	h1 = 0xEFCDAB89
	h2 = 0x98BADCFE
	h3 = 0x10325476
	h4 = 0xC3D2E1F0

	_K0 = 0x5A827999
	_K1 = 0x6ED9EBA1
	_K2 = 0x8F1BBCDC
	_K3 = 0xCA62C1D6

	chunk = 64
)

var _letters = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")

func sha1block(p []byte, h0, h1, h2, h3, h4 uint32) (uint32, uint32, uint32, uint32, uint32) {
	var w [16]uint32

	for len(p) >= chunk {
		// Can interlace the computation of w with the
		// rounds below if needed for speed.
		for i := 0; i < 16; i++ {
			j := i * 4
			w[i] = uint32(p[j])<<24 | uint32(p[j+1])<<16 | uint32(p[j+2])<<8 | uint32(p[j+3])
		}

		a, b, c, d, e := h0, h1, h2, h3, h4

		// Each of the four 20-iteration rounds
		// differs only in the computation of f and
		// the choice of K (_K0, _K1, etc).
		i := 0
		for ; i < 16; i++ {
			f := b&c | (^b)&d
			a5 := a<<5 | a>>(32-5)
			b30 := b<<30 | b>>(32-30)
			t := a5 + f + e + w[i&0xf] + _K0
			a, b, c, d, e = t, a, b30, c, d
		}
		for ; i < 20; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = tmp<<1 | tmp>>(32-1)

			f := b&c | (^b)&d
			a5 := a<<5 | a>>(32-5)
			b30 := b<<30 | b>>(32-30)
			t := a5 + f + e + w[i&0xf] + _K0
			a, b, c, d, e = t, a, b30, c, d
		}
		for ; i < 40; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = tmp<<1 | tmp>>(32-1)
			f := b ^ c ^ d
			a5 := a<<5 | a>>(32-5)
			b30 := b<<30 | b>>(32-30)
			t := a5 + f + e + w[i&0xf] + _K1
			a, b, c, d, e = t, a, b30, c, d
		}
		for ; i < 60; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = tmp<<1 | tmp>>(32-1)
			f := ((b | c) & d) | (b & c)

			a5 := a<<5 | a>>(32-5)
			b30 := b<<30 | b>>(32-30)
			t := a5 + f + e + w[i&0xf] + _K2
			a, b, c, d, e = t, a, b30, c, d
		}
		for ; i < 80; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = tmp<<1 | tmp>>(32-1)
			f := b ^ c ^ d
			a5 := a<<5 | a>>(32-5)
			b30 := b<<30 | b>>(32-30)
			t := a5 + f + e + w[i&0xf] + _K3
			a, b, c, d, e = t, a, b30, c, d
		}

		h0 += a
		h1 += b
		h2 += c
		h3 += d
		h4 += e

		p = p[chunk:]
	}

	return h0, h1, h2, h3, h4
}

func sha1sum(bs []byte, regs []uint32, ml int) []byte {
	if ml == 0 {
		ml = len(bs)
	}
	tmplen := 0
	if ml%64 < 56 {
		tmplen = 56 - ml%64
	} else {
		tmplen = 64 + 56 - ml%64
	}
	tmp := make([]byte, tmplen+8)
	tmp[0] = 0x80
	// Length in bits
	ln := uint64(ml * 8)
	off := uint(len(tmp) - 8)
	for i := uint(0); i < 8; i++ {
		tmp[off+i] = byte(ln >> (56 - 8*i))
	}
	bs = append(bs, tmp...)
	h := [5]uint32{h0, h1, h2, h3, h4}
	if len(regs) == 5 {
		for i := 0; i < 5; i++ {
			h[i] = regs[i]
		}
	}
	h[0], h[1], h[2], h[3], h[4] = sha1block(bs, h[0], h[1], h[2], h[3], h[4])
	digest := make([]byte, 20)
	for i, s := range h {
		digest[i*4] = byte(s >> 24)
		digest[i*4+1] = byte(s >> 16)
		digest[i*4+2] = byte(s >> 8)
		digest[i*4+3] = byte(s)
	}
	return digest
}

func randSeq(n int, rnd *rand.Rand) []byte {
	bs := make([]byte, n)
	l := len(_letters)
	for i := range bs {
		bs[i] = _letters[rnd.Intn(l)]
	}
	return bs
}

func sha1regs(bs []byte) []uint32 {
	regs := make([]uint32, 5)
	for i := 0; i < 5; i++ {
		if len(bs) == 0 {
			panic("not enough bytes to decode")
		}
		regs[i] = binary.BigEndian.Uint32(bs[:4])
		bs = bs[4:]
	}
	return regs
}

func sha1glue(ml int) []byte {
	tmplen := 0
	if ml%64 < 56 {
		tmplen = 56 - ml%64
	} else {
		tmplen = 64 + 56 - ml%64
	}
	tmp := make([]byte, tmplen+8)
	tmp[0] = 0x80
	// Length in bits
	ln := uint64(ml * 8)
	off := uint(len(tmp) - 8)
	for i := uint(0); i < 8; i++ {
		tmp[off+i] = byte(ln >> (56 - 8*i))
	}
	return tmp
}

type mac []byte

func makeMAC(maxlen int) mac {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	randSeq(rnd.Intn(maxlen), rnd)
	return mac(randSeq(rnd.Intn(maxlen), rnd))
}

func (m mac) digest(msg []byte) []byte {
	return sha1sum(append(m, msg...), nil, 0)
}

func (m mac) valid(digest, msg []byte) bool {
	hash := m.digest(msg)
	return bytes.Compare(digest, hash) == 0
}

// returns the message that validates and it's hash
func keyextend(mac mac, data, digest, suffix []byte, maxlen int) (guesshash, msg []byte) {
	regs := sha1regs(digest)
	for i := 1; i <= maxlen; i++ {
		msg = append(data, sha1glue(i+len(data))...)
		msg = append(msg, suffix...)
		guesshash = sha1sum(suffix, regs, i+len(msg))
		if mac.valid(guesshash, msg) {
			return guesshash, msg
		}
	}
	return nil, nil
}

func main() {
	maxlen := 42
	suffix := []byte(";admin=true")
	data := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")

	mac := makeMAC(maxlen)
	digest := mac.digest(data)
	if !mac.valid(digest, data) {
		log.Fatal("MAC and message not valid")
	}
	guesshash, msg := keyextend(mac, data, digest, suffix, maxlen)
	fmt.Printf("Admin:\t %s %q\n", hex.EncodeToString(guesshash), string(msg))
}
