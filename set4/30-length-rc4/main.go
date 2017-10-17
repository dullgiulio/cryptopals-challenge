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

// The size of an MD4 checksum in bytes.
const Size = 16

// The blocksize of MD4 in bytes.
const BlockSize = 64

const (
	_Chunk = 64
	_Init0 = 0x67452301
	_Init1 = 0xEFCDAB89
	_Init2 = 0x98BADCFE
	_Init3 = 0x10325476
)

var shift1 = []uint{3, 7, 11, 19}
var shift2 = []uint{3, 5, 9, 13}
var shift3 = []uint{3, 9, 11, 15}

var xIndex2 = []uint{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
var xIndex3 = []uint{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}

var _letters = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")

type md4 struct {
	s   [4]uint32
	x   [_Chunk]byte
	nx  int
	len uint64
}

func newMD4() *md4 {
	d := &md4{}
	d.s[0] = _Init0
	d.s[1] = _Init1
	d.s[2] = _Init2
	d.s[3] = _Init3
	return d
}

func md4block(dig *md4, p []byte) int {
	a := dig.s[0]
	b := dig.s[1]
	c := dig.s[2]
	d := dig.s[3]
	n := 0
	var X [16]uint32
	for len(p) >= _Chunk {
		aa, bb, cc, dd := a, b, c, d

		j := 0
		for i := 0; i < 16; i++ {
			X[i] = uint32(p[j]) | uint32(p[j+1])<<8 | uint32(p[j+2])<<16 | uint32(p[j+3])<<24
			j += 4
		}

		// Round 1.
		for i := uint(0); i < 16; i++ {
			x := i
			s := shift1[i%4]
			f := ((c ^ d) & b) ^ d
			a += f + X[x]
			a = a<<s | a>>(32-s)
			a, b, c, d = d, a, b, c
		}

		// Round 2.
		for i := uint(0); i < 16; i++ {
			x := xIndex2[i]
			s := shift2[i%4]
			g := (b & c) | (b & d) | (c & d)
			a += g + X[x] + 0x5a827999
			a = a<<s | a>>(32-s)
			a, b, c, d = d, a, b, c
		}

		// Round 3.
		for i := uint(0); i < 16; i++ {
			x := xIndex3[i]
			s := shift3[i%4]
			h := b ^ c ^ d
			a += h + X[x] + 0x6ed9eba1
			a = a<<s | a>>(32-s)
			a, b, c, d = d, a, b, c
		}

		a += aa
		b += bb
		c += cc
		d += dd

		p = p[_Chunk:]
		n += _Chunk
	}

	dig.s[0] = a
	dig.s[1] = b
	dig.s[2] = c
	dig.s[3] = d
	return n
}

func md4sum(in []byte, regs []uint32, ln int) []byte {
	if ln == 0 {
		ln = len(in)
	}
	glue := md4glue(ln)
	in = append(in, glue...)
	d := newMD4()
	if len(regs) > 0 {
		for i := 0; i < 4; i++ {
			d.s[i] = regs[i]
		}
	}
	md4block(d, in)
	out := make([]byte, 16)
	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint32(out[i*4:], d.s[i])
	}
	return out
}

func randSeq(n int, rnd *rand.Rand) []byte {
	bs := make([]byte, n)
	l := len(_letters)
	for i := range bs {
		bs[i] = _letters[rnd.Intn(l)]
	}
	return bs
}

func md4regs(bs []byte) []uint32 {
	regs := make([]uint32, 4)
	for i := 0; i < 4; i++ {
		if len(bs) == 0 {
			panic("not enough bytes to decode")
		}
		regs[i] = binary.BigEndian.Uint32(bs[:4])
		bs = bs[4:]
	}
	return regs
}

func md4glue(ml int) []byte {
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
	return md4sum(append(m, msg...), nil, 0)
}

func (m mac) valid(digest, msg []byte) bool {
	hash := m.digest(msg)
	return bytes.Compare(digest, hash) == 0
}

// returns the message that validates and it's hash
func keyextend(mac mac, data, digest, suffix []byte, maxlen int) (guesshash, msg []byte) {
	regs := md4regs(digest)
	for i := 1; i <= maxlen; i++ {
		msg = append(data, md4glue(i+len(data))...)
		msg = append(msg, suffix...)
		guesshash = md4sum(suffix, regs, i+len(msg))
		if mac.valid(guesshash, msg) {
			return guesshash, msg
		}
	}
	return nil, nil
}

func readableString(bs string) string {
	out, err := json.Marshal(bs)
	if err != nil {
		log.Fatalf("cannot pretty print string: %v", err)
	}
	return string(out)
}

func main() {
	maxlen := 42
	suffix := []byte(";admin=true")
	data := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")

	fmt.Printf("%s\n", hex.EncodeToString(md4sum([]byte("abcdefghijklmnopqrstuvwxyz"), nil, 0)))

	mac := makeMAC(maxlen)
	digest := mac.digest(data)
	if !mac.valid(digest, data) {
		log.Fatal("MAC and message not valid")
	}
	guesshash, msg := keyextend(mac, data, digest, suffix, maxlen)
	fmt.Printf("Admin:\t %s %s\n", hex.EncodeToString(guesshash), readableString(string(msg)))
}
