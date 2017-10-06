package main

import "fmt"

func pad(bs []byte, fill byte, sz int) []byte {
	var end int
	n := sz - (len(bs) % sz)
	end := n + len(bs)
	dst := make([]byte, end, end)
	copy(dst, bs)
	for i := len(bs); i < end; i++ {
		dst[i] = fill
	}
	return dst
}

func main() {
	fmt.Printf("%+v\n", pad([]byte("YELLOW SUBMARINE"), byte(4), 20))
}
