package main

import "testing"

func TestValidatePkcs7(t *testing.T) {
	data := []struct {
		bs       []byte
		expected bool
	}{
		{[]byte("0123456789\x06\x06\x06\x06\x06\x06"), true},
		{[]byte("0123456789\x06\x06\x00\x00\x00\x00"), false},
		{[]byte("0123456789\x06\x06\x00\x00\x00\x02"), false},
	}
	for i := range data {
		if res := validPkcs7(data[i].bs); res != data[i].expected {
			t.Fatalf("%v = %v (expected %v)\n", data[i].bs, res, data[i].expected)
		}
	}
}
