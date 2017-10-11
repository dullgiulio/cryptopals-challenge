package main

import (
	"bytes"
	"testing"
)

func TestRng(t *testing.T) {
	c := newRngEnc(42)
	plain := []byte("Hello world, some crypto test")
	ctxt := make([]byte, len(plain))
	c.crypt(ctxt, plain)
	c = newRngEnc(42)
	ptxt := make([]byte, len(plain))
	c.crypt(ptxt, ctxt)
	if bytes.Compare(ptxt, plain) != 0 {
		t.Fatalf("'%s' != '%s'\n", ptxt, plain)
	}
}
