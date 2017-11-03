package main

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"
)

const blocksize = 64

func hash(d []byte) []byte {
	b := sha1.Sum(d)
	return b[:]
}

func fixKey(key []byte) []byte {
	if len(key) > blocksize {
		return hash(key)
	}
	if len(key) < blocksize {
		nkey := make([]byte, blocksize)
		copy(nkey, key)
		return nkey
	}
	return key
}

func hmac(data, key []byte) []byte {
	key = fixKey(key)
	opad := make([]byte, blocksize)
	for i := range opad {
		opad[i] = 0x5c ^ key[i]
	}
	ipad := make([]byte, blocksize)
	for i := range ipad {
		ipad[i] = 0x36 ^ key[i]
	}
	return hash(append(opad, hash(append(ipad, data...))...))
}

func insecureCompare(a, b []byte, d time.Duration) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
		time.Sleep(d)
	}
	return true
}

type validator []byte

func (v validator) valid(data, sign []byte) bool {
	return insecureCompare(hmac(data, v), sign, 5*time.Millisecond)
}

func (v validator) serve(listen string) {
	http.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		params := r.URL.Query()
		file, ok := params["file"]
		if !ok || file[0] == "" {
			http.Error(w, "Need 'file' GET parameter", http.StatusBadRequest)
			return
		}
		signature, ok := params["signature"]
		if !ok || signature[0] == "" {
			http.Error(w, "Need 'signature' GET parameter", http.StatusBadRequest)
			return
		}
		hs, err := hex.DecodeString(signature[0])
		if err != nil {
			http.Error(w, "Invalid 'signature' GET parameter", http.StatusBadRequest)
			return
		}
		if !v.valid([]byte(file[0]), hs) {
			http.Error(w, "Invalid file hash", http.StatusForbidden)
		}
		fmt.Fprintf(w, "OK File found")
	})
	go log.Fatal(http.ListenAndServe(listen, nil))
}

type client struct {
	endp string
	hc   *http.Client
}

func newClient(endp string) *client {
	return &client{
		endp: endp,
		hc:   &http.Client{},
	}
}

func (c *client) try(fname, hash []byte) bool {
	addr := fmt.Sprintf("http://%s/test?file=%s&signature=%x", c.endp, url.QueryEscape(string(fname)), hash)
	resp, err := c.hc.Get(fmt.Sprintf(addr))
	if err != nil {
		log.Fatalf("HTTP client error: %v", err)
	}
	io.Copy(ioutil.Discard, resp.Body)
	if resp.StatusCode == http.StatusOK {
		return true
	}
	if resp.StatusCode != http.StatusForbidden {
		log.Fatal("HTTP client error: %s", resp.Status)
	}
	return false
}

func (c *client) findHash(fname []byte) []byte {
	hs := make([]byte, 20)
	for p := 0; p < 20; p++ {
		var (
			b byte
			d time.Duration
		)
		for i := 0; i < 256; i++ {
			hs[p] = byte(i)
			t := time.Now()
			if c.try(fname, hs) {
				return hs
			}
			diff := time.Now().Sub(t)
			if diff > d {
				b = byte(i)
				d = diff
			}
		}
		hs[p] = b
	}
	return nil
}

func main() {
	fname := flag.String("file", "somefile.jpg", "name of the file to generate hash for")
	host := flag.String("listen", "localhost:9000", "hostname:port to work on")
	flag.Parse()
	key := make([]byte, 16)
	if _, err := rand.Reader.Read(key); err != nil {
		log.Fatal("cannot generate random key: %v", err)
	}
	v := validator(key)
	go v.serve(*host)
	c := newClient(*host)
	hs := c.findHash([]byte(*fname))
	if hs == nil {
		log.Fatal("bad luck, didn't find any hash")
	}
	fmt.Printf("%s - %x\n", *fname, hs)
}
