package mux

import (
	"bytes"

	"github.com/go-ndn/ndn"
)

type Verifier interface {
	Verify(*ndn.Data) bool
}

type VerifierFunc func(*ndn.Data) bool

func (f VerifierFunc) Verify(d *ndn.Data) bool {
	return f(d)
}

type Transformer interface {
	Transform([]byte) []byte
}

type TransformerFunc func([]byte) []byte

func (f TransformerFunc) Transform(b []byte) []byte {
	return f(b)
}

type Fetchware func(Transformer) Transformer

type Fetcher struct {
	fw Transformer
	mw []Middleware
	v  []Verifier
}

func NewFetcher() *Fetcher {
	return &Fetcher{
		fw: TransformerFunc(func(b []byte) []byte { return b }),
		v:  []Verifier{VerifierFunc(sha256Verifier)},
	}
}

func (f *Fetcher) Use(m Middleware) {
	f.mw = append(f.mw, m)
}

func (f *Fetcher) UseFetchware(m Fetchware) {
	f.fw = m(f.fw)
}

func (f *Fetcher) UseVerifier(v Verifier) {
	f.v = append(f.v, v)
}

func sha256Verifier(d *ndn.Data) bool {
	switch d.SignatureInfo.SignatureType {
	case ndn.SignatureTypeDigestSHA256:
		digest, err := ndn.NewSHA256(d)
		if err != nil {
			return false
		}
		return bytes.Equal(digest, d.SignatureValue)
	}
	return true
}

func (f *Fetcher) Fetch(fetcher Sender, name ndn.Name, fw ...Fetchware) []byte {
	h := Handler(HandlerFunc(func(w Sender, i *ndn.Interest) {
		d, ok := <-fetcher.SendInterest(i)
		if !ok {
			return
		}
		for _, v := range f.v {
			if !v.Verify(d) {
				return
			}
		}
		w.SendData(d)
	}))
	for _, m := range f.mw {
		h = m(h)
	}
	ch := make(chan *ndn.Data, 1)
	Assembler(h).ServeNDN(&assembler{Sender: fetcher, ch: ch}, &ndn.Interest{Name: name})
	select {
	case d := <-ch:
		t := f.fw
		for _, m := range fw {
			t = m(t)
		}
		return t.Transform(d.Content)
	default:
		return nil
	}
}
