package mux

import (
	"bytes"
	"encoding/binary"

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

type assembler struct {
	InterestSender

	content []byte
	offset  int
	next    ndn.Name
}

func (a *assembler) SendData(d *ndn.Data) {
	a.content = append(a.content, d.Content...)
	a.next.Components = nil
	if len(d.Name.Components) > 0 &&
		!bytes.Equal(d.Name.Components[len(d.Name.Components)-1], d.MetaInfo.FinalBlockID.Component) {
		a.offset += len(d.Content)
		a.next.Components = make([]ndn.Component, len(d.Name.Components))
		copy(a.next.Components, d.Name.Components[:len(d.Name.Components)-1])
		segNum := make([]byte, 8)
		binary.BigEndian.PutUint64(segNum, uint64(a.offset))
		a.next.Components[len(a.next.Components)-1] = segNum
	}
}

func (f *Fetcher) Fetch(iw InterestSender, name ndn.Name, fw ...Fetchware) []byte {
	a := &assembler{
		InterestSender: iw,
		next:           name,
	}
	h := Handler(HandlerFunc(func(w Sender, i *ndn.Interest) {
		d, ok := <-iw.SendInterest(i)
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
	offset := -1
	for a.next.Components != nil {
		if offset >= a.offset {
			return nil
		}
		offset = a.offset
		h.ServeNDN(a, &ndn.Interest{Name: a.next})
	}
	t := f.fw
	for _, m := range fw {
		t = m(t)
	}
	return t.Transform(a.content)
}
