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

type FetcherMiddleware func(Transformer) Transformer

type Fetcher struct {
	mw Transformer
	v  []Verifier
}

func NewFetcher() *Fetcher {
	return &Fetcher{
		mw: TransformerFunc(func(b []byte) []byte { return b }),
		v:  []Verifier{VerifierFunc(sha256Verifier)},
	}
}

func (f *Fetcher) Use(m FetcherMiddleware) {
	f.mw = m(f.mw)
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

func (f *Fetcher) Fetch(w InterestSender, name ndn.Name, mw ...FetcherMiddleware) []byte {
	var content []byte
	var start int
	comp := name.Components
	for {
		d, ok := <-w.SendInterest(&ndn.Interest{
			Name: ndn.Name{Components: comp},
		})
		if !ok {
			return nil
		}
		for _, v := range f.v {
			if !v.Verify(d) {
				return nil
			}
		}
		content = append(content, d.Content...)
		if len(d.Name.Components) > 0 &&
			!bytes.Equal(d.Name.Components[len(d.Name.Components)-1], d.MetaInfo.FinalBlockID.Component) {
			start += len(d.Content)
			segNum := make([]byte, 8)
			binary.BigEndian.PutUint64(segNum, uint64(start))
			comp = append(d.Name.Components[:len(d.Name.Components)-1], segNum)
		} else {
			break
		}
	}
	t := f.mw
	for _, m := range mw {
		t = m(t)
	}
	return t.Transform(content)
}
