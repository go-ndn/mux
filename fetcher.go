package mux

import (
	"bytes"
	"encoding/binary"

	"github.com/go-ndn/ndn"
)

type Transformer func([]byte) []byte
type FetcherMiddleware func(Transformer) Transformer

type Fetcher struct {
	mw Transformer
}

func NewFetcher() *Fetcher {
	return &Fetcher{
		mw: func(b []byte) []byte { return b },
	}
}

func (f *Fetcher) Use(m FetcherMiddleware) {
	f.mw = m(f.mw)
}

func (f *Fetcher) Validate(d *ndn.Data) bool {
	switch d.SignatureInfo.SignatureType {
	case ndn.SignatureTypeDigestSha256:
		digest, err := ndn.NewSha256(d)
		if err != nil {
			return false
		}
		return bytes.Equal(digest, d.SignatureValue)
	}
	return false
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
		if !f.Validate(d) {
			return nil
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
	h := f.mw
	for _, m := range mw {
		h = m(h)
	}
	return h(content)
}
