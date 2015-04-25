package mux

import "github.com/go-ndn/ndn"

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
}

func NewFetcher() *Fetcher {
	return &Fetcher{
		fw: TransformerFunc(func(b []byte) []byte { return b }),
	}
}

func (f *Fetcher) Use(m Middleware) {
	f.mw = append(f.mw, m)
}

func (f *Fetcher) UseFetchware(m Fetchware) {
	f.fw = m(f.fw)
}

func (f *Fetcher) Fetch(fetcher Sender, name ndn.Name, fw ...Fetchware) []byte {
	h := Handler(HandlerFunc(func(w Sender, i *ndn.Interest) {
		d, ok := <-fetcher.SendInterest(i)
		if !ok {
			return
		}
		w.SendData(d)
	}))
	for _, m := range f.mw {
		h = m(h)
	}
	ch := make(chan *ndn.Data, 1)
	h.ServeNDN(&assembler{Sender: fetcher, ch: ch}, &ndn.Interest{Name: name})
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
