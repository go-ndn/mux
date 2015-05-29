package mux

import "github.com/go-ndn/ndn"

type Fetcher struct {
	mw []Middleware
}

func NewFetcher() *Fetcher {
	return &Fetcher{}
}

func (f *Fetcher) Use(m Middleware) {
	f.mw = append(f.mw, m)
}

func (f *Fetcher) Fetch(w ndn.Sender, i *ndn.Interest, mw ...Middleware) []byte {
	h := Handler(HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		d, ok := <-w.SendInterest(i)
		if !ok {
			return
		}
		w.SendData(d)
	}))
	for _, m := range f.mw {
		h = m(h)
	}
	for _, m := range mw {
		h = m(h)
	}
	a := &assembler{Sender: w}
	h.ServeNDN(a, i)
	if a.data == nil {
		return nil
	}
	return a.data.Content
}
