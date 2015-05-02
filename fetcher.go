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

func (f *Fetcher) Fetch(fetcher ndn.Sender, name ndn.Name, mw ...Middleware) []byte {
	h := Handler(HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		d, ok := <-fetcher.SendInterest(i)
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
	ch := make(chan *ndn.Data, 1)
	h.ServeNDN(&assembler{Sender: fetcher, ch: ch}, &ndn.Interest{Name: name})
	select {
	case d := <-ch:
		return d.Content
	default:
		return nil
	}
}
