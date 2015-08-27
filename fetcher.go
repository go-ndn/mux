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

type dummySender struct {
	ndn.Sender
	ndn.Data
}

func (s *dummySender) SendData(d *ndn.Data) {
	s.Data = *d
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
	dummy := &dummySender{Sender: w}
	h.ServeNDN(dummy, i)
	return dummy.Content
}
