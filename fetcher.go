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

type collector struct {
	ndn.Sender
	*ndn.Data
}

func (c *collector) SendData(d *ndn.Data) {
	if c.Data == nil {
		c.Data = d
	}
}

func (f *Fetcher) Fetch(remote ndn.Sender, i *ndn.Interest, mw ...Middleware) []byte {
	h := Handler(HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		// interest sender is "remote"
		d, ok := <-w.SendInterest(i)
		if !ok {
			return
		}
		// data sender is "collector" without middleware
		w.SendData(d)
	}))
	for _, m := range f.mw {
		h = m(h)
	}
	for _, m := range mw {
		h = m(h)
	}
	c := &collector{Sender: remote}
	h.ServeNDN(c, i)
	if c.Data == nil {
		return nil
	}
	return c.Content
}
