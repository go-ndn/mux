package mux

import "github.com/go-ndn/ndn"

// Fetcher fetches data packets.
type Fetcher struct {
	mw []Middleware
}

// NewFetcher creates a new fetcher.
func NewFetcher() *Fetcher {
	return &Fetcher{}
}

// Use adds middleware that will be used when Fetch is invoked.
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

// Fetch applies added middleware, and fetches a data packet in the end.
//
// Additional one-time middleware will be added after the ones added by invoking Use.
func (f *Fetcher) Fetch(remote ndn.Sender, i *ndn.Interest, mw ...Middleware) []byte {
	h := Handler(HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		// face
		d, ok := <-w.SendInterest(i)
		if !ok {
			return
		}
		// collector
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
