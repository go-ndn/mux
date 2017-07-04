package mux

import "github.com/go-ndn/ndn"

// Fetcher fetches data packets.
type Fetcher struct {
	Handler
}

// NewFetcher creates a new fetcher.
func NewFetcher() *Fetcher {
	return &Fetcher{
		Handler: HandlerFunc(func(w ndn.Sender, i *ndn.Interest) error {
			// face
			d, err := w.SendInterest(i)
			if err != nil {
				return err
			}
			// collector
			return w.SendData(d)
		}),
	}
}

// Use adds middleware that will be used when Fetch is invoked.
func (f *Fetcher) Use(m Middleware) {
	f.Handler = m(f.Handler)
}

type collector struct {
	ndn.Sender
	*ndn.Data
}

func (c *collector) SendData(d *ndn.Data) error {
	if c.Data == nil {
		c.Data = d
	}
	return nil
}

// Fetch applies added middleware, and fetches a data packet in the end.
//
// Additional one-time middleware will be added after the ones added by invoking Use.
func (f *Fetcher) Fetch(remote ndn.Sender, i *ndn.Interest, mw ...Middleware) ([]byte, error) {
	h := f.Handler
	for _, m := range mw {
		h = m(h)
	}
	c := &collector{Sender: remote}
	err := h.ServeNDN(c, i)
	if err != nil {
		return nil, err
	}
	if c.Data == nil {
		return nil, nil
	}
	return c.Content, nil
}
