package mux

import "github.com/go-ndn/ndn"

// Publisher publishes data packets to content store.
// Typically, it is used with RawCacher, so that the published data
// is immediately available.
type Publisher struct {
	ndn.Cache
	mw []Middleware
}

// NewPublisher creates a new publisher.
func NewPublisher(cache ndn.Cache) *Publisher {
	return &Publisher{
		Cache: cache,
	}
}

// Use adds middleware that will be used when Publish is invoked.
func (p *Publisher) Use(m Middleware) {
	p.mw = append(p.mw, m)
}

// Publish applies added middleware, and publishes data packets to content store in the end.
//
// Additional one-time middleware will be added after the ones added by invoking Use.
func (p *Publisher) Publish(d *ndn.Data, mw ...Middleware) {
	h := Handler(HandlerFunc(func(w ndn.Sender, _ *ndn.Interest) {
		w.SendData(d)
	}))
	for _, m := range p.mw {
		h = m(h)
	}
	for _, m := range mw {
		h = m(h)
	}
	h.ServeNDN(&cacher{Cache: p.Cache}, nil)
}
