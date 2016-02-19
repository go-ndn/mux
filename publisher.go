package mux

import "github.com/go-ndn/ndn"

type Publisher struct {
	ndn.Cache
	mw []Middleware
}

func NewPublisher(cache ndn.Cache) *Publisher {
	return &Publisher{
		Cache: cache,
	}
}

func (p *Publisher) Use(m Middleware) {
	p.mw = append(p.mw, m)
}

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
