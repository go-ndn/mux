package mux

import "github.com/go-ndn/ndn"

type Middleware func(Handler) Handler

type Chain struct {
	*Router
	mw Handler
}

func New() *Chain {
	r := NewRouter()
	return &Chain{Router: r, mw: r}
}

func (c *Chain) Use(m Middleware) {
	c.mw = m(c.mw)
}

func (c *Chain) Run(w DataSender, ch <-chan *ndn.Interest) {
	for i := range ch {
		go c.mw.ServeNDN(w, i)
	}
}
