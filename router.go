package mux

import (
	"github.com/go-ndn/lpm"
	"github.com/go-ndn/ndn"
)

type Router struct {
	m lpm.Matcher
}

func NewRouter() *Router {
	return &Router{m: lpm.NewThreadSafe()}
}

func (r *Router) Handle(name string, h Handler, mw ...Middleware) {
	for _, m := range mw {
		h = m(h)
	}
	r.m.Update(name, func(v interface{}) interface{} { return h }, false)
}

func (r *Router) HandleFunc(name string, h HandlerFunc, mw ...Middleware) {
	r.Handle(name, h, mw...)
}

func (r *Router) ServeNDN(w ndn.Sender, i *ndn.Interest) {
	var h Handler
	r.m.MatchRaw(i.Name.Components, func(v interface{}) {
		h = v.(Handler)
	}, true)

	if h != nil {
		h.ServeNDN(w, i)
	}
}
