package mux

import (
	"github.com/go-ndn/lpm"
	"github.com/go-ndn/ndn"
)

type Router struct {
	m lpm.Matcher
}

func NewRouter() *Router {
	return &Router{m: lpm.New()}
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

func (r *Router) ServeNDN(w Sender, i *ndn.Interest) {
	r.m.Match(i.Name.String(), func(v interface{}) {
		v.(Handler).ServeNDN(w, i)
	}, true)
}
