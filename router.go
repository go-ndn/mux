package mux

import (
	"github.com/go-ndn/lpm"
	"github.com/go-ndn/ndn"
)

type Handler func(*ndn.Face, *ndn.Interest)

type Router struct {
	m lpm.Matcher
}

func New() *Router {
	return &Router{m: lpm.New()}
}

func (r *Router) Handle(name string, h Handler) {
	r.m.Update(name, func(v interface{}) interface{} { return h }, false)
}

func (r *Router) Run(face *ndn.Face, ch <-chan *ndn.Interest) {
	for i := range ch {
		r.m.Match(i.Name.String(), func(v interface{}) {
			go v.(Handler)(face, i)
		})
	}
}
