package mux

import (
	"github.com/go-ndn/lpm"
	"github.com/go-ndn/ndn"
)

type HandlerFunc func(*ndn.Face, *ndn.Interest)

func (f HandlerFunc) ServeNDN(face *ndn.Face, i *ndn.Interest) {
	f(face, i)
}

type Handler interface {
	ServeNDN(*ndn.Face, *ndn.Interest)
}

type Router struct {
	m lpm.Matcher
}

func New() *Router {
	return &Router{m: lpm.New()}
}

func (r *Router) Handle(name string, h Handler) {
	r.m.Update(name, func(v interface{}) interface{} { return h }, false)
}

func (r *Router) HandleFunc(name string, h HandlerFunc) {
	r.m.Update(name, func(v interface{}) interface{} { return h }, false)
}

func (r *Router) ServeNDN(face *ndn.Face, i *ndn.Interest) {
	r.m.Match(i.Name.String(), func(v interface{}) {
		v.(Handler).ServeNDN(face, i)
	})
}

func (r *Router) Run(face *ndn.Face, ch <-chan *ndn.Interest) {
	for i := range ch {
		go r.ServeNDN(face, i)
	}
}
