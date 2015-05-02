package mux

import "github.com/go-ndn/ndn"

type Handler interface {
	ServeNDN(ndn.Sender, *ndn.Interest)
}

type HandlerFunc func(ndn.Sender, *ndn.Interest)

func (f HandlerFunc) ServeNDN(w ndn.Sender, i *ndn.Interest) {
	f(w, i)
}

type Middleware func(Handler) Handler

type Hijacker interface {
	Hijack() ndn.Sender
}
