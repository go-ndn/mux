package mux

import "github.com/go-ndn/ndn"

type Handler interface {
	ServeNDN(Sender, *ndn.Interest)
}

type HandlerFunc func(Sender, *ndn.Interest)

func (f HandlerFunc) ServeNDN(w Sender, i *ndn.Interest) {
	f(w, i)
}

type Middleware func(Handler) Handler

type Sender interface {
	SendInterest(*ndn.Interest) <-chan *ndn.Data
	SendData(*ndn.Data)
}

type Hijacker interface {
	Hijack() Sender
}
