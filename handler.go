package mux

import "github.com/go-ndn/ndn"

// Handler serves interests by invoking SendData and SendInterest from Sender.
type Handler interface {
	ServeNDN(ndn.Sender, *ndn.Interest) error
}

// HandlerFunc is a function that implements Handler.
type HandlerFunc func(ndn.Sender, *ndn.Interest) error

// ServeNDN calls the function itself to serve interests.
func (f HandlerFunc) ServeNDN(w ndn.Sender, i *ndn.Interest) error {
	return f(w, i)
}

// Middleware transforms one Handler into another.
//
// One can create an arbitrarily long handler chain by nesting middleware.
type Middleware func(Handler) Handler

// Hijacker returns underlying Sender.
type Hijacker interface {
	Hijack() ndn.Sender
}
