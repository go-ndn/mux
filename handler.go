package mux

import "github.com/go-ndn/ndn"

type Handler interface {
	ServeNDN(DataSender, *ndn.Interest)
}

type DataSender interface {
	SendData(*ndn.Data)
}

type HandlerFunc func(DataSender, *ndn.Interest)

func (f HandlerFunc) ServeNDN(w DataSender, i *ndn.Interest) {
	f(w, i)
}
