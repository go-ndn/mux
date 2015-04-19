package mux

import "github.com/go-ndn/ndn"

type Handler interface {
	ServeNDN(Sender, *ndn.Interest)
}

type HandlerFunc func(Sender, *ndn.Interest)

func (f HandlerFunc) ServeNDN(w Sender, i *ndn.Interest) {
	f(w, i)
}

type InterestSender interface {
	SendInterest(*ndn.Interest) <-chan *ndn.Data
}

type DataSender interface {
	SendData(*ndn.Data)
}

type Sender interface {
	InterestSender
	DataSender
}
