package mux

import (
	"time"

	"github.com/go-ndn/log"
	"github.com/go-ndn/ndn"
)

type Mux struct {
	*Router
	mw Handler
}

func New() *Mux {
	r := NewRouter()
	return &Mux{Router: r, mw: r}
}

func (mux *Mux) Use(m Middleware) {
	mux.mw = m(mux.mw)
}

func (mux *Mux) ServeNDN(w ndn.Sender, i *ndn.Interest) {
	mux.mw.ServeNDN(w, i)
}

func (mux *Mux) Register(w ndn.Sender, key ndn.Key) {
	var names []string
	mux.m.Visit(func(name string, v interface{}) interface{} {
		names = append(names, name)
		return v
	})
	for _, name := range names {
		for {
			err := ndn.SendControl(w, "rib", "register", &ndn.Parameters{
				Name: ndn.NewName(name),
			}, key)
			if err != nil {
				log.Printf("fail to register %s, got %v\n", name, err)
				time.Sleep(time.Second)
			} else {
				break
			}
		}
	}
	return
}

func (mux *Mux) Run(w ndn.Sender, ch <-chan *ndn.Interest, key ndn.Key) {
	mux.Register(w, key)
	for i := range ch {
		go mux.ServeNDN(w, i)
	}
}
