package mux

import "github.com/go-ndn/ndn"

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

func (mux *Mux) Run(w ndn.Sender, ch <-chan *ndn.Interest, key ndn.Key) (err error) {
	var names []string
	mux.m.Visit(func(name string, v interface{}) interface{} {
		names = append(names, name)
		return v
	})
	for _, name := range names {
		err = ndn.SendControl(w, "rib", "register", &ndn.Parameters{
			Name: ndn.NewName(name),
		}, key)
		if err != nil {
			return
		}
	}
	for i := range ch {
		go mux.ServeNDN(w, i)
	}
	return
}
