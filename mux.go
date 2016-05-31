// Package mux implements a light-weight NDN application framework.
package mux

import (
	"sync"
	"time"

	"github.com/go-ndn/log"
	"github.com/go-ndn/lpm"
	"github.com/go-ndn/ndn"
)

// Mux routes an interest to the handler with the longest matching prefix.
type Mux struct {
	routeMatcher
	mu sync.RWMutex
	Handler
}

// New creates a new mux.
func New() *Mux {
	mux := new(Mux)
	mux.Handler = HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		var h Handler
		mux.mu.RLock()
		mux.Match(i.Name.Components, func(v Handler) {
			h = v
		}, true)
		mux.mu.RUnlock()

		if h != nil {
			h.ServeNDN(w, i)
		}
	})
	return mux
}

// Use adds middleware that will be used when ServeNDN is invoked.
func (mux *Mux) Use(m Middleware) {
	mux.Handler = m(mux.Handler)
}

// Handle adds Handler after additional route-specific middleware is applied.
func (mux *Mux) Handle(name string, h Handler, mw ...Middleware) {
	for _, m := range mw {
		h = m(h)
	}
	mux.mu.Lock()
	mux.routeMatcher.Update(lpm.NewComponents(name), func(Handler) Handler { return h }, false)
	mux.mu.Unlock()
}

// HandleFunc adds HandlerFunc like Handle.
func (mux *Mux) HandleFunc(name string, h HandlerFunc, mw ...Middleware) {
	mux.Handle(name, h, mw...)
}

// Register registers mux prefixes to nfd.
//
// If registering fails, it will retry after a period.
// It will not return until all prefixes are registered successfully.
func (mux *Mux) Register(w ndn.Sender, key ndn.Key) {
	mux.mu.Lock()
	mux.routeMatcher.Visit(func(name []lpm.Component, v Handler) Handler {
		for {
			err := ndn.SendControl(w, "rib", "register", &ndn.Parameters{
				Name: ndn.Name{
					Components: name,
				},
			}, key)
			if err != nil {
				log.Printf("fail to register %s, got %v\n", name, err)
				time.Sleep(time.Second)
			} else {
				break
			}
		}
		return v
	})
	mux.mu.Unlock()
}

// Run invokes Register, and serves each incoming interest in a separate goroutine.
func (mux *Mux) Run(w ndn.Sender, ch <-chan *ndn.Interest, key ndn.Key) {
	mux.Register(w, key)
	for i := range ch {
		go mux.ServeNDN(w, i)
	}
}
