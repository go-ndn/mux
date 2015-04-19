package mux

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/go-ndn/ndn"
)

type Middleware func(Handler) Handler

type Chain struct {
	*Router
	mw Handler
}

func New() *Chain {
	r := NewRouter()
	return &Chain{Router: r, mw: r}
}

func (c *Chain) Use(m Middleware) {
	c.mw = m(c.mw)
}

func (c *Chain) Run(w DataSender, ch <-chan *ndn.Interest) {
	for i := range ch {
		go c.mw.ServeNDN(w, i)
	}
}

type dataSender struct {
	mu      sync.Mutex
	content []*ndn.Data
}

func (s *dataSender) SendData(d *ndn.Data) {
	s.mu.Lock()
	s.content = append(s.content, d)
	s.mu.Unlock()
}

func Cacher(next Handler) Handler {
	return HandlerFunc(func(w DataSender, i *ndn.Interest) {
		cache := ndn.ContentStore.Get(i)
		if cache == nil {
			s := new(dataSender)
			next.ServeNDN(s, i)
			for _, d := range s.content {
				w.SendData(d)
				ndn.ContentStore.Add(d)
			}
		} else {
			w.SendData(cache)
		}
	})
}

func Logger(next Handler) Handler {
	return HandlerFunc(func(w DataSender, i *ndn.Interest) {
		before := time.Now()
		next.ServeNDN(w, i)
		fmt.Printf("%s completed in %s\n", i.Name, time.Now().Sub(before))
	})
}

func Segmentor(size int) Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(w DataSender, i *ndn.Interest) {
			s := new(dataSender)
			next.ServeNDN(s, i)
			for _, d := range s.content {
				if len(d.Content) <= size {
					w.SendData(d)
					continue
				}
				for start := 0; start < len(d.Content); start += size {
					end := start + size
					if end > len(d.Content) {
						end = len(d.Content)
					}
					segNum := make([]byte, 8)
					binary.BigEndian.PutUint64(segNum, uint64(start))
					seg := &ndn.Data{
						Name: ndn.Name{Components: append(d.Name.Components, segNum)},
						MetaInfo: ndn.MetaInfo{
							ContentType:     d.MetaInfo.ContentType,
							FreshnessPeriod: d.MetaInfo.FreshnessPeriod,
						},
						Content: d.Content[start:end],
					}
					if len(seg.Content) < size {
						seg.MetaInfo.FinalBlockID.Component = segNum
					}
					w.SendData(seg)
				}
			}
		})
	}
}
