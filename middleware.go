package mux

import (
	"bytes"
	"encoding/binary"
	"fmt"
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

func (c *Chain) Run(w Sender, ch <-chan *ndn.Interest) {
	for i := range ch {
		go c.mw.ServeNDN(w, i)
	}
}

type cacher struct {
	Sender
}

func (c *cacher) SendData(d *ndn.Data) {
	c.Sender.SendData(d)
	ndn.ContentStore.Add(d)
}

func Cacher(next Handler) Handler {
	return HandlerFunc(func(w Sender, i *ndn.Interest) {
		cache := ndn.ContentStore.Get(i)
		if cache == nil {
			next.ServeNDN(&cacher{Sender: w}, i)
		} else {
			w.SendData(cache)
		}
	})
}

func Logger(next Handler) Handler {
	return HandlerFunc(func(w Sender, i *ndn.Interest) {
		before := time.Now()
		next.ServeNDN(w, i)
		fmt.Printf("%s completed in %s\n", i.Name, time.Now().Sub(before))
	})
}

type segmentor struct {
	Sender
	size int
}

func (s *segmentor) SendData(d *ndn.Data) {
	if len(d.Content) <= s.size {
		s.Sender.SendData(d)
	} else {
		for start := 0; start < len(d.Content); start += s.size {
			end := start + s.size
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
			if len(seg.Content) < s.size {
				seg.MetaInfo.FinalBlockID.Component = segNum
			}
			s.Sender.SendData(seg)
		}
	}
}

func Segmentor(size int) Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(w Sender, i *ndn.Interest) {
			next.ServeNDN(&segmentor{Sender: w, size: size}, i)
		})
	}
}

func Assemble(w InterestSender, name ndn.Name) []byte {
	var content []byte
	var start int
	for {
		segNum := make([]byte, 8)
		binary.BigEndian.PutUint64(segNum, uint64(start))
		d, ok := <-w.SendInterest(&ndn.Interest{
			Name: ndn.Name{Components: append(name.Components, segNum)},
		})
		if !ok {
			return nil
		}
		content = append(content, d.Content...)
		if len(d.Name.Components) > 0 &&
			!bytes.Equal(d.Name.Components[len(d.Name.Components)-1], d.MetaInfo.FinalBlockID.Component) {
			start += len(d.Content)
		} else {
			break
		}
	}
	return content
}
