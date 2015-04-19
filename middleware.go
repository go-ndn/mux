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

func (c *Chain) Run(w DataSender, ch <-chan *ndn.Interest) {
	for i := range ch {
		go c.mw.ServeNDN(w, i)
	}
}

type cacher struct {
	w DataSender
}

func (c *cacher) SendData(d *ndn.Data) {
	c.w.SendData(d)
	ndn.ContentStore.Add(d)
}

func Cacher(next Handler) Handler {
	return HandlerFunc(func(w DataSender, i *ndn.Interest) {
		cache := ndn.ContentStore.Get(i)
		if cache == nil {
			next.ServeNDN(&cacher{w: w}, i)
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

type segmentor struct {
	w    DataSender
	size int
}

func (s *segmentor) SendData(d *ndn.Data) {
	if len(d.Content) <= s.size {
		s.w.SendData(d)
	} else {
		segNum := make([]byte, 8)
		for start := 0; start < len(d.Content); start += s.size {
			end := start + s.size
			if end > len(d.Content) {
				end = len(d.Content)
			}
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
			s.w.SendData(seg)
		}
	}
}

func Segmentor(size int) Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(w DataSender, i *ndn.Interest) {
			next.ServeNDN(&segmentor{w: w, size: size}, i)
		})
	}
}

func Assemble(w InterestSender, name ndn.Name) []byte {
	var content []byte
	var start int
	segNum := make([]byte, 8)
	for {
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
