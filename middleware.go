package mux

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/go-ndn/ndn"
)

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
		if len(d.Name.Components) > 0 {
			d.MetaInfo.FinalBlockID.Component = d.Name.Components[len(d.Name.Components)-1]
		}
		s.Sender.SendData(d)
	} else {
		for i := 0; i*s.size < len(d.Content); i++ {
			end := (i + 1) * s.size
			if end > len(d.Content) {
				end = len(d.Content)
			}
			segNum := make([]byte, 8)
			binary.BigEndian.PutUint64(segNum, uint64(i))
			seg := &ndn.Data{
				Name: ndn.Name{Components: append(d.Name.Components, segNum)},
				MetaInfo: ndn.MetaInfo{
					ContentType:     d.MetaInfo.ContentType,
					FreshnessPeriod: d.MetaInfo.FreshnessPeriod,
				},
				Content: d.Content[i*s.size : end],
			}
			if end == len(d.Content) {
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

type assembler struct {
	Sender
	ch chan<- *ndn.Data
}

func (a *assembler) SendData(d *ndn.Data) {
	select {
	case a.ch <- d:
	default:
	}
}

func Assembler(next Handler) Handler {
	return HandlerFunc(func(w Sender, i *ndn.Interest) {
		var (
			name    []ndn.Component
			content []byte
			index   int
		)
	ASSEMBLE:
		for {
			segNum := make([]byte, 8)
			binary.BigEndian.PutUint64(segNum, uint64(index))
			index++

			segName := i.Name.Components
			if name != nil {
				segName = append(name, segNum)
			}
			ch := make(chan *ndn.Data, 1)
			next.ServeNDN(
				&assembler{Sender: w, ch: ch},
				&ndn.Interest{Name: ndn.Name{Components: segName}},
			)
			select {
			case d := <-ch:
				if len(d.Name.Components) == 0 {
					return
				}
				content = append(content, d.Content...)

				if bytes.Equal(d.Name.Components[len(d.Name.Components)-1], d.MetaInfo.FinalBlockID.Component) {
					if name == nil {
						name = d.Name.Components
					}
					break ASSEMBLE
				} else {
					if name == nil {
						name = make([]ndn.Component, len(d.Name.Components)-1)
						copy(name, d.Name.Components)
					}
				}
			default:
				return
			}
		}
		d := &ndn.Data{
			Name:    ndn.Name{Components: name},
			Content: content,
		}
		if len(name) > 0 {
			d.MetaInfo.FinalBlockID.Component = name[len(name)-1]
		}
		w.SendData(d)
	})
}

type sha256Verifier struct {
	Sender
}

func (v *sha256Verifier) SendData(d *ndn.Data) {
	if d.SignatureInfo.SignatureType == ndn.SignatureTypeDigestSHA256 {
		digest, err := ndn.NewSHA256(d)
		if err != nil {
			return
		}
		if !bytes.Equal(digest, d.SignatureValue) {
			return
		}
	}
	v.Sender.SendData(d)
}

func SHA256Verifier(next Handler) Handler {
	return HandlerFunc(func(w Sender, i *ndn.Interest) {
		next.ServeNDN(&sha256Verifier{Sender: w}, i)
	})
}
