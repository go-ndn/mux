package mux

import (
	"bytes"
	"testing"

	"github.com/go-ndn/ndn"
)

type interestSender struct {
	content []byte
}

func (s *interestSender) SendInterest(_ *ndn.Interest) <-chan *ndn.Data {
	ch := make(chan *ndn.Data, 1)
	ch <- &ndn.Data{
		Content: s.content,
	}
	return ch
}

func (s *interestSender) SendData(_ *ndn.Data) {}

func TestFetcher(t *testing.T) {
	f := NewFetcher()
	f.Use(dummyMiddleware)
	want := []byte{1, 2, 3}
	got := f.Fetch(&interestSender{content: want}, nil, dummyMiddleware)
	if !bytes.Equal(want, got) {
		t.Fatalf("expect %v, got %v", want, got)
	}
}
