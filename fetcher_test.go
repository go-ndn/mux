package mux

import (
	"bytes"
	"testing"

	"github.com/go-ndn/ndn"
)

type fakeSender struct {
	content []byte
}

func (s *fakeSender) SendInterest(_ *ndn.Interest) <-chan *ndn.Data {
	ch := make(chan *ndn.Data, 1)
	ch <- &ndn.Data{
		Content: s.content,
	}
	return ch
}

func (s *fakeSender) SendData(_ *ndn.Data) {}

func TestFetcher(t *testing.T) {
	f := NewFetcher()
	f.Use(fakeMiddleware)
	want := []byte{1, 2, 3}
	got := f.Fetch(&fakeSender{content: want}, nil, fakeMiddleware)
	if !bytes.Equal(want, got) {
		t.Fatalf("expect %v, got %v", want, got)
	}
}
