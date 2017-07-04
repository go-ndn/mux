package mux

import (
	"bytes"
	"testing"

	"github.com/go-ndn/ndn"
)

type fakeSender struct{}

func (s fakeSender) SendInterest(_ *ndn.Interest) (*ndn.Data, error) {
	return fakeData(), nil
}

func (s fakeSender) SendData(_ *ndn.Data) error { return nil }

func TestFetcher(t *testing.T) {
	f := NewFetcher()
	f.Use(fakeMiddleware)
	want := fakeData().Content
	got, err := f.Fetch(fakeSender{}, nil, fakeMiddleware)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("expect %v, got %v", want, got)
	}
}
