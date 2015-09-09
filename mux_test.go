package mux

import (
	"testing"

	"github.com/go-ndn/ndn"
)

func fakeMiddleware(h Handler) Handler { return h }

func TestMux(t *testing.T) {
	var count int
	m := New()
	m.Use(fakeMiddleware)
	m.HandleFunc("/a/b/c", func(_ ndn.Sender, _ *ndn.Interest) {
		count++
	}, fakeMiddleware)

	m.ServeNDN(nil, &ndn.Interest{
		Name: ndn.NewName("/a/b/c"),
	})

	if count != 1 {
		t.Fatalf("expect 1, got %d", count)
	}
}
