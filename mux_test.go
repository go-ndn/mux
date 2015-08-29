package mux

import (
	"testing"

	"github.com/go-ndn/ndn"
)

func dummyMiddleware(h Handler) Handler { return h }

func TestMux(t *testing.T) {
	var count int
	m := New()
	m.Use(dummyMiddleware)
	m.HandleFunc("/a/b/c", func(_ ndn.Sender, _ *ndn.Interest) {
		count++
	}, dummyMiddleware)

	m.ServeNDN(nil, &ndn.Interest{
		Name: ndn.NewName("/a/b/c"),
	})

	if count != 1 {
		t.Fatalf("expect 1, got %d", count)
	}
}
