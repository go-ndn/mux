package mux

import (
	"reflect"
	"testing"

	"github.com/go-ndn/ndn"
)

func TestPublisher(t *testing.T) {
	c := ndn.NewCache(1)
	p := NewPublisher(c)
	p.Use(fakeMiddleware)
	p.Publish(fakeData(), fakeMiddleware)

	want := fakeData()
	got := c.Get(&ndn.Interest{
		Name: want.Name,
	})
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("expect %v, got %v", want, got)
	}
}
