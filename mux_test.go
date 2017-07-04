package mux

import (
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"

	"github.com/go-ndn/ndn"
	"github.com/go-ndn/tlv"
)

func fakeMiddleware(h Handler) Handler { return h }

type fakeForwarder struct {
	registered map[string]struct{}
}

func (f *fakeForwarder) SendInterest(i *ndn.Interest) (*ndn.Data, error) {
	cmd := new(ndn.Command)
	err := tlv.Copy(cmd, &i.Name)
	if err != nil {
		return nil, err
	}
	f.registered[cmd.Parameters.Parameters.Name.String()] = struct{}{}

	content, err := tlv.Marshal(&ndn.CommandResponse{
		StatusCode: 200,
		StatusText: "OK",
	}, 101)
	if err != nil {
		return nil, err
	}
	return &ndn.Data{
		Name:    i.Name,
		Content: content,
	}, nil
}

func (f *fakeForwarder) SendData(_ *ndn.Data) error { return nil }

func TestMuxHandle(t *testing.T) {
	var count int
	m := New()
	m.Use(fakeMiddleware)
	m.HandleFunc("/A", func(_ ndn.Sender, _ *ndn.Interest) error {
		count++
		return nil
	}, fakeMiddleware)

	err := m.ServeNDN(nil, &ndn.Interest{
		Name: ndn.NewName("/A/B"),
	})
	if err != nil {
		t.Fatal(err)
	}

	if want := 1; count != want {
		t.Fatalf("expect %d, got %d", want, count)
	}
}

func TestMuxRegister(t *testing.T) {
	m := New()
	m.HandleFunc("/A", func(_ ndn.Sender, _ *ndn.Interest) error { return nil })
	m.HandleFunc("/B", func(_ ndn.Sender, _ *ndn.Interest) error { return nil })

	pri, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	fw := &fakeForwarder{
		registered: make(map[string]struct{}),
	}
	err = m.Register(fw, &ndn.RSAKey{
		PrivateKey: pri,
	})
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]struct{}{
		"/A": {},
		"/B": {},
	}
	if !reflect.DeepEqual(fw.registered, want) {
		t.Fatalf("expect %+v, got %+v", want, fw.registered)
	}
}
