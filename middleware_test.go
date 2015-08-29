package mux

import (
	"crypto/rand"
	"crypto/rsa"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/go-ndn/ndn"
)

func dummyHandler(d ndn.Data) Handler {
	return HandlerFunc(func(w ndn.Sender, _ *ndn.Interest) {
		w.SendData(&d)
	})
}

func TestMiddlewareNOOP(t *testing.T) {
	want := ndn.Data{
		Name: ndn.NewName("/a/b/c"),
		MetaInfo: ndn.MetaInfo{
			FinalBlockID: ndn.FinalBlockID{
				Component: []byte("c"),
			},
		},
		Content: []byte{1, 2, 3},
	}

	h := dummyHandler(want)

	key := []byte("example key 1234")

	for _, test := range []Handler{
		Assembler(Cacher(Segmentor(1)(h))),
		AESDecryptor(key)(AESEncryptor(key)(h)),
		Gunzipper(Gzipper(h)),
		Logger(h),
	} {
		sender := &dummySender{}
		test.ServeNDN(sender, &ndn.Interest{
			Name: ndn.NewName("/a/b/c"),
		})
		if !reflect.DeepEqual(want, sender.Data) {
			t.Fatalf("expect %#v, got %#v", want, sender.Data)
		}
	}
}

func TestChecksumVerifier(t *testing.T) {
	for _, test := range []uint64{
		ndn.SignatureTypeDigestSHA256,
		ndn.SignatureTypeDigestCRC32C,
	} {
		want := ndn.Data{
			Name: ndn.NewName("/a/b/c"),
			SignatureInfo: ndn.SignatureInfo{
				SignatureType: test,
			},
		}
		want.WriteTo(ioutil.Discard)

		sender := &dummySender{}
		ChecksumVerifier(dummyHandler(want)).ServeNDN(sender, nil)
		if !reflect.DeepEqual(want, sender.Data) {
			t.Fatalf("expect %#v, got %#v", want, sender.Data)
		}
	}
}

func TestSignerVerifier(t *testing.T) {
	pri, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatal(err)
	}

	key := &ndn.RSAKey{
		Name:       ndn.NewName("/a/b/c"),
		PrivateKey: pri,
	}
	want := ndn.Data{
		Name: ndn.NewName("/a/b/c"),
	}

	sender := &dummySender{}
	Verifier(key)(Signer(key)(dummyHandler(want))).ServeNDN(sender, nil)
	if want.Name.Compare(sender.Name) != 0 {
		t.Fatalf("expect %#v, got %#v", want, sender.Data)
	}
}

func TestVersioner(t *testing.T) {
	want := ndn.Data{
		Name: ndn.NewName("/a/b/c"),
	}

	sender := &dummySender{}
	Versioner(dummyHandler(want)).ServeNDN(sender, nil)
	if want.Name.Len() >= sender.Name.Len() {
		t.Fatalf("expect %#v, got %#v", want, sender.Data)
	}
}

func TestHijacker(t *testing.T) {
	sender := &dummySender{}

	for _, test := range []Hijacker{
		&cacher{Sender: sender},
		&segmentor{Sender: sender},
		&assembler{Sender: sender},
		&checksumVerifier{Sender: sender},
		&aesEncryptor{Sender: sender},
		&aesDecryptor{Sender: sender},
		&gzipper{Sender: sender},
		&gunzipper{Sender: sender},
		&signer{Sender: sender},
		&verifier{Sender: sender},
		&versioner{Sender: sender},
	} {
		got := test.Hijack()
		if got != sender {
			t.Fatalf("expect %T, got %T", sender, got)
		}
	}

}
