package mux

import (
	"crypto/rand"
	"crypto/rsa"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/go-ndn/ndn"
	"github.com/go-ndn/tlv"
)

// only deep copy data packet's content
func copyHandler(d *ndn.Data) Handler {
	return HandlerFunc(func(w ndn.Sender, _ *ndn.Interest) {
		copied := *d
		if len(d.Content) > 0 {
			copied.Content = make([]byte, len(d.Content))
			copy(copied.Content, d.Content)
		}
		w.SendData(&copied)
	})
}

func TestMiddlewareNOOP(t *testing.T) {
	want := &ndn.Data{
		Name: ndn.NewName("/a/b/c"),
		MetaInfo: ndn.MetaInfo{
			FinalBlockID: ndn.FinalBlockID{
				Component: []byte("c"),
			},
		},
		Content: []byte{1, 2, 3},
	}

	key := []byte("example key 1234")

	h := copyHandler(want)
	for _, test := range []Handler{
		Assembler(Cacher(Segmentor(1)(h))),
		AESDecryptor(key)(AESEncryptor(key)(h)),
		Gunzipper(Gzipper(h)),
		Logger(h),
	} {
		c := &collector{}
		test.ServeNDN(c, &ndn.Interest{
			Name: ndn.NewName("/a/b/c"),
		})
		if !reflect.DeepEqual(want, c.Data) {
			t.Fatalf("expect %+v, got %+v", want, c.Data)
		}
	}
}

func TestChecksumVerifier(t *testing.T) {
	for _, test := range []uint64{
		ndn.SignatureTypeDigestSHA256,
		ndn.SignatureTypeDigestCRC32C,
	} {
		want := &ndn.Data{
			Name: ndn.NewName("/a/b/c"),
			SignatureInfo: ndn.SignatureInfo{
				SignatureType: test,
			},
		}
		want.WriteTo(tlv.NewWriter(ioutil.Discard))

		c := &collector{}
		ChecksumVerifier(copyHandler(want)).ServeNDN(c, nil)
		if !reflect.DeepEqual(want, c.Data) {
			t.Fatalf("expect %+v, got %+v", want, c.Data)
		}
	}
}

func TestSignerVerifier(t *testing.T) {
	want := &ndn.Data{
		Name: ndn.NewName("/a/b/c"),
	}

	pri, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatal(err)
	}
	key := &ndn.RSAKey{
		Name:       ndn.NewName("/a/b/c"),
		PrivateKey: pri,
	}

	c := &collector{}
	Verifier(key)(Signer(key)(copyHandler(want))).ServeNDN(c, nil)
	if c.Data == nil || want.Name.Compare(c.Name) != 0 {
		t.Fatalf("expect %+v, got %+v", want, c.Data)
	}
}

func TestVersioner(t *testing.T) {
	want := &ndn.Data{
		Name: ndn.NewName("/a/b/c"),
	}

	c := &collector{}
	Versioner(copyHandler(want)).ServeNDN(c, nil)
	if c.Data == nil || want.Name.Len() >= c.Name.Len() {
		t.Fatalf("expect %+v, got %+v", want, c.Data)
	}
}

func TestHijacker(t *testing.T) {
	c := &collector{}

	for _, test := range []Hijacker{
		&cacher{Sender: c},
		&segmentor{Sender: c},
		&assembler{Sender: c},
		&checksumVerifier{Sender: c},
		&aesEncryptor{Sender: c},
		&aesDecryptor{Sender: c},
		&gzipper{Sender: c},
		&gunzipper{Sender: c},
		&signer{Sender: c},
		&verifier{Sender: c},
		&versioner{Sender: c},
	} {
		got := test.Hijack()
		if got != c {
			t.Fatalf("expect %T, got %T", c, got)
		}
	}
}
