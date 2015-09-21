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

func fakeData() *ndn.Data {
	return &ndn.Data{
		Name: ndn.NewName("/A/B"),
		MetaInfo: ndn.MetaInfo{
			FinalBlockID: ndn.FinalBlockID{
				Component: []byte("B"),
			},
		},
		Content: []byte{1, 2, 3},
	}
}

var (
	fakeHandler = HandlerFunc(func(w ndn.Sender, _ *ndn.Interest) {
		w.SendData(fakeData())
	})
)

func fakeChecksumHandler(sig uint64) Handler {
	return HandlerFunc(func(w ndn.Sender, _ *ndn.Interest) {
		d := fakeData()
		d.SignatureInfo.SignatureType = sig
		d.WriteTo(tlv.NewWriter(ioutil.Discard))
		w.SendData(d)
	})
}

func TestMiddleware(t *testing.T) {
	// encrypt
	encryptKey := []byte("example key 1234")
	// sign
	pri, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatal(err)
	}
	signKey := &ndn.RSAKey{
		PrivateKey: pri,
	}

	want := fakeData()
	for _, test := range []Handler{
		Assembler(Cacher(Segmentor(1)(fakeHandler))),
		AESDecryptor(encryptKey)(AESEncryptor(encryptKey)(fakeHandler)),
		Gunzipper(Gzipper(fakeHandler)),
		Logger(fakeHandler),
		Verifier(signKey)(Signer(signKey)(fakeHandler)),
		ChecksumVerifier(fakeChecksumHandler(ndn.SignatureTypeDigestSHA256)),
		ChecksumVerifier(fakeChecksumHandler(ndn.SignatureTypeDigestCRC32C)),
	} {
		c := &collector{}
		test.ServeNDN(c, &ndn.Interest{
			Name: ndn.NewName("/A/B"),
		})
		if c.Data != nil {
			// reset signature for deep equal
			c.SignatureInfo = ndn.SignatureInfo{}
			c.SignatureValue = nil
		}
		if !reflect.DeepEqual(want, c.Data) {
			t.Fatalf("expect %+v, got %+v", want, c.Data)
		}
	}
}

func TestVersioner(t *testing.T) {
	want := fakeData()

	c := &collector{}
	Versioner(fakeHandler).ServeNDN(c, nil)
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
