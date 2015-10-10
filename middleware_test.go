package mux

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
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

func fakeVerifyRule(l int) (key []ndn.Key, rule []*VerifyRule, err error) {
	key = make([]ndn.Key, l)
	rule = make([]*VerifyRule, l)
	for i := 0; i < l; i++ {
		var pri *rsa.PrivateKey
		pri, err = rsa.GenerateKey(rand.Reader, 512)
		if err != nil {
			return
		}
		key[i] = &ndn.RSAKey{
			Name:       ndn.NewName(fmt.Sprintf("/%d", i)),
			PrivateKey: pri,
		}
		rule[i] = &VerifyRule{
			DataPattern: fmt.Sprintf("/%d", i),
		}
		var d *ndn.Data
		d, err = ndn.CertificateToData(key[i])
		if err != nil {
			return
		}
		if i > 0 {
			// sign current key vith previous key
			ndn.SignData(key[i-1], d)
			rule[i].KeyPattern = fmt.Sprintf("/%d", i-1)
		} else {
			// anchor, get sha256
			var digest []byte
			digest, err = tlv.Hash(sha256.New, d)
			if err != nil {
				return
			}
			rule[i].DataSHA256 = fmt.Sprintf("%x", digest)
		}
		ndn.ContentStore.Add(d)
	}
	return
}

func TestMiddleware(t *testing.T) {
	// encrypt
	encryptKey := []byte("example key 1234")
	// sign
	key, rule, err := fakeVerifyRule(3)
	if err != nil {
		t.Fatal(err)
	}
	rule = append(rule, &VerifyRule{
		DataPattern: "/A/B",
		KeyPattern:  fmt.Sprintf("/%d", len(rule)-1),
	})

	want := fakeData()
	for i, test := range []Handler{
		Verifier(rule...)(Cacher(Signer(key[len(key)-1])(fakeHandler))),
		Assembler(Cacher(Segmentor(1)(fakeHandler))),
		AESDecryptor(encryptKey)(AESEncryptor(encryptKey)(fakeHandler)),
		Gunzipper(Gzipper(fakeHandler)),
		Logger(fakeHandler),
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
			t.Fatalf("test %d: expect %+v, got %+v", i, want, c.Data)
		}
		// reset cache
		ndn.ContentStore = ndn.NewCache(16)
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
