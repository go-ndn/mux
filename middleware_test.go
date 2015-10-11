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

func server(collection ...*ndn.Data) Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
			for _, d := range collection {
				if i.Name.Compare(d.Name) != 0 {
					continue
				}
				w.SendData(d)
				return
			}
			next.ServeNDN(w, i)
		})
	}
}

func fakeVerifyRule(l int) (key []ndn.Key, rule []*VerifyRule, certServer Middleware, err error) {
	key = make([]ndn.Key, l)
	rule = make([]*VerifyRule, l)
	cert := make([]*ndn.Data, l)
	for i := 0; i < l; i++ {
		var pri *rsa.PrivateKey
		pri, err = rsa.GenerateKey(rand.Reader, 1024)
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
		cert[i], err = ndn.CertificateToData(key[i])
		if err != nil {
			return
		}
		if i > 0 {
			// sign current key vith previous key
			ndn.SignData(key[i-1], cert[i])
			rule[i].KeyPattern = fmt.Sprintf("/%d", i-1)
		} else {
			// anchor, get sha256
			var digest []byte
			digest, err = tlv.Hash(sha256.New, cert[i])
			if err != nil {
				return
			}
			rule[i].DataSHA256 = fmt.Sprintf("%x", digest)
		}
	}
	certServer = server(cert...)
	return
}

func TestMiddleware(t *testing.T) {
	// sign
	key, rule, certServer, err := fakeVerifyRule(3)
	if err != nil {
		t.Fatal(err)
	}
	rule = append(rule, &VerifyRule{
		DataPattern: "/A/B",
		KeyPattern:  fmt.Sprintf("/%d", len(rule)-1),
	})
	signKey := key[len(key)-1]
	rsaKey := signKey.(*ndn.RSAKey)

	want := fakeData()
	for i, test := range []Handler{
		Assembler(Queuer(Cacher(Segmentor(1)(fakeHandler)))),
		Decryptor(rsaKey)(Queuer(Cacher(Encryptor(rsaKey)(fakeHandler)))),
		Verifier(rule...)(certServer(Signer(signKey)(fakeHandler))),
		Gunzipper(Gzipper(fakeHandler)),
		Logger(fakeHandler),
		ChecksumVerifier(fakeChecksumHandler(ndn.SignatureTypeDigestSHA256)),
		ChecksumVerifier(fakeChecksumHandler(ndn.SignatureTypeDigestCRC32C)),
	} {
		t.Log(i)

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
		&encryptor{Sender: c},
		&decryptor{Sender: c},
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
