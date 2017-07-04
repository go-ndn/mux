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
	fakeHandler = HandlerFunc(func(w ndn.Sender, _ *ndn.Interest) error {
		return w.SendData(fakeData())
	})
)

func fakeChecksumHandler(sig uint64) Handler {
	return HandlerFunc(func(w ndn.Sender, _ *ndn.Interest) error {
		d := fakeData()
		d.SignatureInfo.SignatureType = sig
		err := d.WriteTo(tlv.NewWriter(ioutil.Discard))
		if err != nil {
			return err
		}
		return w.SendData(d)
	})
}

func server(collection ...*ndn.Data) Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) error {
			for _, d := range collection {
				if i.Name.Compare(d.Name) != 0 {
					continue
				}
				return w.SendData(d)
			}
			return next.ServeNDN(w, i)
		})
	}
}

func fakeCacher(next Handler) Handler {
	return RawCacher(ndn.NewCache(16), true)(next)
}

func fakeVerifyRule(l int) ([]ndn.Key, []*VerifyRule, Middleware, error) {
	key := make([]ndn.Key, l)
	rule := make([]*VerifyRule, l)
	cert := make([]*ndn.Data, l)
	for i := 0; i < l; i++ {
		var pri *rsa.PrivateKey
		pri, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			return nil, nil, nil, err
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
			return nil, nil, nil, err
		}
		if i > 0 {
			// sign current key vith previous key
			ndn.SignData(key[i-1], cert[i])
			rule[i].KeyPattern = fmt.Sprintf("/%d", i-1)
		} else {
			// anchor, get sha256
			h := sha256.New()
			err = cert[i].WriteTo(tlv.NewWriter(h))
			if err != nil {
				return nil, nil, nil, err
			}
			rule[i].DataSHA256 = fmt.Sprintf("%x", h.Sum(nil))
		}
	}
	return key, rule, server(cert...), nil
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
		Assembler(Queuer(fakeCacher(Segmentor(1)(fakeHandler)))),
		Decryptor(rsaKey)(Queuer(fakeCacher(Encryptor("/test", rsaKey)(fakeHandler)))),
		Verifier(rule...)(certServer(Signer(signKey)(fakeHandler))),
		Gunzipper(Gzipper(fakeHandler)),
		Logger(fakeHandler),
		ChecksumVerifier(fakeChecksumHandler(ndn.SignatureTypeDigestSHA256)),
		ChecksumVerifier(fakeChecksumHandler(ndn.SignatureTypeDigestCRC32C)),
	} {
		t.Log(i)

		c := &collector{}
		err := test.ServeNDN(c, &ndn.Interest{
			Name: ndn.NewName("/A/B"),
		})
		if err != nil {
			t.Fatal(err)
		}
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
	err := Versioner(fakeHandler).ServeNDN(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Data == nil || want.Name.Len() >= c.Name.Len() {
		t.Fatalf("expect %+v, got %+v", want, c.Data)
	}
}

func TestListenNotify(t *testing.T) {
	const (
		producerName = "/producerName"
		dataName     = "/data"
	)

	var count int
	m := New()
	m.Handle(Listener(producerName, func(name string, _ ndn.Sender, _ *ndn.Interest) error {
		count++
		if name != dataName {
			t.Fatalf("expect %s, got %s", dataName, name)
		}
		return nil
	}))

	err := m.ServeNDN(nil, &ndn.Interest{
		Name: Notify(producerName, dataName),
	})
	if err != nil {
		t.Fatal(err)
	}

	if want := 1; count != want {
		t.Fatalf("expect %d, got %d", want, count)
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
		&queuer{Sender: c},
	} {
		got := test.Hijack()
		if got != c {
			t.Fatalf("expect %T, got %T", c, got)
		}
	}
}
