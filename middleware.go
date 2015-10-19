package mux

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/go-ndn/log"
	"github.com/go-ndn/ndn"
	"github.com/go-ndn/tlv"
)

// if data packet is signed, do nothing in middleware
func signed(d *ndn.Data) bool {
	switch d.SignatureInfo.SignatureType {
	case ndn.SignatureTypeSHA256WithRSA:
	case ndn.SignatureTypeSHA256WithECDSA:
	case ndn.SignatureTypeSHA256WithHMAC:
	default:
		return false
	}
	return len(d.SignatureValue) != 0
}

type cacher struct {
	ndn.Sender
	cpy bool
}

func (c *cacher) SendData(d *ndn.Data) {
	ndn.ContentStore.Add(d)
	copySend(c.Sender, d, c.cpy)
}

func copySend(w ndn.Sender, d *ndn.Data, cpy bool) {
	if cpy {
		copied := new(ndn.Data)
		tlv.Copy(copied, d)
		w.SendData(copied)
	} else {
		w.SendData(d)
	}
}

func (c *cacher) Hijack() ndn.Sender {
	return c.Sender
}

func RawCacher(cpy bool) Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
			d := ndn.ContentStore.Get(i)
			if d == nil {
				next.ServeNDN(&cacher{Sender: w, cpy: cpy}, i)
			} else {
				copySend(w, d, cpy)
			}
		})
	}
}

var Cacher = RawCacher(true)

func Logger(next Handler) Handler {
	return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		before := time.Now()
		next.ServeNDN(w, i)
		log.Printf("%s completed in %s\n", i.Name, time.Since(before))
	})
}

type segmentor struct {
	ndn.Sender
	size int
}

func (s *segmentor) SendData(d *ndn.Data) {
	if signed(d) {
		s.Sender.SendData(d)
		return
	}
	l := d.Name.Len()
	for i := 0; i == 0 || i*s.size < len(d.Content); i++ {
		end := (i + 1) * s.size
		if end > len(d.Content) {
			end = len(d.Content)
		}
		seg := &ndn.Data{
			MetaInfo: ndn.MetaInfo{
				ContentType:     d.MetaInfo.ContentType,
				FreshnessPeriod: d.MetaInfo.FreshnessPeriod,
				CompressionType: d.MetaInfo.CompressionType,
			},
			Content:        d.Content[i*s.size : end],
			EncryptionInfo: d.EncryptionInfo,
		}
		segNum := encodeMarkedNum(segmentMarker, uint64(i))
		seg.Name.Components = make([]ndn.Component, l+1)
		copy(seg.Name.Components, d.Name.Components)
		seg.Name.Components[l] = segNum
		if end == len(d.Content) {
			seg.MetaInfo.FinalBlockID.Component = segNum
		}
		s.Sender.SendData(seg)
	}
}

func (s *segmentor) Hijack() ndn.Sender {
	return s.Sender
}

func Segmentor(size int) Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
			next.ServeNDN(&segmentor{Sender: w, size: size}, i)
		})
	}
}

type assembler struct {
	ndn.Sender
	Handler
	content []byte
	blockID uint64
}

func (a *assembler) SendData(d *ndn.Data) {
	l := d.Name.Len()
	if l == 0 {
		return
	}
	blockID, err := decodeMarkedNum(segmentMarker, d.Name.Components[l-1])
	if err != nil {
		// not segmented
		a.Sender.SendData(d)
		return
	}
	// check if this block is requested
	if blockID != a.blockID {
		return
	}
	a.blockID++

	a.content = append(a.content, d.Content...)
	finalBlockID, err := decodeMarkedNum(segmentMarker, d.MetaInfo.FinalBlockID.Component)
	if err == nil && blockID >= finalBlockID {
		// final block
		assembled := &ndn.Data{
			Name: ndn.Name{Components: d.Name.Components[:l-1]},
			MetaInfo: ndn.MetaInfo{
				ContentType:     d.MetaInfo.ContentType,
				FreshnessPeriod: d.MetaInfo.FreshnessPeriod,
				CompressionType: d.MetaInfo.CompressionType,
			},
			Content:        a.content,
			EncryptionInfo: d.EncryptionInfo,
		}
		if l > 1 {
			assembled.MetaInfo.FinalBlockID.Component = assembled.Name.Components[l-2]
		}

		a.Sender.SendData(assembled)
		return
	}

	// more blocks
	seg := new(ndn.Interest)
	seg.Name.Components = make([]ndn.Component, l)
	copy(seg.Name.Components, d.Name.Components[:l-1])
	seg.Name.Components[l-1] = encodeMarkedNum(segmentMarker, a.blockID)
	a.ServeNDN(a, seg)
}

func (a *assembler) Hijack() ndn.Sender {
	return a.Sender
}

func Assembler(next Handler) Handler {
	return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		next.ServeNDN(&assembler{Sender: w, Handler: next}, i)
	})
}

type checksumVerifier struct {
	ndn.Sender
}

func (v *checksumVerifier) SendData(d *ndn.Data) {
	var f func() hash.Hash
	switch d.SignatureInfo.SignatureType {
	case ndn.SignatureTypeDigestSHA256:
		f = sha256.New
	case ndn.SignatureTypeDigestCRC32C:
		f = ndn.NewCRC32C
	default:
		v.Sender.SendData(d)
		return
	}
	digest, err := tlv.Hash(f, d)
	if err != nil {
		return
	}
	if !bytes.Equal(digest, d.SignatureValue) {
		return
	}
	v.Sender.SendData(d)
}

func (v *checksumVerifier) Hijack() ndn.Sender {
	return v.Sender
}

func ChecksumVerifier(next Handler) Handler {
	return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		next.ServeNDN(&checksumVerifier{Sender: w}, i)
	})
}

func FileServer(from, to string) (string, Handler) {
	return from, HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		content, err := ioutil.ReadFile(to + filepath.Clean(strings.TrimPrefix(i.Name.String(), from)))
		if err != nil {
			return
		}
		w.SendData(&ndn.Data{
			Name:    i.Name,
			Content: content,
		})
	})
}

func StaticFile(path string) (string, Handler) {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	d := new(ndn.Data)
	err = d.ReadFrom(tlv.NewReader(base64.NewDecoder(base64.StdEncoding, f)))
	if err != nil {
		panic(err)
	}
	return d.Name.String(), HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		w.SendData(d)
	})
}

type encryptor struct {
	pub []*ndn.RSAKey
	ndn.Sender
}

func (enc *encryptor) SendData(d *ndn.Data) {
	if signed(d) {
		enc.Sender.SendData(d)
		return
	}
	if d.EncryptionInfo.EncryptionType != ndn.EncryptionTypeNone {
		enc.Sender.SendData(d)
		return
	}
	// content key name
	keyName := make([]ndn.Component, d.Name.Len()+1)
	copy(keyName, d.Name.Components)
	keyName[len(keyName)-1] = []byte("C-KEY")

	ckey := make([]byte, 16)
	rand.Read(ckey)

	// AES-128 CTR
	d.EncryptionInfo.EncryptionType = ndn.EncryptionTypeAESWithCTR
	d.EncryptionInfo.KeyLocator.Name.Components = keyName
	d.EncryptionInfo.IV = make([]byte, aes.BlockSize)
	rand.Read(d.EncryptionInfo.IV)
	block, err := aes.NewCipher(ckey)
	if err != nil {
		return
	}
	cipher.NewCTR(block, d.EncryptionInfo.IV).XORKeyStream(d.Content, d.Content)

	enc.Sender.SendData(d)

	// encrypt content key with RSA-OAEP
	for _, pub := range enc.pub {
		keyFor := make([]ndn.Component, len(keyName)+pub.Name.Len()+1)
		copy(keyFor, keyName)
		keyFor[len(keyName)] = []byte("FOR")
		copy(keyFor[len(keyName)+1:], pub.Name.Components)

		dkey := new(ndn.Data)
		dkey.Name.Components = keyFor
		dkey.Content, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, &pub.PrivateKey.PublicKey, ckey, nil)
		if err != nil {
			continue
		}
		enc.Sender.SendData(dkey)
	}
}

func (enc *encryptor) Hijack() ndn.Sender {
	return enc.Sender
}

func Encryptor(pub ...*ndn.RSAKey) Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
			next.ServeNDN(&encryptor{Sender: w, pub: pub}, i)
		})
	}
}

type decryptor struct {
	pri *ndn.RSAKey
	Handler
	ndn.Sender
}

func (dec *decryptor) SendData(d *ndn.Data) {
	if d.EncryptionInfo.EncryptionType != ndn.EncryptionTypeAESWithCTR {
		dec.Sender.SendData(d)
		return
	}
	l := d.EncryptionInfo.KeyLocator.Name.Len()
	keyFor := make([]ndn.Component, l+dec.pri.Name.Len()+1)
	copy(keyFor, d.EncryptionInfo.KeyLocator.Name.Components)
	keyFor[l] = []byte("FOR")
	copy(keyFor[l+1:], dec.pri.Name.Components)

	c := &collector{Sender: dec.Sender}
	dec.ServeNDN(c, &ndn.Interest{Name: ndn.Name{Components: keyFor}})
	if c.Data == nil {
		return
	}

	ckey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, dec.pri.PrivateKey, c.Data.Content, nil)
	if err != nil {
		return
	}

	block, err := aes.NewCipher(ckey)
	if err != nil {
		return
	}

	cipher.NewCTR(block, d.EncryptionInfo.IV).XORKeyStream(d.Content, d.Content)
	d.EncryptionInfo = ndn.EncryptionInfo{}

	dec.Sender.SendData(d)
}

func (dec *decryptor) Hijack() ndn.Sender {
	return dec.Sender
}

func Decryptor(pri *ndn.RSAKey) Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
			next.ServeNDN(&decryptor{Sender: w, pri: pri, Handler: next}, i)
		})
	}
}

type gzipper struct {
	ndn.Sender
}

func (gz *gzipper) SendData(d *ndn.Data) {
	if signed(d) {
		gz.Sender.SendData(d)
		return
	}
	if d.MetaInfo.CompressionType != ndn.CompressionTypeNone {
		gz.Sender.SendData(d)
		return
	}
	buf := new(bytes.Buffer)
	gzw := gzip.NewWriter(buf)
	gzw.Write(d.Content)
	gzw.Close()

	d.MetaInfo.CompressionType = ndn.CompressionTypeGZIP
	d.Content = buf.Bytes()
	gz.Sender.SendData(d)
}

func (gz *gzipper) Hijack() ndn.Sender {
	return gz.Sender
}

func Gzipper(next Handler) Handler {
	return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		next.ServeNDN(&gzipper{Sender: w}, i)
	})
}

type gunzipper struct {
	ndn.Sender
}

func (gz *gunzipper) SendData(d *ndn.Data) {
	if d.MetaInfo.CompressionType != ndn.CompressionTypeGZIP {
		gz.Sender.SendData(d)
		return
	}
	gzr, err := gzip.NewReader(bytes.NewReader(d.Content))
	if err != nil {
		return
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(gzr)
	gzr.Close()

	d.MetaInfo.CompressionType = ndn.CompressionTypeNone
	d.Content = buf.Bytes()
	gz.Sender.SendData(d)
}

func (gz *gunzipper) Hijack() ndn.Sender {
	return gz.Sender
}

func Gunzipper(next Handler) Handler {
	return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		next.ServeNDN(&gunzipper{Sender: w}, i)
	})
}

type signer struct {
	ndn.Key
	ndn.Sender
}

func (s *signer) SendData(d *ndn.Data) {
	if signed(d) {
		s.Sender.SendData(d)
		return
	}
	err := ndn.SignData(s, d)
	if err != nil {
		return
	}
	s.Sender.SendData(d)
}

func (s *signer) Hijack() ndn.Sender {
	return s.Sender
}

func Signer(key ndn.Key) Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
			next.ServeNDN(&signer{Sender: w, Key: key}, i)
		})
	}
}

type VerifyRule struct {
	DataPattern string
	re          *regexp.Regexp

	KeyPattern string
	DataSHA256 string
}

type verifier struct {
	ndn.Sender
	Handler
	rule []*VerifyRule
}

func (v *verifier) verify(d *ndn.Data) bool {
	name := d.Name.String()
	keyName := d.SignatureInfo.KeyLocator.Name.String()
	for _, rule := range v.rule {
		if !rule.re.MatchString(name) {
			continue
		}

		if rule.DataSHA256 != "" {
			// check for anchor
			digest, err := tlv.Hash(sha256.New, d)
			if err != nil {
				return false
			}
			return rule.DataSHA256 == fmt.Sprintf("%x", digest)
		}

		if rule.KeyPattern != "" &&
			!regexp.MustCompile(rule.re.ReplaceAllString(name, rule.KeyPattern)).MatchString(keyName) {
			// invalid key name
			return false
		}
		c := &collector{Sender: v.Sender}
		v.ServeNDN(c, &ndn.Interest{Name: d.SignatureInfo.KeyLocator.Name})
		if c.Data == nil {
			// cannot fetch key
			return false
		}

		key, err := ndn.CertificateFromData(c.Data)
		if err != nil {
			// invalid key
			return false
		}

		if ndn.VerifyData(key, d) != nil {
			// key cannot verify data
			return false
		}
		// recursively verify key
		return v.verify(c.Data)
	}
	return false
}

func (v *verifier) SendData(d *ndn.Data) {
	name := d.Name.String()
	for _, rule := range v.rule {
		if !rule.re.MatchString(name) {
			continue
		}
		// if any rule matches, recursive validation is enforced
		if v.verify(d) {
			v.Sender.SendData(d)
		}
		return
	}
	v.Sender.SendData(d)
}

func (v *verifier) Hijack() ndn.Sender {
	return v.Sender
}

func Verifier(rule ...*VerifyRule) Middleware {
	for _, r := range rule {
		r.re = regexp.MustCompile(r.DataPattern)
	}
	return func(next Handler) Handler {
		return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
			next.ServeNDN(&verifier{Sender: w, Handler: next, rule: rule}, i)
		})
	}
}

type versioner struct {
	ndn.Sender
}

func (v *versioner) SendData(d *ndn.Data) {
	if signed(d) {
		v.Sender.SendData(d)
		return
	}
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(time.Now().UTC().UnixNano()/1000000))
	d.Name.Components = append(d.Name.Components, timestamp)
	v.Sender.SendData(d)
}

func (v *versioner) Hijack() ndn.Sender {
	return v.Sender
}

func Versioner(next Handler) Handler {
	return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		next.ServeNDN(&versioner{Sender: w}, i)
	})
}

type queuer struct {
	ndn.Sender
	d []*ndn.Data
}

func (q *queuer) SendData(d *ndn.Data) {
	q.d = append(q.d, d)
}

func Queuer(next Handler) Handler {
	return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		q := &queuer{Sender: w}
		next.ServeNDN(q, i)
		for _, d := range q.d {
			w.SendData(d)
		}
	})
}
