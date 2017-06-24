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
	"github.com/go-ndn/lpm"
	"github.com/go-ndn/ndn"
	"github.com/go-ndn/tlv"
)

// if data packet is signed, do nothing in middleware.
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
	ndn.Cache
	cpy bool
}

func (c *cacher) SendData(d *ndn.Data) error {
	if d.MetaInfo.CacheHint == ndn.CacheHintNoCache {
		// producer indicates that this packet should not be cached
		if c.Sender == nil {
			return nil
		}
		return c.Sender.SendData(d)
	}
	c.Add(d)
	if c.Sender == nil {
		return nil
	}
	return copySend(c.Sender, d, c.cpy)
}

func copySend(w ndn.Sender, d *ndn.Data, cpy bool) error {
	if cpy {
		copied := new(ndn.Data)
		err := tlv.Copy(copied, d)
		if err != nil {
			return err
		}
		return w.SendData(copied)
	} else {
		return w.SendData(d)
	}
}

func (c *cacher) Hijack() ndn.Sender {
	return c.Sender
}

// RawCacher allows data packets to be served from content store directly.
//
// If cpy is true, data packets will be copied when they are added to and retrieved
// from content store.
func RawCacher(cache ndn.Cache, cpy bool) Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
			d := cache.Get(i)
			if d == nil {
				next.ServeNDN(&cacher{Sender: w, Cache: cache, cpy: cpy}, i)
			} else {
				copySend(w, d, cpy)
			}
		})
	}
}

// Cacher creates a new Cacher middleware instance from the default content store.
var Cacher = RawCacher(ndn.NewCache(65536), true)

// Logger prints total time to serve an interest to os.Stderr.
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

func (s *segmentor) SendData(d *ndn.Data) error {
	if signed(d) {
		return s.Sender.SendData(d)
	}
	l := d.Name.Len()
	for i := 0; i == 0 || i*s.size < len(d.Content); i++ {
		end := (i + 1) * s.size
		if end > len(d.Content) {
			end = len(d.Content)
		}
		seg := &ndn.Data{
			Content: d.Content[i*s.size : end],
		}
		segNum := encodeMarkedNum(segmentMarker, uint64(i))
		seg.Name.Components = make([]lpm.Component, l+1)
		copy(seg.Name.Components, d.Name.Components)
		seg.Name.Components[l] = segNum

		seg.MetaInfo = d.MetaInfo
		seg.MetaInfo.FinalBlockID = ndn.FinalBlockID{}
		if end == len(d.Content) {
			seg.MetaInfo.FinalBlockID.Component = segNum
		}

		err := s.Sender.SendData(seg)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *segmentor) Hijack() ndn.Sender {
	return s.Sender
}

// Segmentor breaks a data packet into many by cutting its content
// with the given size in byte.
//
// FinalBlockID is set on the last segment of the data packet.
//
// See Assembler.
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

func (a *assembler) SendData(d *ndn.Data) error {
	l := d.Name.Len()
	if l == 0 {
		return nil
	}
	blockID, err := decodeMarkedNum(segmentMarker, d.Name.Components[l-1])
	if err != nil {
		// not segmented
		return a.Sender.SendData(d)
	}
	// check if this block is requested
	if blockID != a.blockID {
		return nil
	}
	a.blockID++

	a.content = append(a.content, d.Content...)
	finalBlockID, err := decodeMarkedNum(segmentMarker, d.MetaInfo.FinalBlockID.Component)
	if err == nil && blockID >= finalBlockID {
		// final block
		assembled := &ndn.Data{
			Name:    ndn.Name{Components: d.Name.Components[:l-1]},
			Content: a.content,
		}

		assembled.MetaInfo = d.MetaInfo
		assembled.MetaInfo.FinalBlockID = ndn.FinalBlockID{}
		if l > 1 {
			assembled.MetaInfo.FinalBlockID.Component = assembled.Name.Components[l-2]
		}

		return a.Sender.SendData(assembled)
	}

	// more blocks
	seg := new(ndn.Interest)
	seg.Name.Components = make([]lpm.Component, l)
	copy(seg.Name.Components, d.Name.Components[:l-1])
	seg.Name.Components[l-1] = encodeMarkedNum(segmentMarker, a.blockID)
	a.ServeNDN(a, seg)
	return nil
}

func (a *assembler) Hijack() ndn.Sender {
	return a.Sender
}

// Assembler assembles packets broken down by Segmentor.
//
// FinalBlockID is unset after assembly.
//
// See Segmentor.
func Assembler(next Handler) Handler {
	return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		next.ServeNDN(&assembler{Sender: w, Handler: next}, i)
	})
}

type checksumVerifier struct {
	ndn.Sender
}

func (v *checksumVerifier) SendData(d *ndn.Data) error {
	var f func() hash.Hash
	switch d.SignatureInfo.SignatureType {
	case ndn.SignatureTypeDigestSHA256:
		f = sha256.New
	case ndn.SignatureTypeDigestCRC32C:
		f = ndn.NewCRC32C
	default:
		return v.Sender.SendData(d)
	}
	digest, err := tlv.Hash(f, d)
	if err != nil {
		return err
	}
	if !bytes.Equal(digest, d.SignatureValue) {
		return nil
	}
	return v.Sender.SendData(d)
}

func (v *checksumVerifier) Hijack() ndn.Sender {
	return v.Sender
}

// ChecksumVerifier verifies packet checksum like SHA256 and CRC32C.
//
// If the signature type is not a supported digest type, that data packet
// is allowed to pass through without verification.
//
// To verify signature, see Verifier.
func ChecksumVerifier(next Handler) Handler {
	return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		next.ServeNDN(&checksumVerifier{Sender: w}, i)
	})
}

// FileServer replaces an interest's prefix to form a file path,
// and serves a directory on file system.
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

// StaticFile serves a file that contains a data packet encoded in base64.
//
// It is often used to serve a certificate.
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
	pub        []*ndn.RSAKey
	keyLocator ndn.Name
	ndn.Sender
}

func (enc *encryptor) SendData(d *ndn.Data) error {
	if signed(d) {
		return enc.Sender.SendData(d)
	}
	if d.MetaInfo.EncryptionType != ndn.EncryptionTypeNone {
		return enc.Sender.SendData(d)
	}

	// Producer generates encrypted AES key with name: /producerName/C-KEY/dataName/FOR/consumerName
	// for each consumer.
	// Data packet's keyLocator is /producerName/C-KEY/dataName.
	// When consumer receives data, it attaches /FOR/consumerName in the end to fetch encrypted AES key.
	//
	// This is a primitive to distribute access to one data packet.
	l := enc.keyLocator.Len()
	keyName := make([]lpm.Component, l+d.Name.Len()+1)
	copy(keyName, enc.keyLocator.Components)
	keyName[l] = []byte("C-KEY")
	copy(keyName[l+1:], d.Name.Components)

	ckey := make([]byte, 16)
	_, err := rand.Read(ckey)
	if err != nil {
		return err
	}

	// AES-128 CTR
	d.MetaInfo.EncryptionType = ndn.EncryptionTypeAESWithCTR
	d.MetaInfo.EncryptionKeyLocator.Name.Components = keyName
	d.MetaInfo.EncryptionIV = make([]byte, aes.BlockSize)
	_, err = rand.Read(d.MetaInfo.EncryptionIV)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(ckey)
	if err != nil {
		return err
	}
	cipher.NewCTR(block, d.MetaInfo.EncryptionIV).XORKeyStream(d.Content, d.Content)

	err = enc.Sender.SendData(d)
	if err != nil {
		return err
	}

	// encrypt content key with RSA-OAEP
	for _, pub := range enc.pub {
		keyFor := make([]lpm.Component, len(keyName)+pub.Name.Len()+1)
		copy(keyFor, keyName)
		keyFor[len(keyName)] = []byte("FOR")
		copy(keyFor[len(keyName)+1:], pub.Name.Components)

		dkey := new(ndn.Data)
		dkey.Name.Components = keyFor
		dkey.Content, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, &pub.PrivateKey.PublicKey, ckey, nil)
		if err != nil {
			continue
		}
		err := enc.Sender.SendData(dkey)
		if err != nil {
			return err
		}
	}
	return nil
}

func (enc *encryptor) Hijack() ndn.Sender {
	return enc.Sender
}

// Encryptor generates a random AES content key, and encrypts data packets with AES-128 in CTR mode.
// Then this AES key is encrypted by peers' RSA public keys for distribution (RSA-OAEP).
//
// It does not register keyLocator.
//
// See Decryptor.
func Encryptor(keyLocator string, pub ...*ndn.RSAKey) Middleware {
	name := ndn.NewName(keyLocator)
	return func(next Handler) Handler {
		return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
			next.ServeNDN(&encryptor{
				Sender:     w,
				pub:        pub,
				keyLocator: name,
			}, i)
		})
	}
}

type decryptor struct {
	pri *ndn.RSAKey
	Handler
	ndn.Sender
}

func (dec *decryptor) SendData(d *ndn.Data) error {
	if d.MetaInfo.EncryptionType != ndn.EncryptionTypeAESWithCTR {
		return dec.Sender.SendData(d)
	}
	l := d.MetaInfo.EncryptionKeyLocator.Name.Len()
	keyFor := make([]lpm.Component, l+dec.pri.Name.Len()+1)
	copy(keyFor, d.MetaInfo.EncryptionKeyLocator.Name.Components)
	keyFor[l] = []byte("FOR")
	copy(keyFor[l+1:], dec.pri.Name.Components)

	c := &collector{Sender: dec.Sender}
	dec.ServeNDN(c, &ndn.Interest{Name: ndn.Name{Components: keyFor}})
	if c.Data == nil {
		return nil
	}

	ckey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, dec.pri.PrivateKey, c.Data.Content, nil)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(ckey)
	if err != nil {
		return err
	}

	cipher.NewCTR(block, d.MetaInfo.EncryptionIV).XORKeyStream(d.Content, d.Content)
	d.MetaInfo.EncryptionType = ndn.EncryptionTypeNone
	d.MetaInfo.EncryptionKeyLocator = ndn.KeyLocator{}
	d.MetaInfo.EncryptionIV = nil

	return dec.Sender.SendData(d)
}

func (dec *decryptor) Hijack() ndn.Sender {
	return dec.Sender
}

// Decryptor decrypts data packets encrypted from encryptor.
//
// It fetches encryped AES content key, and uses its private RSA key to decrypt this
// AES key.
// Later this AES key will be used to decrypt data packets.
//
// See Encryptor.
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

func (gz *gzipper) SendData(d *ndn.Data) error {
	if signed(d) {
		return gz.Sender.SendData(d)
	}
	if d.MetaInfo.CompressionType != ndn.CompressionTypeNone {
		return gz.Sender.SendData(d)
	}
	buf := new(bytes.Buffer)
	gzw := gzip.NewWriter(buf)
	_, err := gzw.Write(d.Content)
	if err != nil {
		return err
	}
	err = gzw.Close()
	if err != nil {
		return err
	}

	d.MetaInfo.CompressionType = ndn.CompressionTypeGZIP
	d.Content = buf.Bytes()
	return gz.Sender.SendData(d)
}

func (gz *gzipper) Hijack() ndn.Sender {
	return gz.Sender
}

// Gzipper compresses data packets with GZIP.
//
// See Gunzipper.
func Gzipper(next Handler) Handler {
	return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		next.ServeNDN(&gzipper{Sender: w}, i)
	})
}

type gunzipper struct {
	ndn.Sender
}

func (gz *gunzipper) SendData(d *ndn.Data) error {
	if d.MetaInfo.CompressionType != ndn.CompressionTypeGZIP {
		return gz.Sender.SendData(d)
	}
	gzr, err := gzip.NewReader(bytes.NewReader(d.Content))
	if err != nil {
		return err
	}
	defer gzr.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(gzr)

	d.MetaInfo.CompressionType = ndn.CompressionTypeNone
	d.Content = buf.Bytes()
	return gz.Sender.SendData(d)
}

func (gz *gunzipper) Hijack() ndn.Sender {
	return gz.Sender
}

// Gunzipper decompresses data packets compressed by Gzipper.
//
// See Gzipper.
func Gunzipper(next Handler) Handler {
	return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		next.ServeNDN(&gunzipper{Sender: w}, i)
	})
}

type signer struct {
	ndn.Key
	ndn.Sender
}

func (s *signer) SendData(d *ndn.Data) error {
	if signed(d) {
		return s.Sender.SendData(d)
	}
	err := ndn.SignData(s, d)
	if err != nil {
		return err
	}
	return s.Sender.SendData(d)
}

func (s *signer) Hijack() ndn.Sender {
	return s.Sender
}

// Signer signs data packets with the given key.
//
// See Verifier.
func Signer(key ndn.Key) Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
			next.ServeNDN(&signer{Sender: w, Key: key}, i)
		})
	}
}

// VerifyRule specifies a trust model.
//
// The first rule that has matching DataPattern RE2 regexp is applied.
// If there is no rule found, verification fails, and the data packet is dropped.
// DataPattern RE2 regexp capture transforms KeyPattern to match signature key locator.
// Finally DataSHA256 is used to check the trust anchor.
//
// See https://github.com/google/re2/wiki/Syntax.
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
			h := sha256.New()
			err := d.WriteTo(tlv.NewWriter(h))
			if err != nil {
				return false
			}
			return rule.DataSHA256 == fmt.Sprintf("%x", h.Sum(nil))
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

func (v *verifier) SendData(d *ndn.Data) error {
	name := d.Name.String()
	for _, rule := range v.rule {
		if !rule.re.MatchString(name) {
			continue
		}
		// if any rule matches, recursive validation is enforced
		if v.verify(d) {
			return v.Sender.SendData(d)
		}
		return nil
	}
	return v.Sender.SendData(d)
}

func (v *verifier) Hijack() ndn.Sender {
	return v.Sender
}

// Verifier checks packet signature.
//
// To verify checksum, see ChecksumVerifier.
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

func (v *versioner) SendData(d *ndn.Data) error {
	if signed(d) {
		return v.Sender.SendData(d)
	}
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(time.Now().UnixNano()/1000000))
	d.Name.Components = append(d.Name.Components, timestamp)
	return v.Sender.SendData(d)
}

func (v *versioner) Hijack() ndn.Sender {
	return v.Sender
}

// Versioner adds timestamp version to a data packet.
func Versioner(next Handler) Handler {
	return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		next.ServeNDN(&versioner{Sender: w}, i)
	})
}

type queuer struct {
	ndn.Sender
	d []*ndn.Data
}

func (q *queuer) SendData(d *ndn.Data) error {
	q.d = append(q.d, d)
	return nil
}

func (q *queuer) Hijack() ndn.Sender {
	return q.Sender
}

// Queuer sends data packets after Handler returns.
//
// By default, data packets are sent as soon as SendData is invoked.
// It is often used with RawCacher and Segmentor to ensure that all
// segmented packets are successfully added to the content store before
// the first segment is sent to the consumer.
func Queuer(next Handler) Handler {
	return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		q := &queuer{Sender: w}
		next.ServeNDN(q, i)
		for _, d := range q.d {
			w.SendData(d)
		}
	})
}

// Notify returns an interest name to notify that the data packet is ready.
//
// See Listener.
func Notify(listener, dataName string) ndn.Name {
	return ndn.NewName(fmt.Sprintf("%s/ACK%s", listener, dataName))
}

// Listener listens to notifications.
//
// The first argument of h is the data name notified from remote.
//
// See Notify.
func Listener(name string, h func(string, ndn.Sender, *ndn.Interest)) (string, Handler) {
	name += "/ACK"
	return name, HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		h(strings.TrimPrefix(i.Name.String(), name), w, i)
	})
}
