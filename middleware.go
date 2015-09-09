package mux

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"hash"
	"io/ioutil"
	"os"
	"path/filepath"
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
}

func (c *cacher) SendData(d *ndn.Data) {
	copied := new(ndn.Data)
	tlv.Copy(copied, d)
	ndn.ContentStore.Add(copied)
	c.Sender.SendData(d)
}

func (c *cacher) Hijack() ndn.Sender {
	return c.Sender
}

func Cacher(next Handler) Handler {
	return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		d := ndn.ContentStore.Get(i)
		if d == nil {
			next.ServeNDN(&cacher{Sender: w}, i)
		} else {
			copied := new(ndn.Data)
			tlv.Copy(copied, d)
			w.SendData(copied)
		}
	})
}

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
				EncryptionType:  d.MetaInfo.EncryptionType,
				CompressionType: d.MetaInfo.CompressionType,
			},
			Content: d.Content[i*s.size : end],
		}
		segNum, _ := encodeMarkedNum(segmentMarker, uint64(i))
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
				EncryptionType:  d.MetaInfo.EncryptionType,
				CompressionType: d.MetaInfo.CompressionType,
			},
			Content: a.content,
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
	seg.Name.Components[l-1], _ = encodeMarkedNum(segmentMarker, a.blockID)
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
	var d ndn.Data
	err = d.ReadFrom(tlv.NewReader(base64.NewDecoder(base64.StdEncoding, f)))
	if err != nil {
		panic(err)
	}
	return d.Name.String(), HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		w.SendData(&d)
	})
}

type aesEncryptor struct {
	cipher.Block
	ndn.Sender
}

func (enc *aesEncryptor) SendData(d *ndn.Data) {
	if signed(d) {
		enc.Sender.SendData(d)
		return
	}
	if d.MetaInfo.EncryptionType != ndn.EncryptionTypeNone {
		enc.Sender.SendData(d)
		return
	}
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)
	stream := cipher.NewCTR(enc, iv)
	stream.XORKeyStream(d.Content, d.Content)
	d.Content = append(d.Content, iv...)

	d.MetaInfo.EncryptionType = ndn.EncryptionTypeAESWithCTR
	enc.Sender.SendData(d)
}

func (enc *aesEncryptor) Hijack() ndn.Sender {
	return enc.Sender
}

func AESEncryptor(key []byte) Middleware {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return func(next Handler) Handler {
		return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
			next.ServeNDN(&aesEncryptor{Sender: w, Block: block}, i)
		})
	}
}

type aesDecryptor struct {
	cipher.Block
	ndn.Sender
}

func (dec *aesDecryptor) SendData(d *ndn.Data) {
	if d.MetaInfo.EncryptionType != ndn.EncryptionTypeAESWithCTR {
		dec.Sender.SendData(d)
		return
	}
	if len(d.Content) < aes.BlockSize {
		return
	}
	iv := d.Content[len(d.Content)-aes.BlockSize:]
	d.Content = d.Content[:len(d.Content)-aes.BlockSize]
	stream := cipher.NewCTR(dec, iv)
	stream.XORKeyStream(d.Content, d.Content)

	d.MetaInfo.EncryptionType = ndn.EncryptionTypeNone
	dec.Sender.SendData(d)
}

func (dec *aesDecryptor) Hijack() ndn.Sender {
	return dec.Sender
}

func AESDecryptor(key []byte) Middleware {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return func(next Handler) Handler {
		return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
			next.ServeNDN(&aesDecryptor{Sender: w, Block: block}, i)
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

type verifier struct {
	ndn.Key
	ndn.Sender
}

func (v *verifier) SendData(d *ndn.Data) {
	err := v.Verify(d, d.SignatureValue)
	if err != nil {
		return
	}
	v.Sender.SendData(d)
}

func (v *verifier) Hijack() ndn.Sender {
	return v.Sender
}

func Verifier(key ndn.Key) Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
			next.ServeNDN(&verifier{Sender: w, Key: key}, i)
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
