package mux

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/go-ndn/ndn"
	"github.com/go-ndn/tlv"
)

type cacher struct {
	ndn.Sender
}

func (c *cacher) SendData(d *ndn.Data) {
	ndn.ContentStore.Add(d)
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
			w.SendData(d)
		}
	})
}

type logger struct {
	ndn.Sender
}

func (l *logger) SendData(d *ndn.Data) {
	spew.Dump(d)
	l.Sender.SendData(d)
}

func (l *logger) Hijack() ndn.Sender {
	return l.Sender
}

func Logger(next Handler) Handler {
	return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		spew.Dump(i)
		before := time.Now()
		next.ServeNDN(&logger{Sender: w}, i)
		fmt.Printf("%s completed in %s\n", i.Name, time.Since(before))
	})
}

type segmentor struct {
	ndn.Sender
	size int
}

func (s *segmentor) SendData(d *ndn.Data) {
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
	data *ndn.Data
}

func (a *assembler) SendData(d *ndn.Data) {
	a.data = d
}

func (a *assembler) Hijack() ndn.Sender {
	return a.Sender
}

func Assembler(next Handler) Handler {
	return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		buf := new(ndn.Data)

		var fetch func(*ndn.Interest)
		fetch = func(i *ndn.Interest) {
			a := &assembler{Sender: w}
			next.ServeNDN(a, i)
			if a.data == nil {
				return
			}
			l := a.data.Name.Len()
			if l == 0 {
				return
			}

			buf.Content = append(buf.Content, a.data.Content...)

			blockID, err := decodeMarkedNum(segmentMarker, a.data.Name.Components[l-1])
			if err != nil {
				return
			}
			finalBlockID, err := decodeMarkedNum(segmentMarker, a.data.MetaInfo.FinalBlockID.Component)
			if err == nil && blockID >= finalBlockID {
				// final block
				buf.Name.Components = a.data.Name.Components[:l-1]
				buf.MetaInfo = ndn.MetaInfo{
					ContentType:     a.data.MetaInfo.ContentType,
					FreshnessPeriod: a.data.MetaInfo.FreshnessPeriod,
					EncryptionType:  a.data.MetaInfo.EncryptionType,
					CompressionType: a.data.MetaInfo.CompressionType,
				}

				if l > 1 {
					buf.MetaInfo.FinalBlockID.Component = buf.Name.Components[l-2]
				}
				return
			}

			seg := new(ndn.Interest)
			seg.Name.Components = make([]ndn.Component, l)
			copy(seg.Name.Components, a.data.Name.Components[:l-1])
			seg.Name.Components[l-1], _ = encodeMarkedNum(segmentMarker, blockID+1)

			fetch(seg)
		}
		fetch(i)
		w.SendData(buf)
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
	block cipher.Block
	ndn.Sender
}

func (enc *aesEncryptor) SendData(d *ndn.Data) {
	if d.MetaInfo.EncryptionType != ndn.EncryptionTypeNone {
		enc.Sender.SendData(d)
		return
	}
	ciphertext := make([]byte, aes.BlockSize+len(d.Content))
	iv := ciphertext[:aes.BlockSize]
	rand.Read(iv)
	stream := cipher.NewCTR(enc.block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], d.Content)

	enc.Sender.SendData(&ndn.Data{
		Name: d.Name,
		MetaInfo: ndn.MetaInfo{
			ContentType:     d.MetaInfo.ContentType,
			FreshnessPeriod: d.MetaInfo.FreshnessPeriod,
			FinalBlockID:    d.MetaInfo.FinalBlockID,
			EncryptionType:  ndn.EncryptionTypeAESWithCTR,
			CompressionType: d.MetaInfo.CompressionType,
		},
		Content: ciphertext,
	})
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
			next.ServeNDN(&aesEncryptor{Sender: w, block: block}, i)
		})
	}
}

type aesDecryptor struct {
	block cipher.Block
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
	plaintext := make([]byte, len(d.Content)-aes.BlockSize)
	stream := cipher.NewCTR(dec.block, d.Content[:aes.BlockSize])
	stream.XORKeyStream(plaintext, d.Content[aes.BlockSize:])

	dec.Sender.SendData(&ndn.Data{
		Name: d.Name,
		MetaInfo: ndn.MetaInfo{
			ContentType:     d.MetaInfo.ContentType,
			FreshnessPeriod: d.MetaInfo.FreshnessPeriod,
			FinalBlockID:    d.MetaInfo.FinalBlockID,
			EncryptionType:  ndn.EncryptionTypeNone,
			CompressionType: d.MetaInfo.CompressionType,
		},
		Content: plaintext,
	})
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
			next.ServeNDN(&aesDecryptor{Sender: w, block: block}, i)
		})
	}
}

type gzipper struct {
	ndn.Sender
}

func (gz *gzipper) SendData(d *ndn.Data) {
	if d.MetaInfo.CompressionType != ndn.CompressionTypeNone {
		gz.Sender.SendData(d)
		return
	}
	buf := new(bytes.Buffer)
	gzw := gzip.NewWriter(buf)
	gzw.Write(d.Content)
	gzw.Close()

	gz.Sender.SendData(&ndn.Data{
		Name: d.Name,
		MetaInfo: ndn.MetaInfo{
			ContentType:     d.MetaInfo.ContentType,
			FreshnessPeriod: d.MetaInfo.FreshnessPeriod,
			FinalBlockID:    d.MetaInfo.FinalBlockID,
			EncryptionType:  d.MetaInfo.EncryptionType,
			CompressionType: ndn.CompressionTypeGZIP,
		},
		Content: buf.Bytes(),
	})
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
	buf := new(bytes.Buffer)
	gzr, err := gzip.NewReader(bytes.NewReader(d.Content))
	if err != nil {
		return
	}
	defer gzr.Close()
	buf.ReadFrom(gzr)

	gz.Sender.SendData(&ndn.Data{
		Name: d.Name,
		MetaInfo: ndn.MetaInfo{
			ContentType:     d.MetaInfo.ContentType,
			FreshnessPeriod: d.MetaInfo.FreshnessPeriod,
			FinalBlockID:    d.MetaInfo.FinalBlockID,
			EncryptionType:  d.MetaInfo.EncryptionType,
			CompressionType: ndn.CompressionTypeNone,
		},
		Content: buf.Bytes(),
	})
}

func (gz *gunzipper) Hijack() ndn.Sender {
	return gz.Sender
}

func Gunzipper(next Handler) Handler {
	return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		next.ServeNDN(&gunzipper{Sender: w}, i)
	})
}
