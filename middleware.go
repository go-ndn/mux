package mux

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"
	"io/ioutil"
	"path/filepath"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/go-ndn/ndn"
	"github.com/go-ndn/tlv"
)

// NOTE:
// 1. When data packet is passed to SendData, it is owned by receiver.
// 2. Sender may call SendData zero or one time.

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
	for i := 0; i == 0 || i*s.size < len(d.Content); i++ {
		end := (i + 1) * s.size
		if end > len(d.Content) {
			end = len(d.Content)
		}
		segNum := bytes.NewBuffer([]byte{0x00})
		tlv.WriteVarNum(segNum, uint64(i))

		seg := new(ndn.Data)
		seg.Name.Components = make([]ndn.Component, len(d.Name.Components)+1)
		copy(seg.Name.Components, d.Name.Components)
		seg.Name.Components[len(seg.Name.Components)-1] = segNum.Bytes()
		seg.Content = d.Content[i*s.size : end]
		seg.MetaInfo = d.MetaInfo
		if end == len(d.Content) {
			seg.MetaInfo.FinalBlockID.Component = segNum.Bytes()
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
		var (
			name    []ndn.Component
			content []byte
			index   uint64
		)
		for {
			seg := i
			if name != nil {
				segNum := bytes.NewBuffer([]byte{0x00})
				tlv.WriteVarNum(segNum, index)

				seg = new(ndn.Interest)
				seg.Name.Components = make([]ndn.Component, len(name)+1)
				copy(seg.Name.Components, name)
				seg.Name.Components[len(name)] = segNum.Bytes()
			}
			index++

			a := &assembler{Sender: w}
			next.ServeNDN(a, seg)
			if a.data == nil {
				return
			}
			d := a.data

			if len(d.Name.Components) == 0 {
				return
			}
			content = append(content, d.Content...)

			if bytes.Equal(d.Name.Components[len(d.Name.Components)-1], d.MetaInfo.FinalBlockID.Component) {
				if name == nil {
					name = d.Name.Components
				}
				break
			} else {
				if name == nil {
					name = d.Name.Components[:len(d.Name.Components)-1]
				}
			}
		}
		d := &ndn.Data{
			Name:    ndn.Name{Components: name},
			Content: content,
		}
		if len(name) > 0 {
			d.MetaInfo.FinalBlockID.Component = name[len(name)-1]
		}
		w.SendData(d)
	})
}

type basicVerifier struct {
	ndn.Sender
}

func (v *basicVerifier) SendData(d *ndn.Data) {
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

func (v *basicVerifier) Hijack() ndn.Sender {
	return v.Sender
}

func BasicVerifier(next Handler) Handler {
	return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		next.ServeNDN(&basicVerifier{Sender: w}, i)
	})
}

type prefixTrimmer struct {
	ndn.Sender
	name []ndn.Component
}

func (t *prefixTrimmer) SendData(d *ndn.Data) {
	name := make([]ndn.Component, len(t.name)+len(d.Name.Components))
	copy(name, t.name)
	copy(name[len(t.name):], d.Name.Components)
	d.Name.Components = name
	t.Sender.SendData(d)
}

func (t *prefixTrimmer) Hijack() ndn.Sender {
	return t.Sender
}

func PrefixTrimmer(prefix string) Middleware {
	name := ndn.NewName(prefix).Components
	return func(next Handler) Handler {
		return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
			if len(i.Name.Components) < len(name) {
				return
			}
			for index, comp := range name {
				if !bytes.Equal(comp, i.Name.Components[index]) {
					return
				}
			}
			orig := i.Name.Components
			i.Name.Components = i.Name.Components[len(name):]
			next.ServeNDN(&prefixTrimmer{Sender: w, name: name}, i)
			i.Name.Components = orig
		})
	}
}

func FileServer(root string) Handler {
	return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
		content, err := ioutil.ReadFile(root + filepath.Clean(i.Name.String()))
		if err != nil {
			return
		}
		w.SendData(&ndn.Data{
			Name:    i.Name,
			Content: content,
		})
	})
}

type aesEncryptor struct {
	block cipher.Block
	ndn.Sender
}

func (enc *aesEncryptor) SendData(d *ndn.Data) {
	ciphertext := make([]byte, aes.BlockSize+len(d.Content))
	iv := ciphertext[:aes.BlockSize]
	rand.Read(iv)
	stream := cipher.NewCTR(enc.block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], d.Content)
	d.Content = ciphertext
	enc.Sender.SendData(d)
}

func (enc *aesEncryptor) Hijack() ndn.Sender {
	return enc.Sender
}

func AESEncryptor(key []byte) Middleware {
	block, err := aes.NewCipher(key)
	return func(next Handler) Handler {
		return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
			if err != nil {
				fmt.Println(err)
				return
			}
			next.ServeNDN(&aesEncryptor{Sender: w, block: block}, i)
		})
	}
}

type aesDecryptor struct {
	block cipher.Block
	ndn.Sender
}

func (dec *aesDecryptor) SendData(d *ndn.Data) {
	if len(d.Content) < aes.BlockSize {
		return
	}
	plaintext := make([]byte, len(d.Content)-aes.BlockSize)
	stream := cipher.NewCTR(dec.block, d.Content[:aes.BlockSize])
	stream.XORKeyStream(plaintext, d.Content[aes.BlockSize:])
	d.Content = plaintext
	dec.Sender.SendData(d)
}

func (dec *aesDecryptor) Hijack() ndn.Sender {
	return dec.Sender
}

func AESDecryptor(key []byte) Middleware {
	block, err := aes.NewCipher(key)
	return func(next Handler) Handler {
		return HandlerFunc(func(w ndn.Sender, i *ndn.Interest) {
			if err != nil {
				fmt.Println(err)
				return
			}
			next.ServeNDN(&aesDecryptor{Sender: w, block: block}, i)
		})
	}
}

type gzipper struct {
	ndn.Sender
}

func (gz *gzipper) SendData(d *ndn.Data) {
	buf := new(bytes.Buffer)
	gzw := gzip.NewWriter(buf)
	gzw.Write(d.Content)
	gzw.Close()
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
	buf := new(bytes.Buffer)
	gzr, err := gzip.NewReader(bytes.NewReader(d.Content))
	if err != nil {
		return
	}
	defer gzr.Close()
	buf.ReadFrom(gzr)
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
