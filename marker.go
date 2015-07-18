package mux

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
)

const (
	segmentMarker = 0x00
)

func encodeMarkedNum(marker byte, v uint64) (b []byte, err error) {
	buf := new(bytes.Buffer)
	err = buf.WriteByte(marker)
	if err != nil {
		return
	}
	err = encodeUint64(buf, v)
	if err != nil {
		return
	}
	b = buf.Bytes()
	return
}

func decodeMarkedNum(marker byte, b []byte) (v uint64, err error) {
	if len(b) == 0 || b[0] != marker {
		err = io.ErrShortBuffer
		return
	}
	v = decodeUint64(b[1:])
	return
}

func decodeUint64(b []byte) uint64 {
	switch len(b) {
	case 8:
		return binary.BigEndian.Uint64(b)
	case 4:
		return uint64(binary.BigEndian.Uint32(b))
	case 2:
		return uint64(binary.BigEndian.Uint16(b))
	case 1:
		return uint64(b[0])
	}
	return 0
}

func encodeUint64(w io.Writer, v uint64) (err error) {
	b := make([]byte, 8)
	switch {
	case v > math.MaxUint32:
		binary.BigEndian.PutUint64(b, v)
		_, err = w.Write(b)
	case v > math.MaxUint16:
		binary.BigEndian.PutUint32(b, uint32(v))
		_, err = w.Write(b[:4])
	case v > math.MaxUint8:
		binary.BigEndian.PutUint16(b, uint16(v))
		_, err = w.Write(b[:2])
	default:
		b[0] = uint8(v)
		_, err = w.Write(b[:1])
	}
	return
}
