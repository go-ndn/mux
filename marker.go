package mux

import (
	"encoding/binary"
	"io"
	"math"
)

const (
	segmentMarker = 0x00
)

func encodeMarkedNum(marker byte, v uint64) []byte {
	b := make([]byte, 9)
	b[0] = marker
	n := encodeUint64(b[1:], v)
	return b[:n+1]
}

func decodeMarkedNum(marker byte, b []byte) (uint64, error) {
	if len(b) == 0 || b[0] != marker {
		return 0, io.ErrShortBuffer
	}
	return decodeUint64(b[1:]), nil
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

func encodeUint64(b []byte, v uint64) int {
	switch {
	case v > math.MaxUint32:
		binary.BigEndian.PutUint64(b, v)
		return 8
	case v > math.MaxUint16:
		binary.BigEndian.PutUint32(b, uint32(v))
		return 4
	case v > math.MaxUint8:
		binary.BigEndian.PutUint16(b, uint16(v))
		return 2
	default:
		b[0] = uint8(v)
		return 1
	}
}
