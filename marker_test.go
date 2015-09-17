package mux

import "testing"

func TestMarkedNum(t *testing.T) {
	for _, test := range []uint64{
		1<<8 - 1,
		1<<16 - 1,
		1<<32 - 1,
		1<<64 - 1,
	} {
		got, err := decodeMarkedNum(segmentMarker, encodeMarkedNum(segmentMarker, test))
		if err != nil {
			t.Fatal(err)
		}
		if got != test {
			t.Fatalf("expect %d, got %d", test, got)
		}
	}
}
