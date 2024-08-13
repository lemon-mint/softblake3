//go:build !appengine
// +build !appengine

package softblake3

import "unsafe"

// WriteString adds more data to the running hash.
// It never returns an error.
func (g *Hasher) WriteString(b string) (n int, err error) {
	_blake3_hasher_update(&g.h, unsafe.Slice((*byte)(unsafe.Pointer(unsafe.StringData(b))), len(b)))
	return len(b), nil
}
