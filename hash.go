package softblake3

import (
	"encoding/binary"
	"errors"
	"hash"
	"io"
)

const (
	BlockSize = _BLAKE3_BLOCK_LEN
	KeySize   = _BLAKE3_KEY_LEN
	Size      = _BLAKE3_OUT_LEN
)

var ErrKeyLengthMismatch = errors.New("key length mismatch")

type hasher_type int

const (
	_HasherRegular hasher_type = iota
	_HasherKeyed
	_HasherDeriveKey
)

type Hasher struct {
	h   blake3_hasher
	key [32]byte
	t   hasher_type
}

var _ io.Writer = (*Hasher)(nil)
var _ io.StringWriter = (*Hasher)(nil)
var _ hash.Hash = (*Hasher)(nil)
var _ hash.Hash32 = (*Hasher)(nil)
var _ hash.Hash64 = (*Hasher)(nil)

func New() *Hasher {
	hasher := Hasher{
		t: _HasherRegular,
	}
	_blake3_hasher_init(&hasher.h)
	return &hasher
}

func NewKeyed(key *[32]byte) *Hasher {
	hasher := Hasher{
		t: _HasherKeyed,
	}
	copy(hasher.key[:], key[:])
	_blake3_hasher_init_keyed(&hasher.h, &hasher.key)
	return &hasher
}

func NewDeriveKey(context []byte) *Hasher {
	hasher := Hasher{
		t: _HasherDeriveKey,
	}
	_blake3_derive_key_calculate_context_key(context, &hasher.key)
	_blake3_hasher_init_derive_key_from_context_key(&hasher.h, &hasher.key)
	return &hasher
}

// Write adds more data to the running hash.
// It never returns an error.
func (g *Hasher) Write(b []byte) (n int, err error) {
	_blake3_hasher_update(&g.h, b)
	return len(b), nil
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (g *Hasher) Sum(b []byte) []byte {
	var out [Size]byte

	if cap(b)-len(b) >= Size {
		_blake3_hasher_finalize(&g.h, b[len(b):len(b)+Size])
		return b[:len(b)+Size]
	}

	_blake3_hasher_finalize(&g.h, out[:])
	return append(b, out[:]...)
}

// SumFill fills the given byte array with the current hash.
func (g *Hasher) SumFill(b []byte) {
	if len(b) <= 0 {
		return
	}
	_blake3_hasher_finalize(&g.h, b)
}

// Reset resets the Hash to its initial state.
func (g *Hasher) Reset() {
	_blake3_hasher_destroy(&g.h)
	switch g.t {
	case _HasherRegular:
		_blake3_hasher_init(&g.h)
	case _HasherKeyed:
		_blake3_hasher_init_keyed(&g.h, &g.key)
	case _HasherDeriveKey:
		_blake3_hasher_init_derive_key_from_context_key(&g.h, &g.key)
	}
}

// Size returns the number of bytes Sum will return.
func (g *Hasher) Size() int { return Size }

// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount
// of data, but it may operate more efficiently if all writes
// are a multiple of the block size.
func (g *Hasher) BlockSize() int { return BlockSize }

func (g *Hasher) Sum64() uint64 {
	var out [8]byte
	_blake3_hasher_finalize(&g.h, out[:])
	return binary.LittleEndian.Uint64(out[:])
}

func (g *Hasher) Sum32() uint32 {
	var out [4]byte
	_blake3_hasher_finalize(&g.h, out[:])
	return binary.LittleEndian.Uint32(out[:])
}

// Destroy wipes secret materials from the memory.
func (g *Hasher) Destroy() {
	_blake3_hasher_destroy(&g.h)
	_wipe_bytes(g.key[:])
	g.t = _HasherRegular
	_blake3_hasher_init(&g.h)
}

func Sum224(b []byte) (out [224 / 8]byte) {
	var hasher blake3_hasher
	_blake3_hasher_init(&hasher)
	_blake3_hasher_update(&hasher, b)
	_blake3_hasher_finalize(&hasher, out[:])
	_blake3_hasher_destroy(&hasher)
	return
}

func Sum256(b []byte) (out [256 / 8]byte) {
	var hasher blake3_hasher
	_blake3_hasher_init(&hasher)
	_blake3_hasher_update(&hasher, b)
	_blake3_hasher_finalize(&hasher, out[:])
	_blake3_hasher_destroy(&hasher)
	return
}

func Sum384(b []byte) (out [384 / 8]byte) {
	var hasher blake3_hasher
	_blake3_hasher_init(&hasher)
	_blake3_hasher_update(&hasher, b)
	_blake3_hasher_finalize(&hasher, out[:])
	_blake3_hasher_destroy(&hasher)
	return
}

func Sum512(b []byte) (out [512 / 8]byte) {
	var hasher blake3_hasher
	_blake3_hasher_init(&hasher)
	_blake3_hasher_update(&hasher, b)
	_blake3_hasher_finalize(&hasher, out[:])
	_blake3_hasher_destroy(&hasher)
	return
}
