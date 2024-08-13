package softblake3

const (
	_BLAKE3_OUT_LEN   = 32
	_BLAKE3_KEY_LEN   = 32
	_BLAKE3_BLOCK_LEN = 64
	_BLAKE3_CHUNK_LEN = 1024

	_CHUNK_START         = 1 << 0
	_CHUNK_END           = 1 << 1
	_PARENT              = 1 << 2
	_ROOT                = 1 << 3
	_KEYED_HASH          = 1 << 4
	_DERIVE_KEY_CONTEXT  = 1 << 5
	_DERIVE_KEY_MATERIAL = 1 << 6
)

var (
	_IV = [8]uint32{
		0x6A09E667,
		0xBB67AE85,
		0x3C6EF372,
		0xA54FF53A,
		0x510E527F,
		0x9B05688C,
		0x1F83D9AB,
		0x5BE0CD19,
	}
	_MSG_PERMUTATION = [16]int{
		2, 6, 3, 10, 7, 0, 4, 13,
		1, 11, 12, 5, 9, 14, 15, 8,
	}
)

/*
// This struct is private.
typedef struct _blake3_chunk_state {
  uint32_t chaining_value[8];
  uint64_t chunk_counter;
  uint8_t block[BLAKE3_BLOCK_LEN];
  uint8_t block_len;
  uint8_t blocks_compressed;
  uint32_t flags;
} _blake3_chunk_state;
*/

type _blake3_chunk_state struct {
	chaining_value    [8]uint32
	chunk_counter     uint64
	block             [_BLAKE3_BLOCK_LEN]uint8
	block_len         uint8
	blocks_compressed uint8
	flags             uint32
}

/*
// An incremental hasher that can accept any number of writes.
typedef struct blake3_hasher {
  _blake3_chunk_state chunk_state;
  uint32_t key_words[8];
  uint32_t cv_stack[8 * 54]; // Space for 54 subtree chaining values:
  uint8_t cv_stack_len;      // 2^54 * CHUNK_LEN = 2^64
  uint32_t flags;
} blake3_hasher;
*/

type blake3_hasher struct {
	chunk_state  _blake3_chunk_state
	key_words    [8]uint32
	cv_stack     [8 * 54]uint32
	cv_stack_len uint8
	flags        uint32
}

/*
inline static uint32_t rotate_right(uint32_t x, int n) {
  return (x >> n) | (x << (32 - n));
}
*/

func _rotate_right(x uint32, n int) uint32 {
	return (x >> n) | (x << (32 - n))
}

/*
inline static void g(uint32_t state[16], size_t a, size_t b, size_t c, size_t d,
                    uint32_t mx, uint32_t my) {
  state[a] = state[a] + state[b] + mx;
  state[d] = rotate_right(state[d] ^ state[a], 16);
  state[c] = state[c] + state[d];
  state[b] = rotate_right(state[b] ^ state[c], 12);
  state[a] = state[a] + state[b] + my;
  state[d] = rotate_right(state[d] ^ state[a], 8);
  state[c] = state[c] + state[d];
  state[b] = rotate_right(state[b] ^ state[c], 7);
}
*/

func _g(state *[16]uint32, a, b, c, d uint, mx, my uint32) {
	state[a] = state[a] + state[b] + mx
	state[d] = _rotate_right(state[d]^state[a], 16)
	state[c] = state[c] + state[d]
	state[b] = _rotate_right(state[b]^state[c], 12)
	state[a] = state[a] + state[b] + my
	state[d] = _rotate_right(state[d]^state[a], 8)
	state[c] = state[c] + state[d]
	state[b] = _rotate_right(state[b]^state[c], 7)
}

/*
inline static void round_function(uint32_t state[16], uint32_t m[16]) {
  // Mix the columns.
  g(state, 0, 4, 8, 12, m[0], m[1]);
  g(state, 1, 5, 9, 13, m[2], m[3]);
  g(state, 2, 6, 10, 14, m[4], m[5]);
  g(state, 3, 7, 11, 15, m[6], m[7]);
  // Mix the diagonals.
  g(state, 0, 5, 10, 15, m[8], m[9]);
  g(state, 1, 6, 11, 12, m[10], m[11]);
  g(state, 2, 7, 8, 13, m[12], m[13]);
  g(state, 3, 4, 9, 14, m[14], m[15]);
}
*/

func _round_function(state *[16]uint32, m *[16]uint32) {
	// Mix the columns.
	_g(state, 0, 4, 8, 12, m[0], m[1])
	_g(state, 1, 5, 9, 13, m[2], m[3])
	_g(state, 2, 6, 10, 14, m[4], m[5])
	_g(state, 3, 7, 11, 15, m[6], m[7])
	// Mix the diagonals.
	_g(state, 0, 5, 10, 15, m[8], m[9])
	_g(state, 1, 6, 11, 12, m[10], m[11])
	_g(state, 2, 7, 8, 13, m[12], m[13])
	_g(state, 3, 4, 9, 14, m[14], m[15])
}

/*
inline static void permute(uint32_t m[16]) {
  uint32_t permuted[16];
  for (size_t i = 0; i < 16; i++) {
    permuted[i] = m[MSG_PERMUTATION[i]];
  }
  memcpy(m, permuted, sizeof(permuted));
}
*/

func _permute(m *[16]uint32) {
	var permuted [16]uint32
	for i := 0; i < 16; i++ {
		permuted[i] = m[_MSG_PERMUTATION[i]]
	}
	copy(m[:], permuted[:])
	_wipe_uint32s(permuted[:])
}

/*
inline static void compress(const uint32_t chaining_value[8],
                            const uint32_t block_words[16], uint64_t counter,
                            uint32_t block_len, uint32_t flags,
                            uint32_t out[16]) {
  uint32_t state[16] = {
      chaining_value[0],
      chaining_value[1],
      chaining_value[2],
      chaining_value[3],
      chaining_value[4],
      chaining_value[5],
      chaining_value[6],
      chaining_value[7],
      IV[0],
      IV[1],
      IV[2],
      IV[3],
      (uint32_t)counter,
      (uint32_t)(counter >> 32),
      block_len,
      flags,
  };
  uint32_t block[16];
  memcpy(block, block_words, sizeof(block));

  round_function(state, block); // round 1
  permute(block);
  round_function(state, block); // round 2
  permute(block);
  round_function(state, block); // round 3
  permute(block);
  round_function(state, block); // round 4
  permute(block);
  round_function(state, block); // round 5
  permute(block);
  round_function(state, block); // round 6
  permute(block);
  round_function(state, block); // round 7

  for (size_t i = 0; i < 8; i++) {
    state[i] ^= state[i + 8];
    state[i + 8] ^= chaining_value[i];
  }

  memcpy(out, state, sizeof(state));
}
*/

func _compress(
	chaining_value *[8]uint32,
	block_words *[16]uint32, counter uint64,
	block_len uint32, flags uint32,
	out *[16]uint32,
) {
	var state [16]uint32
	state[0] = chaining_value[0]
	state[1] = chaining_value[1]
	state[2] = chaining_value[2]
	state[3] = chaining_value[3]
	state[4] = chaining_value[4]
	state[5] = chaining_value[5]
	state[6] = chaining_value[6]
	state[7] = chaining_value[7]
	state[8] = _IV[0]
	state[9] = _IV[1]
	state[10] = _IV[2]
	state[11] = _IV[3]
	state[12] = uint32(counter)
	state[13] = uint32(counter >> 32)
	state[14] = block_len
	state[15] = flags

	var block [16]uint32
	copy(block[:], block_words[:])

	_round_function(&state, &block) // round 1
	_permute(&block)
	_round_function(&state, &block) // round 2
	_permute(&block)
	_round_function(&state, &block) // round 3
	_permute(&block)
	_round_function(&state, &block) // round 4
	_permute(&block)
	_round_function(&state, &block) // round 5
	_permute(&block)
	_round_function(&state, &block) // round 6
	_permute(&block)
	_round_function(&state, &block) // round 7

	for i := 0; i < 8; i++ {
		state[i] ^= state[i+8]
		state[i+8] ^= chaining_value[i]
	}

	copy(out[:], state[:])
	_wipe_uint32s(state[:])
	_wipe_uint32s(block[:])
}

/*
inline static void words_from_little_endian_bytes(const void *bytes,
                                                  size_t bytes_len,
                                                  uint32_t *out) {
  assert(bytes_len % 4 == 0);
  const uint8_t *u8_ptr = (const uint8_t *)bytes;
  for (size_t i = 0; i < (bytes_len / 4); i++) {
    out[i] = ((uint32_t)(*u8_ptr++));
    out[i] += ((uint32_t)(*u8_ptr++)) << 8;
    out[i] += ((uint32_t)(*u8_ptr++)) << 16;
    out[i] += ((uint32_t)(*u8_ptr++)) << 24;
  }
}
*/

func _words_from_little_endian_bytes(bytes []byte, out []uint32) {
	if len(bytes)%4 != 0 {
		panic("bytes_len % 4 != 0")
	}
	for i := 0; i < len(bytes)/4; i++ {
		out[i] = uint32(bytes[i*4]) + uint32(bytes[i*4+1])<<8 + uint32(bytes[i*4+2])<<16 + uint32(bytes[i*4+3])<<24
	}
}

/*
typedef struct output {
  uint32_t input_chaining_value[8];
  uint32_t block_words[16];
  uint64_t counter;
  uint32_t block_len;
  uint32_t flags;
} output;
*/

type output struct {
	input_chaining_value [8]uint32
	block_words          [16]uint32
	counter              uint64
	block_len            uint32
	flags                uint32
}

/*
inline static void output_chaining_value(const output *self, uint32_t out[8]) {
  uint32_t out16[16];
  compress(self->input_chaining_value, self->block_words, self->counter,
          self->block_len, self->flags, out16);
  memcpy(out, out16, 8 * 4);
}
*/

func _output_chaining_value(self *output, out *[8]uint32) {
	var out16 [16]uint32
	_compress(
		&self.input_chaining_value, &self.block_words, self.counter,
		self.block_len, self.flags, &out16,
	)
	copy(out[:], out16[:])
	_wipe_uint32s(out16[:])
}

/*
inline static void output_root_bytes(const output *self, void *out,
                                    size_t out_len) {
  uint8_t *out_u8 = (uint8_t *)out;
  uint64_t output_block_counter = 0;
  while (out_len > 0) {
    uint32_t words[16];
    compress(self->input_chaining_value, self->block_words,
            output_block_counter, self->block_len, self->flags | ROOT, words);
    for (size_t word = 0; word < 16; word++) {
      for (int byte = 0; byte < 4; byte++) {
        if (out_len == 0) {
          return;
        }
        *out_u8 = (uint8_t)(words[word] >> (8 * byte));
        out_u8++;
        out_len--;
      }
    }
    output_block_counter++;
  }
}
*/

func _output_root_bytes(self *output, out []byte) {
	var output_block_counter uint64
	var index int
	var words [16]uint32
	out_len := len(out)
	for out_len > 0 {
		_compress(
			&self.input_chaining_value, &self.block_words, output_block_counter,
			self.block_len, self.flags|_ROOT, &words,
		)
		for word := 0; word < 16; word++ {
			for byte := 0; byte < 4; byte++ {
				if out_len == 0 {
					_wipe_uint32s(words[:])
					return
				}
				out[index] = uint8(words[word] >> (8 * byte))
				index++
				out_len--
			}
		}
		output_block_counter++
	}
	_wipe_uint32s(words[:])
}

/*
inline static void chunk_state_init(_blake3_chunk_state *self,
                                    const uint32_t key_words[8],
                                    uint64_t chunk_counter, uint32_t flags) {
  memcpy(self->chaining_value, key_words, sizeof(self->chaining_value));
  self->chunk_counter = chunk_counter;
  memset(self->block, 0, sizeof(self->block));
  self->block_len = 0;
  self->blocks_compressed = 0;
  self->flags = flags;
}
*/

func _chunk_state_init(self *_blake3_chunk_state, key_words *[8]uint32, chunk_counter uint64, flags uint32) {
	copy(self.chaining_value[:], key_words[:])
	self.chunk_counter = chunk_counter
	for i := range self.block {
		self.block[i] = 0
	}
	self.block_len = 0
	self.blocks_compressed = 0
	self.flags = flags
}

/*
inline static size_t chunk_state_len(const _blake3_chunk_state *self) {
  return BLAKE3_BLOCK_LEN * (size_t)self->blocks_compressed +
        (size_t)self->block_len;
}
*/

func _chunk_state_len(self *_blake3_chunk_state) uint {
	return _BLAKE3_BLOCK_LEN*uint(self.blocks_compressed) + uint(self.block_len)
}

/*
inline static uint32_t chunk_state_start_flag(const _blake3_chunk_state *self) {
  if (self->blocks_compressed == 0) {
    return CHUNK_START;
  } else {
    return 0;
  }
}
*/

func _chunk_state_start_flag(self *_blake3_chunk_state) uint32 {
	if self.blocks_compressed == 0 {
		return _CHUNK_START
	} else {
		return 0
	}
}

/*
inline static void chunk_state_update(_blake3_chunk_state *self,
                                      const void *input, size_t input_len) {
  const uint8_t *input_u8 = (const uint8_t *)input;
  while (input_len > 0) {
    // If the block buffer is full, compress it and clear it. More input is
    // coming, so this compression is not CHUNK_END.
    if (self->block_len == BLAKE3_BLOCK_LEN) {
      uint32_t block_words[16];
      words_from_little_endian_bytes(self->block, BLAKE3_BLOCK_LEN,
                                    block_words);
      uint32_t out16[16];
      compress(self->chaining_value, block_words, self->chunk_counter,
              BLAKE3_BLOCK_LEN, self->flags | chunk_state_start_flag(self),
              out16);
      memcpy(self->chaining_value, out16, sizeof(self->chaining_value));
      self->blocks_compressed++;
      memset(self->block, 0, sizeof(self->block));
      self->block_len = 0;
    }

    // Copy input bytes into the block buffer.
    size_t want = BLAKE3_BLOCK_LEN - (size_t)self->block_len;
    size_t take = want;
    if (input_len < want) {
      take = input_len;
    }
    memcpy(&self->block[(size_t)self->block_len], input_u8, take);
    self->block_len += (uint8_t)take;
    input_u8 += take;
    input_len -= take;
  }
}
*/

func _chunk_state_update(self *_blake3_chunk_state, input []byte) {
	input_len := uint(len(input))
	var block_words [16]uint32
	var out16 [16]uint32

	for input_len > 0 {
		// If the block buffer is full, compress it and clear it. More input is
		// coming, so this compression is not CHUNK_END.
		if self.block_len == _BLAKE3_BLOCK_LEN {
			_words_from_little_endian_bytes(self.block[:], block_words[:])
			_compress(
				&self.chaining_value, &block_words, self.chunk_counter,
				_BLAKE3_BLOCK_LEN, self.flags|_chunk_state_start_flag(self), &out16,
			)
			copy(self.chaining_value[:], out16[:])
			self.blocks_compressed++
			for i := range self.block {
				self.block[i] = 0
			}
			self.block_len = 0
		}

		// Copy input bytes into the block buffer.
		var want uint = _BLAKE3_BLOCK_LEN - uint(self.block_len)
		var take uint = want
		if input_len < want {
			take = input_len
		}
		copy(self.block[uint(self.block_len):uint(self.block_len)+take], input[:take])
		self.block_len += uint8(take)
		input = input[take:]
		input_len -= take
	}
	_wipe_uint32s(block_words[:])
	_wipe_uint32s(out16[:])
}

/*
inline static output chunk_state_output(const _blake3_chunk_state *self) {
  output ret;
  memcpy(ret.input_chaining_value, self->chaining_value,
        sizeof(ret.input_chaining_value));
  words_from_little_endian_bytes(self->block, sizeof(self->block),
                                ret.block_words);
  ret.counter = self->chunk_counter;
  ret.block_len = (uint32_t)self->block_len;
  ret.flags = self->flags | chunk_state_start_flag(self) | CHUNK_END;
  return ret;
}
*/

func _chunk_state_output(self *_blake3_chunk_state) output {
	var ret output
	copy(ret.input_chaining_value[:], self.chaining_value[:])
	_words_from_little_endian_bytes(self.block[:], ret.block_words[:])
	ret.counter = self.chunk_counter
	ret.block_len = uint32(self.block_len)
	ret.flags = self.flags | _chunk_state_start_flag(self) | _CHUNK_END
	return ret
}

/*
inline static output parent_output(const uint32_t left_child_cv[8],
                                  const uint32_t right_child_cv[8],
                                  const uint32_t key_words[8],
                                  uint32_t flags) {
  output ret;
  memcpy(ret.input_chaining_value, key_words, sizeof(ret.input_chaining_value));
  memcpy(&ret.block_words[0], left_child_cv, 8 * 4);
  memcpy(&ret.block_words[8], right_child_cv, 8 * 4);
  ret.counter = 0; // Always 0 for parent nodes.
  ret.block_len =
      BLAKE3_BLOCK_LEN; // Always BLAKE3_BLOCK_LEN (64) for parent nodes.
  ret.flags = PARENT | flags;
  return ret;
}
*/

func _parent_output(left_child_cv, right_child_cv, key_words *[8]uint32, flags uint32) output {
	var ret output
	copy(ret.input_chaining_value[:], key_words[:])
	copy(ret.block_words[:8], left_child_cv[:])
	copy(ret.block_words[8:], right_child_cv[:])
	ret.counter = 0                   // Always 0 for parent nodes.
	ret.block_len = _BLAKE3_BLOCK_LEN // Always BLAKE3_BLOCK_LEN (64) for parent nodes.
	ret.flags = _PARENT | flags
	return ret
}

/*
inline static void parent_cv(const uint32_t left_child_cv[8],
                            const uint32_t right_child_cv[8],
                            const uint32_t key_words[8], uint32_t flags,
                            uint32_t out[8]) {
  output o = parent_output(left_child_cv, right_child_cv, key_words, flags);
  // We only write to `out` after we've read the inputs. That makes it safe for
  // `out` to alias an input, which we do below.
  output_chaining_value(&o, out);
}
*/

func _parent_cv(left_child_cv, right_child_cv, key_words *[8]uint32, flags uint32, out *[8]uint32) {
	var o output = _parent_output(left_child_cv, right_child_cv, key_words, flags)
	_output_chaining_value(&o, out)
}

/*
inline static void hasher_init_internal(blake3_hasher *self,
                                        const uint32_t key_words[8],
                                        uint32_t flags) {
  chunk_state_init(&self->chunk_state, key_words, 0, flags);
  memcpy(self->key_words, key_words, sizeof(self->key_words));
  self->cv_stack_len = 0;
  self->flags = flags;
}
*/

func _hasher_init_internal(self *blake3_hasher, key_words *[8]uint32, flags uint32) {
	_chunk_state_init(&self.chunk_state, key_words, 0, flags)
	copy(self.key_words[:], key_words[:])
	self.cv_stack_len = 0
	self.flags = flags
}

/*
// Construct a new `Hasher` for the regular hash function.
void blake3_hasher_init(blake3_hasher *self) {
  hasher_init_internal(self, IV, 0);
}
*/

func _blake3_hasher_init(self *blake3_hasher) {
	_hasher_init_internal(self, &_IV, 0)
}

/*
// Construct a new `Hasher` for the keyed hash function.
void blake3_hasher_init_keyed(blake3_hasher *self,
                              const uint8_t key[BLAKE3_KEY_LEN]) {
  uint32_t key_words[8];
  words_from_little_endian_bytes(key, BLAKE3_KEY_LEN, key_words);
  hasher_init_internal(self, key_words, KEYED_HASH);
}
*/

func _blake3_hasher_init_keyed(self *blake3_hasher, key *[_BLAKE3_KEY_LEN]uint8) {
	var key_words [8]uint32
	_words_from_little_endian_bytes(key[:], key_words[:])
	_hasher_init_internal(self, &key_words, _KEYED_HASH)
	_wipe_uint32s(key_words[:])
}

/*
// Construct a new `Hasher` for the key derivation function. The context
// string should be hardcoded, globally unique, and application-specific.

	void blake3_hasher_init_derive_key(blake3_hasher *self, const char *context) {
		blake3_hasher context_hasher;
		hasher_init_internal(&context_hasher, IV, DERIVE_KEY_CONTEXT);
		blake3_hasher_update(&context_hasher, context, strlen(context));
		uint8_t context_key[BLAKE3_KEY_LEN];
		blake3_hasher_finalize(&context_hasher, context_key, BLAKE3_KEY_LEN);
		uint32_t context_key_words[8];
		words_from_little_endian_bytes(context_key, BLAKE3_KEY_LEN,
																	context_key_words);
		hasher_init_internal(self, context_key_words, DERIVE_KEY_MATERIAL);
	}
*/

func _blake3_hasher_init_derive_key(self *blake3_hasher, context []byte) {
	var context_key [_BLAKE3_KEY_LEN]byte
	_blake3_derive_key_calculate_context_key(context, &context_key)
	_blake3_hasher_init_derive_key_from_context_key(self, &context_key)
	_wipe_bytes(context_key[:])
}

func _blake3_derive_key_calculate_context_key(
	context []byte, // [IN]
	context_key *[_BLAKE3_KEY_LEN]byte, // [OUT]
) {
	var context_hasher blake3_hasher
	_hasher_init_internal(&context_hasher, &_IV, _DERIVE_KEY_CONTEXT)
	_blake3_hasher_update(&context_hasher, context)
	_blake3_hasher_finalize(&context_hasher, context_key[:])
	_blake3_hasher_destroy(&context_hasher)
}

func _blake3_hasher_init_derive_key_from_context_key(self *blake3_hasher, context_key *[_BLAKE3_KEY_LEN]byte) {
	var context_key_words [8]uint32
	_words_from_little_endian_bytes(context_key[:], context_key_words[:])
	_hasher_init_internal(self, &context_key_words, _DERIVE_KEY_MATERIAL)
	_wipe_uint32s(context_key_words[:])
}

/*
inline static void hasher_push_stack(blake3_hasher *self,
                                    const uint32_t cv[8]) {
  memcpy(&self->cv_stack[(size_t)self->cv_stack_len * 8], cv, 8 * 4);
  self->cv_stack_len++;
}
*/

func _hasher_push_stack(self *blake3_hasher, cv *[8]uint32) {
	copy(self.cv_stack[uint(self.cv_stack_len)*8:uint(self.cv_stack_len)*8+8], cv[:])
	self.cv_stack_len++
}

/*
// Returns a pointer to the popped CV, which is valid until the next push.
inline static const uint32_t *hasher_pop_stack(blake3_hasher *self) {
  self->cv_stack_len--;
  return &self->cv_stack[(size_t)self->cv_stack_len * 8];
}
*/

func _hasher_pop_stack(self *blake3_hasher) *[8]uint32 {
	self.cv_stack_len--
	return (*[8]uint32)(self.cv_stack[uint(self.cv_stack_len)*8:])
}

/*
// Section 5.1.2 of the BLAKE3 spec explains this algorithm in more detail.
inline static void hasher_add_chunk_cv(blake3_hasher *self, uint32_t new_cv[8],
                                      uint64_t total_chunks) {
  // This chunk might complete some subtrees. For each completed subtree, its
  // left child will be the current top entry in the CV stack, and its right
  // child will be the current value of `new_cv`. Pop each left child off the
  // stack, merge it with `new_cv`, and overwrite `new_cv` with the result.
  // After all these merges, push the final value of `new_cv` onto the stack.
  // The number of completed subtrees is given by the number of trailing 0-bits
  // in the new total number of chunks.
  while ((total_chunks & 1) == 0) {
    parent_cv(hasher_pop_stack(self), new_cv, self->key_words, self->flags,
              new_cv);
    total_chunks >>= 1;
  }
  hasher_push_stack(self, new_cv);
}
*/

func _hasher_add_chunk_cv(self *blake3_hasher, new_cv *[8]uint32, total_chunks uint64) {
	// This chunk might complete some subtrees. For each completed subtree, its
	// left child will be the current top entry in the CV stack, and its right
	// child will be the current value of `new_cv`. Pop each left child off the
	// stack, merge it with `new_cv`, and overwrite `new_cv` with the result.
	// After all these merges, push the final value of `new_cv` onto the stack.
	// The number of completed subtrees is given by the number of trailing 0-bits
	// in the new total number of chunks.
	for (total_chunks & 1) == 0 {
		_parent_cv(_hasher_pop_stack(self), new_cv, &self.key_words, self.flags, new_cv)
		total_chunks >>= 1
	}
	_hasher_push_stack(self, new_cv)
}

/*
// Add input to the hash state. This can be called any number of times.
void blake3_hasher_update(blake3_hasher *self, const void *input,
                          size_t input_len) {
  const uint8_t *input_u8 = (const uint8_t *)input;
  while (input_len > 0) {
    // If the current chunk is complete, finalize it and reset the chunk state.
    // More input is coming, so this chunk is not ROOT.
    if (chunk_state_len(&self->chunk_state) == BLAKE3_CHUNK_LEN) {
      output chunk_output = chunk_state_output(&self->chunk_state);
      uint32_t chunk_cv[8];
      output_chaining_value(&chunk_output, chunk_cv);
      uint64_t total_chunks = self->chunk_state.chunk_counter + 1;
      hasher_add_chunk_cv(self, chunk_cv, total_chunks);
      chunk_state_init(&self->chunk_state, self->key_words, total_chunks,
                      self->flags);
    }

    // Compress input bytes into the current chunk state.
    size_t want = BLAKE3_CHUNK_LEN - chunk_state_len(&self->chunk_state);
    size_t take = want;
    if (input_len < want) {
      take = input_len;
    }
    chunk_state_update(&self->chunk_state, input_u8, take);
    input_u8 += take;
    input_len -= take;
  }
}
*/

func _blake3_hasher_update(self *blake3_hasher, input []byte) {
	input_len := uint(len(input))
	var chunk_cv [8]uint32
	for input_len > 0 {
		// If the current chunk is complete, finalize it and reset the chunk state.
		// More input is coming, so this chunk is not ROOT.
		if _chunk_state_len(&self.chunk_state) == _BLAKE3_CHUNK_LEN {
			var chunk_output output = _chunk_state_output(&self.chunk_state)
			_output_chaining_value(&chunk_output, &chunk_cv)
			var total_chunks uint64 = self.chunk_state.chunk_counter + 1
			_hasher_add_chunk_cv(self, &chunk_cv, total_chunks)
			_chunk_state_init(&self.chunk_state, &self.key_words, total_chunks, self.flags)
		}

		// Compress input bytes into the current chunk state.
		var want uint = _BLAKE3_CHUNK_LEN - _chunk_state_len(&self.chunk_state)
		var take uint = want
		if input_len < want {
			take = input_len
		}
		_chunk_state_update(&self.chunk_state, input[:take])
		input = input[take:]
		input_len -= take
	}
	_wipe_uint32s(chunk_cv[:])
}

/*
// Finalize the hash and write any number of output bytes.
void blake3_hasher_finalize(const blake3_hasher *self, void *out,
                            size_t out_len) {
  // Starting with the output from the current chunk, compute all the parent
  // chaining values along the right edge of the tree, until we have the root
  // output.
  output current_output = chunk_state_output(&self->chunk_state);
  size_t parent_nodes_remaining = (size_t)self->cv_stack_len;
  while (parent_nodes_remaining > 0) {
    parent_nodes_remaining--;
    uint32_t current_cv[8];
    output_chaining_value(&current_output, current_cv);
    current_output = parent_output(&self->cv_stack[parent_nodes_remaining * 8],
                                  current_cv, self->key_words, self->flags);
  }
  output_root_bytes(&current_output, out, out_len);
}
*/

func _blake3_hasher_finalize(self *blake3_hasher, out []byte) {
	// Starting with the output from the current chunk, compute all the parent
	// chaining values along the right edge of the tree, until we have the root
	// output.
	var current_output output = _chunk_state_output(&self.chunk_state)
	var parent_nodes_remaining uint = uint(self.cv_stack_len)
	var current_cv [8]uint32
	for parent_nodes_remaining > 0 {
		parent_nodes_remaining--
		_output_chaining_value(&current_output, &current_cv)
		current_output = _parent_output((*[8]uint32)(self.cv_stack[parent_nodes_remaining*8:]), &current_cv, &self.key_words, self.flags)
	}
	_output_root_bytes(&current_output, out)
	_wipe_uint32s(current_cv[:])
}

//go:nosplit
func _wipe_bytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	_ = b
}

//go:nosplit
func _wipe_uint32s(b []uint32) {
	for i := range b {
		b[i] = 0
	}
	_ = b
}

func _blake3_hasher_destroy(self *blake3_hasher) {
	_wipe_uint32s(self.chunk_state.chaining_value[:])
	self.chunk_state.chunk_counter = 0
	_wipe_bytes(self.chunk_state.block[:])
	self.chunk_state.block_len = 0
	self.chunk_state.blocks_compressed = 0
	self.chunk_state.flags = 0

	_wipe_uint32s(self.key_words[:])
	_wipe_uint32s(self.cv_stack[:])
	self.cv_stack_len = 0
	self.flags = 0
}
