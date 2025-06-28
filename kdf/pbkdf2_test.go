package kdf_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jkoelker/schwab-proxy/kdf"
)

func TestPBKDF2Params_Type(t *testing.T) {
	t.Parallel()

	params := &kdf.PBKDF2Params{}
	assert.Equal(t, kdf.TypePBKDF2, params.Type())
}

func TestPBKDF2Params_DeriveKey(t *testing.T) {
	t.Parallel()

	t.Run("ValidDerivation", func(t *testing.T) {
		t.Parallel()

		params := &kdf.PBKDF2Params{
			Iterations: 1000,
			HashFunc:   kdf.HashTypeSHA256,
		}

		password := []byte("test-password")
		salt := []byte("test-salt")
		keyLen := 32

		key, err := params.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)
		assert.Len(t, key, keyLen)
	})

	t.Run("DeterministicOutput", func(t *testing.T) {
		t.Parallel()

		params := &kdf.PBKDF2Params{
			Iterations: 1000,
			HashFunc:   kdf.HashTypeSHA256,
		}

		password := []byte("test-password")
		salt := []byte("test-salt")
		keyLen := 32

		key1, err := params.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)

		key2, err := params.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)

		assert.Equal(t, key1, key2, "same parameters should produce same key")
	})

	t.Run("DifferentIterationsProduceDifferentKeys", func(t *testing.T) {
		t.Parallel()

		password := []byte("test-password")
		salt := []byte("test-salt")
		keyLen := 32

		params1 := &kdf.PBKDF2Params{Iterations: 1000, HashFunc: kdf.HashTypeSHA256}
		key1, err := params1.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)

		params2 := &kdf.PBKDF2Params{Iterations: 2000, HashFunc: kdf.HashTypeSHA256}
		key2, err := params2.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)

		assert.NotEqual(t, key1, key2, "different iterations should produce different keys")
	})

	t.Run("DifferentHashFunctionsProduceDifferentKeys", func(t *testing.T) {
		t.Parallel()

		password := []byte("test-password")
		salt := []byte("test-salt")
		keyLen := 32

		params1 := &kdf.PBKDF2Params{Iterations: 1000, HashFunc: kdf.HashTypeSHA256}
		key1, err := params1.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)

		params2 := &kdf.PBKDF2Params{Iterations: 1000, HashFunc: kdf.HashTypeSHA512}
		key2, err := params2.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)

		assert.NotEqual(t, key1, key2, "different hash functions should produce different keys")
	})

	t.Run("EmptyHashFuncDefaultsToSHA256", func(t *testing.T) {
		t.Parallel()

		password := []byte("test-password")
		salt := []byte("test-salt")
		keyLen := 32

		params1 := &kdf.PBKDF2Params{Iterations: 1000, HashFunc: ""}
		key1, err := params1.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)

		params2 := &kdf.PBKDF2Params{Iterations: 1000, HashFunc: kdf.HashTypeSHA256}
		key2, err := params2.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)

		assert.Equal(t, key1, key2, "empty hash func should default to SHA256")
	})

	t.Run("InvalidIterations", func(t *testing.T) {
		t.Parallel()

		params := &kdf.PBKDF2Params{
			Iterations: 0,
			HashFunc:   kdf.HashTypeSHA256,
		}

		_, err := params.DeriveKey([]byte("password"), []byte("salt"), 32)
		require.ErrorIs(t, err, kdf.ErrInvalidParams)
		assert.Contains(t, err.Error(), "invalid pbkdf2 iterations")
	})

	t.Run("NegativeIterations", func(t *testing.T) {
		t.Parallel()

		params := &kdf.PBKDF2Params{
			Iterations: -1,
			HashFunc:   kdf.HashTypeSHA256,
		}

		_, err := params.DeriveKey([]byte("password"), []byte("salt"), 32)
		require.Error(t, err)
		assert.ErrorIs(t, err, kdf.ErrInvalidParams)
	})

	t.Run("UnsupportedHashFunction", func(t *testing.T) {
		t.Parallel()

		params := &kdf.PBKDF2Params{
			Iterations: 1000,
			HashFunc:   "md5",
		}

		_, err := params.DeriveKey([]byte("password"), []byte("salt"), 32)
		require.ErrorIs(t, err, kdf.ErrInvalidParams)
		assert.Contains(t, err.Error(), "unsupported hash function")
	})

	t.Run("VariableKeyLengths", func(t *testing.T) {
		t.Parallel()

		params := &kdf.PBKDF2Params{
			Iterations: 1000,
			HashFunc:   kdf.HashTypeSHA256,
		}

		password := []byte("test-password")
		salt := []byte("test-salt")

		for _, keyLen := range []int{16, 24, 32, 48, 64} {
			key, err := params.DeriveKey(password, salt, keyLen)
			require.NoError(t, err)
			assert.Len(t, key, keyLen)
		}
	})
}

func TestPBKDF2Params_Equal(t *testing.T) {
	t.Parallel()

	t.Run("EqualParams", func(t *testing.T) {
		t.Parallel()

		params1 := &kdf.PBKDF2Params{Iterations: 1000, HashFunc: kdf.HashTypeSHA256}
		params2 := &kdf.PBKDF2Params{Iterations: 1000, HashFunc: kdf.HashTypeSHA256}
		assert.True(t, params1.Equal(params2))
	})

	t.Run("DifferentIterations", func(t *testing.T) {
		t.Parallel()

		params1 := &kdf.PBKDF2Params{Iterations: 1000, HashFunc: kdf.HashTypeSHA256}
		params2 := &kdf.PBKDF2Params{Iterations: 2000, HashFunc: kdf.HashTypeSHA256}
		assert.False(t, params1.Equal(params2))
	})

	t.Run("DifferentHashFunc", func(t *testing.T) {
		t.Parallel()

		params1 := &kdf.PBKDF2Params{Iterations: 1000, HashFunc: kdf.HashTypeSHA256}
		params2 := &kdf.PBKDF2Params{Iterations: 1000, HashFunc: kdf.HashTypeSHA512}
		assert.False(t, params1.Equal(params2))
	})

	t.Run("EmptyHashFuncEqualsDefaultSHA256", func(t *testing.T) {
		t.Parallel()

		params1 := &kdf.PBKDF2Params{Iterations: 1000, HashFunc: ""}
		params2 := &kdf.PBKDF2Params{Iterations: 1000, HashFunc: kdf.HashTypeSHA256}
		assert.True(t, params1.Equal(params2))
	})

	t.Run("BothEmptyHashFunc", func(t *testing.T) {
		t.Parallel()

		params1 := &kdf.PBKDF2Params{Iterations: 1000, HashFunc: ""}
		params2 := &kdf.PBKDF2Params{Iterations: 1000, HashFunc: ""}
		assert.True(t, params1.Equal(params2))
	})

	t.Run("DifferentType", func(t *testing.T) {
		t.Parallel()

		params1 := &kdf.PBKDF2Params{Iterations: 1000, HashFunc: kdf.HashTypeSHA256}
		params2 := &kdf.Argon2idParams{Iterations: 2, Memory: 1024, Parallelism: 1}
		assert.False(t, params1.Equal(params2))
	})
}

func TestPBKDF2Params_Factories(t *testing.T) {
	t.Parallel()

	t.Run("DefaultParams", func(t *testing.T) {
		t.Parallel()

		params := kdf.DefaultPBKDF2Params()
		assert.Equal(t, 600000, params.Iterations)
		assert.Equal(t, kdf.HashTypeSHA256, params.HashFunc)

		// Should be able to derive a key
		key, err := params.DeriveKey([]byte("password"), []byte("salt"), 32)
		require.NoError(t, err)
		assert.Len(t, key, 32)
	})

	t.Run("LegacyParams", func(t *testing.T) {
		t.Parallel()

		params := kdf.LegacyPBKDF2Params()
		assert.Equal(t, 10000, params.Iterations)
		assert.Equal(t, kdf.HashTypeSHA256, params.HashFunc)

		// Should be able to derive a key
		key, err := params.DeriveKey([]byte("password"), []byte("salt"), 32)
		require.NoError(t, err)
		assert.Len(t, key, 32)
	})

	t.Run("DefaultAndLegacyProduceDifferentKeys", func(t *testing.T) {
		t.Parallel()

		password := []byte("test-password")
		salt := []byte("test-salt")
		keyLen := 32

		defaultParams := kdf.DefaultPBKDF2Params()
		defaultKey, err := defaultParams.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)

		legacyParams := kdf.LegacyPBKDF2Params()
		legacyKey, err := legacyParams.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)

		assert.NotEqual(t, defaultKey, legacyKey)
	})
}

func TestPBKDF2_KnownVectors(t *testing.T) {
	t.Parallel()

	// Test vector from RFC 6070
	t.Run("RFC6070_Vector1", func(t *testing.T) {
		t.Parallel()

		params := &kdf.PBKDF2Params{
			Iterations: 1,
			HashFunc:   kdf.HashTypeSHA256,
		}

		password := []byte("password")
		salt := []byte("salt")

		key, err := params.DeriveKey(password, salt, 32)
		require.NoError(t, err)

		// This is the expected output for PBKDF2-HMAC-SHA256 with 1 iteration
		expected := []byte{
			0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c,
			0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
			0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48,
			0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b,
		}

		assert.True(t, bytes.Equal(key, expected), "key should match known test vector")
	})
}
