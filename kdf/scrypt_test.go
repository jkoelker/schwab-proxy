package kdf_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jkoelker/schwab-proxy/kdf"
)

func TestScryptParams_Type(t *testing.T) {
	t.Parallel()

	params := &kdf.ScryptParams{}
	assert.Equal(t, kdf.TypeScrypt, params.Type())
}

func TestScryptParams_DeriveKey(t *testing.T) {
	t.Parallel()

	t.Run("ValidDerivation", func(t *testing.T) {
		t.Parallel()

		params := &kdf.ScryptParams{
			Cost:        1024, // 2^10
			BlockSize:   8,
			Parallelism: 1,
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

		params := &kdf.ScryptParams{
			Cost:        1024,
			BlockSize:   8,
			Parallelism: 1,
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

	t.Run("DifferentCostProduceDifferentKeys", func(t *testing.T) {
		t.Parallel()

		password := []byte("test-password")
		salt := []byte("test-salt")
		keyLen := 32

		params1 := &kdf.ScryptParams{Cost: 1024, BlockSize: 8, Parallelism: 1}
		key1, err := params1.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)

		params2 := &kdf.ScryptParams{Cost: 2048, BlockSize: 8, Parallelism: 1}
		key2, err := params2.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)

		assert.NotEqual(t, key1, key2, "different cost should produce different keys")
	})

	t.Run("DifferentBlockSizeProduceDifferentKeys", func(t *testing.T) {
		t.Parallel()

		password := []byte("test-password")
		salt := []byte("test-salt")
		keyLen := 32

		params1 := &kdf.ScryptParams{Cost: 1024, BlockSize: 8, Parallelism: 1}
		key1, err := params1.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)

		params2 := &kdf.ScryptParams{Cost: 1024, BlockSize: 16, Parallelism: 1}
		key2, err := params2.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)

		assert.NotEqual(t, key1, key2, "different block size should produce different keys")
	})

	t.Run("DifferentParallelismProduceDifferentKeys", func(t *testing.T) {
		t.Parallel()

		password := []byte("test-password")
		salt := []byte("test-salt")
		keyLen := 32

		params1 := &kdf.ScryptParams{Cost: 1024, BlockSize: 8, Parallelism: 1}
		key1, err := params1.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)

		params2 := &kdf.ScryptParams{Cost: 1024, BlockSize: 8, Parallelism: 2}
		key2, err := params2.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)

		assert.NotEqual(t, key1, key2, "different parallelism should produce different keys")
	})

	t.Run("InvalidCostNotPowerOfTwo", func(t *testing.T) {
		t.Parallel()

		params := &kdf.ScryptParams{
			Cost:        1023, // Not power of 2
			BlockSize:   8,
			Parallelism: 1,
		}

		_, err := params.DeriveKey([]byte("password"), []byte("salt"), 32)
		require.ErrorIs(t, err, kdf.ErrInvalidParams)
		assert.Contains(t, err.Error(), "must be power of 2")
	})

	t.Run("InvalidCostZero", func(t *testing.T) {
		t.Parallel()

		params := &kdf.ScryptParams{
			Cost:        0,
			BlockSize:   8,
			Parallelism: 1,
		}

		_, err := params.DeriveKey([]byte("password"), []byte("salt"), 32)
		require.ErrorIs(t, err, kdf.ErrInvalidParams)
		assert.Contains(t, err.Error(), "must be power of 2")
	})

	t.Run("InvalidCostOne", func(t *testing.T) {
		t.Parallel()

		params := &kdf.ScryptParams{
			Cost:        1,
			BlockSize:   8,
			Parallelism: 1,
		}

		_, err := params.DeriveKey([]byte("password"), []byte("salt"), 32)
		require.ErrorIs(t, err, kdf.ErrInvalidParams)
		assert.Contains(t, err.Error(), "must be power of 2")
	})

	t.Run("InvalidBlockSize", func(t *testing.T) {
		t.Parallel()

		params := &kdf.ScryptParams{
			Cost:        1024,
			BlockSize:   0,
			Parallelism: 1,
		}

		_, err := params.DeriveKey([]byte("password"), []byte("salt"), 32)
		require.ErrorIs(t, err, kdf.ErrInvalidParams)
		assert.Contains(t, err.Error(), "invalid scrypt block size")
	})

	t.Run("InvalidParallelism", func(t *testing.T) {
		t.Parallel()

		params := &kdf.ScryptParams{
			Cost:        1024,
			BlockSize:   8,
			Parallelism: 0,
		}

		_, err := params.DeriveKey([]byte("password"), []byte("salt"), 32)
		require.ErrorIs(t, err, kdf.ErrInvalidParams)
		assert.Contains(t, err.Error(), "invalid scrypt parallelism")
	})

	t.Run("InvalidKeyLength", func(t *testing.T) {
		t.Parallel()

		params := &kdf.ScryptParams{
			Cost:        1024,
			BlockSize:   8,
			Parallelism: 1,
		}

		_, err := params.DeriveKey([]byte("password"), []byte("salt"), 0)
		require.ErrorIs(t, err, kdf.ErrInvalidParams)
		assert.Contains(t, err.Error(), "invalid key length")
	})

	t.Run("KeyLengthTooLarge", func(t *testing.T) {
		t.Parallel()

		params := &kdf.ScryptParams{
			Cost:        1024,
			BlockSize:   8,
			Parallelism: 1,
		}

		_, err := params.DeriveKey([]byte("password"), []byte("salt"), 1025)
		require.ErrorIs(t, err, kdf.ErrInvalidParams)
		assert.Contains(t, err.Error(), "invalid key length")
	})

	t.Run("ParametersTooLarge", func(t *testing.T) {
		t.Parallel()

		params := &kdf.ScryptParams{
			Cost:        1 << 20, // Very large
			BlockSize:   1024,    // Very large
			Parallelism: 64,      // Very large
		}

		_, err := params.DeriveKey([]byte("password"), []byte("salt"), 32)
		require.ErrorIs(t, err, kdf.ErrInvalidParams)
		assert.Contains(t, err.Error(), "parameters too large")
	})

	t.Run("VariableKeyLengths", func(t *testing.T) {
		t.Parallel()

		params := &kdf.ScryptParams{
			Cost:        1024,
			BlockSize:   8,
			Parallelism: 1,
		}

		password := []byte("test-password")
		salt := []byte("test-salt")

		for _, keyLen := range []int{16, 24, 32, 48, 64} {
			key, err := params.DeriveKey(password, salt, keyLen)
			require.NoError(t, err)
			assert.Len(t, key, keyLen)
		}
	})

	t.Run("ValidPowersOfTwo", func(t *testing.T) {
		t.Parallel()

		password := []byte("test-password")
		salt := []byte("test-salt")
		keyLen := 32

		// Test various valid powers of 2
		for _, cost := range []int{2, 4, 8, 16, 32, 64, 128, 256, 512, 1024} {
			params := &kdf.ScryptParams{
				Cost:        cost,
				BlockSize:   8,
				Parallelism: 1,
			}

			key, err := params.DeriveKey(password, salt, keyLen)
			require.NoError(t, err, "cost %d should be valid", cost)
			assert.Len(t, key, keyLen)
		}
	})
}

func TestScryptParams_Equal(t *testing.T) {
	t.Parallel()

	t.Run("EqualParams", func(t *testing.T) {
		t.Parallel()

		params1 := &kdf.ScryptParams{Cost: 16384, BlockSize: 8, Parallelism: 1}
		params2 := &kdf.ScryptParams{Cost: 16384, BlockSize: 8, Parallelism: 1}
		assert.True(t, params1.Equal(params2))
	})

	t.Run("DifferentCost", func(t *testing.T) {
		t.Parallel()

		params1 := &kdf.ScryptParams{Cost: 16384, BlockSize: 8, Parallelism: 1}
		params2 := &kdf.ScryptParams{Cost: 32768, BlockSize: 8, Parallelism: 1}
		assert.False(t, params1.Equal(params2))
	})

	t.Run("DifferentBlockSize", func(t *testing.T) {
		t.Parallel()

		params1 := &kdf.ScryptParams{Cost: 16384, BlockSize: 8, Parallelism: 1}
		params2 := &kdf.ScryptParams{Cost: 16384, BlockSize: 16, Parallelism: 1}
		assert.False(t, params1.Equal(params2))
	})

	t.Run("DifferentParallelism", func(t *testing.T) {
		t.Parallel()

		params1 := &kdf.ScryptParams{Cost: 16384, BlockSize: 8, Parallelism: 1}
		params2 := &kdf.ScryptParams{Cost: 16384, BlockSize: 8, Parallelism: 2}
		assert.False(t, params1.Equal(params2))
	})

	t.Run("DifferentType", func(t *testing.T) {
		t.Parallel()

		params1 := &kdf.ScryptParams{Cost: 16384, BlockSize: 8, Parallelism: 1}
		params2 := &kdf.PBKDF2Params{Iterations: 1000, HashFunc: kdf.HashTypeSHA256}
		assert.False(t, params1.Equal(params2))
	})
}

func TestScryptParams_Factories(t *testing.T) {
	t.Parallel()

	t.Run("DefaultParams", func(t *testing.T) {
		t.Parallel()

		params := kdf.DefaultScryptParams()
		assert.Equal(t, 32768, params.Cost)
		assert.Equal(t, 8, params.BlockSize)
		assert.Equal(t, 1, params.Parallelism)

		// Should be able to derive a key
		key, err := params.DeriveKey([]byte("password"), []byte("salt"), 32)
		require.NoError(t, err)
		assert.Len(t, key, 32)
	})

	t.Run("ModerateParams", func(t *testing.T) {
		t.Parallel()

		params := kdf.ModerateScryptParams()
		assert.Equal(t, 65536, params.Cost)
		assert.Equal(t, 8, params.BlockSize)
		assert.Equal(t, 2, params.Parallelism)

		// Should be able to derive a key
		key, err := params.DeriveKey([]byte("password"), []byte("salt"), 32)
		require.NoError(t, err)
		assert.Len(t, key, 32)
	})

	t.Run("HighParams", func(t *testing.T) {
		t.Parallel()

		params := kdf.HighScryptParams()
		assert.Equal(t, 1048576, params.Cost)
		assert.Equal(t, 8, params.BlockSize)
		assert.Equal(t, 1, params.Parallelism)

		// Note: This might be slow on some systems
		key, err := params.DeriveKey([]byte("password"), []byte("salt"), 32)
		require.NoError(t, err)
		assert.Len(t, key, 32)
	})

	t.Run("DifferentSecurityLevelsProduceDifferentKeys", func(t *testing.T) {
		t.Parallel()

		password := []byte("test-password")
		salt := []byte("test-salt")
		keyLen := 32

		defaultParams := kdf.DefaultScryptParams()
		defaultKey, err := defaultParams.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)

		moderateParams := kdf.ModerateScryptParams()
		moderateKey, err := moderateParams.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)

		// Skip high params for this test as it's slow
		assert.NotEqual(t, defaultKey, moderateKey)
	})
}
