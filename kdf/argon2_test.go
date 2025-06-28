package kdf_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jkoelker/schwab-proxy/kdf"
)

func TestArgon2idParams_Type(t *testing.T) {
	t.Parallel()

	params := &kdf.Argon2idParams{}
	assert.Equal(t, kdf.TypeArgon2id, params.Type())
}

func TestArgon2idParams_DeriveKey(t *testing.T) {
	t.Parallel()

	t.Run("ValidDerivation", func(t *testing.T) {
		t.Parallel()

		params := &kdf.Argon2idParams{
			Iterations:  1,
			Memory:      64,
			Parallelism: 1,
		}

		password := []byte("test-password")
		salt := []byte("test-salt-16bytes") // Argon2 requires at least 8 bytes of salt
		keyLen := 32

		key, err := params.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)
		assert.Len(t, key, keyLen)
	})

	t.Run("DeterministicOutput", func(t *testing.T) {
		t.Parallel()

		params := &kdf.Argon2idParams{
			Iterations:  1,
			Memory:      64,
			Parallelism: 1,
		}

		password := []byte("test-password")
		salt := []byte("test-salt-16bytes")
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
		salt := []byte("test-salt-16bytes")
		keyLen := 32

		params1 := &kdf.Argon2idParams{Iterations: 1, Memory: 64, Parallelism: 1}
		key1, err := params1.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)

		params2 := &kdf.Argon2idParams{Iterations: 2, Memory: 64, Parallelism: 1}
		key2, err := params2.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)

		assert.NotEqual(t, key1, key2, "different iterations should produce different keys")
	})

	t.Run("DifferentMemoryProduceDifferentKeys", func(t *testing.T) {
		t.Parallel()

		password := []byte("test-password")
		salt := []byte("test-salt-16bytes")
		keyLen := 32

		params1 := &kdf.Argon2idParams{Iterations: 1, Memory: 64, Parallelism: 1}
		key1, err := params1.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)

		params2 := &kdf.Argon2idParams{Iterations: 1, Memory: 128, Parallelism: 1}
		key2, err := params2.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)

		assert.NotEqual(t, key1, key2, "different memory should produce different keys")
	})

	t.Run("DifferentParallelismProduceDifferentKeys", func(t *testing.T) {
		t.Parallel()

		password := []byte("test-password")
		salt := []byte("test-salt-16bytes")
		keyLen := 32

		params1 := &kdf.Argon2idParams{Iterations: 1, Memory: 64, Parallelism: 1}
		key1, err := params1.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)

		params2 := &kdf.Argon2idParams{Iterations: 1, Memory: 64, Parallelism: 2}
		key2, err := params2.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)

		assert.NotEqual(t, key1, key2, "different parallelism should produce different keys")
	})

	t.Run("InvalidIterations", func(t *testing.T) {
		t.Parallel()

		params := &kdf.Argon2idParams{
			Iterations:  0,
			Memory:      64,
			Parallelism: 1,
		}

		_, err := params.DeriveKey([]byte("password"), []byte("salt16bytes"), 32)
		require.ErrorIs(t, err, kdf.ErrInvalidParams)
		assert.Contains(t, err.Error(), "invalid argon2id iterations")
	})

	t.Run("InvalidMemory", func(t *testing.T) {
		t.Parallel()

		params := &kdf.Argon2idParams{
			Iterations:  1,
			Memory:      0,
			Parallelism: 1,
		}

		_, err := params.DeriveKey([]byte("password"), []byte("salt16bytes"), 32)
		require.ErrorIs(t, err, kdf.ErrInvalidParams)
		assert.Contains(t, err.Error(), "invalid argon2id memory")
	})

	t.Run("InvalidParallelism", func(t *testing.T) {
		t.Parallel()

		params := &kdf.Argon2idParams{
			Iterations:  1,
			Memory:      64,
			Parallelism: 0,
		}

		_, err := params.DeriveKey([]byte("password"), []byte("salt16bytes"), 32)
		require.ErrorIs(t, err, kdf.ErrInvalidParams)
		assert.Contains(t, err.Error(), "invalid argon2id parallelism")
	})

	t.Run("InvalidKeyLength", func(t *testing.T) {
		t.Parallel()

		params := &kdf.Argon2idParams{
			Iterations:  1,
			Memory:      64,
			Parallelism: 1,
		}

		_, err := params.DeriveKey([]byte("password"), []byte("salt16bytes"), 0)
		require.ErrorIs(t, err, kdf.ErrInvalidParams)
		assert.Contains(t, err.Error(), "invalid argon2id key length")
	})

	t.Run("KeyLengthTooLarge", func(t *testing.T) {
		t.Parallel()

		params := &kdf.Argon2idParams{
			Iterations:  1,
			Memory:      64,
			Parallelism: 1,
		}

		_, err := params.DeriveKey([]byte("password"), []byte("salt16bytes"), 1025)
		require.ErrorIs(t, err, kdf.ErrInvalidParams)
		assert.Contains(t, err.Error(), "invalid argon2id key length")
	})

	t.Run("VariableKeyLengths", func(t *testing.T) {
		t.Parallel()

		params := &kdf.Argon2idParams{
			Iterations:  1,
			Memory:      64,
			Parallelism: 1,
		}

		password := []byte("test-password")
		salt := []byte("test-salt-16bytes")

		for _, keyLen := range []int{16, 24, 32, 48, 64, 128} {
			key, err := params.DeriveKey(password, salt, keyLen)
			require.NoError(t, err)
			assert.Len(t, key, keyLen)
		}
	})
}

func TestArgon2idParams_Equal(t *testing.T) {
	t.Parallel()

	t.Run("EqualParams", func(t *testing.T) {
		t.Parallel()

		params1 := &kdf.Argon2idParams{Iterations: 2, Memory: 1024, Parallelism: 1}
		params2 := &kdf.Argon2idParams{Iterations: 2, Memory: 1024, Parallelism: 1}
		assert.True(t, params1.Equal(params2))
	})

	t.Run("DifferentIterations", func(t *testing.T) {
		t.Parallel()

		params1 := &kdf.Argon2idParams{Iterations: 2, Memory: 1024, Parallelism: 1}
		params2 := &kdf.Argon2idParams{Iterations: 3, Memory: 1024, Parallelism: 1}
		assert.False(t, params1.Equal(params2))
	})

	t.Run("DifferentMemory", func(t *testing.T) {
		t.Parallel()

		params1 := &kdf.Argon2idParams{Iterations: 2, Memory: 1024, Parallelism: 1}
		params2 := &kdf.Argon2idParams{Iterations: 2, Memory: 2048, Parallelism: 1}
		assert.False(t, params1.Equal(params2))
	})

	t.Run("DifferentParallelism", func(t *testing.T) {
		t.Parallel()

		params1 := &kdf.Argon2idParams{Iterations: 2, Memory: 1024, Parallelism: 1}
		params2 := &kdf.Argon2idParams{Iterations: 2, Memory: 1024, Parallelism: 2}
		assert.False(t, params1.Equal(params2))
	})

	t.Run("DifferentType", func(t *testing.T) {
		t.Parallel()

		params1 := &kdf.Argon2idParams{Iterations: 2, Memory: 1024, Parallelism: 1}
		params2 := &kdf.PBKDF2Params{Iterations: 1000, HashFunc: kdf.HashTypeSHA256}
		assert.False(t, params1.Equal(params2))
	})
}

func TestArgon2idParams_Factories(t *testing.T) {
	t.Parallel()

	t.Run("DefaultParams", func(t *testing.T) {
		t.Parallel()

		params := kdf.DefaultArgon2idParams()
		assert.Equal(t, uint32(2), params.Iterations)
		assert.Equal(t, uint32(19*1024), params.Memory)
		assert.Equal(t, uint8(1), params.Parallelism)

		// Should be able to derive a key
		key, err := params.DeriveKey([]byte("password"), []byte("salt16bytes"), 32)
		require.NoError(t, err)
		assert.Len(t, key, 32)
	})

	t.Run("ModerateParams", func(t *testing.T) {
		t.Parallel()

		params := kdf.ModerateArgon2idParams()
		assert.Equal(t, uint32(3), params.Iterations)
		assert.Equal(t, uint32(64*1024), params.Memory)
		assert.Equal(t, uint8(4), params.Parallelism)

		// Should be able to derive a key
		key, err := params.DeriveKey([]byte("password"), []byte("salt16bytes"), 32)
		require.NoError(t, err)
		assert.Len(t, key, 32)
	})

	t.Run("HighParams", func(t *testing.T) {
		t.Parallel()

		params := kdf.HighArgon2idParams()
		assert.Equal(t, uint32(4), params.Iterations)
		assert.Equal(t, uint32(128*1024), params.Memory)
		assert.Equal(t, uint8(8), params.Parallelism)

		// Should be able to derive a key
		key, err := params.DeriveKey([]byte("password"), []byte("salt16bytes"), 32)
		require.NoError(t, err)
		assert.Len(t, key, 32)
	})

	t.Run("DifferentSecurityLevelsProduceDifferentKeys", func(t *testing.T) {
		t.Parallel()

		password := []byte("test-password")
		salt := []byte("test-salt-16bytes")
		keyLen := 32

		defaultParams := kdf.DefaultArgon2idParams()
		defaultKey, err := defaultParams.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)

		moderateParams := kdf.ModerateArgon2idParams()
		moderateKey, err := moderateParams.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)

		highParams := kdf.HighArgon2idParams()
		highKey, err := highParams.DeriveKey(password, salt, keyLen)
		require.NoError(t, err)

		assert.NotEqual(t, defaultKey, moderateKey)
		assert.NotEqual(t, defaultKey, highKey)
		assert.NotEqual(t, moderateKey, highKey)
	})
}
