package kdf_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jkoelker/schwab-proxy/kdf"
)

func TestMarshalUnmarshalParams(t *testing.T) {
	t.Parallel()

	t.Run("PBKDF2", func(t *testing.T) {
		t.Parallel()

		original := &kdf.PBKDF2Params{
			Iterations: 100000,
			HashFunc:   kdf.HashTypeSHA256,
		}

		data, err := kdf.MarshalParams(original)
		require.NoError(t, err)
		require.NotEmpty(t, data)

		unmarshaled, err := kdf.UnmarshalParams(data)
		require.NoError(t, err)
		require.NotNil(t, unmarshaled)

		pbkdf2Params, ok := unmarshaled.(*kdf.PBKDF2Params)
		require.True(t, ok, "expected *PBKDF2Params type")
		assert.Equal(t, original.Iterations, pbkdf2Params.Iterations)
		assert.Equal(t, original.HashFunc, pbkdf2Params.HashFunc)
	})

	t.Run("Argon2id", func(t *testing.T) {
		t.Parallel()

		original := &kdf.Argon2idParams{
			Iterations:  3,
			Memory:      64 * 1024,
			Parallelism: 4,
		}

		data, err := kdf.MarshalParams(original)
		require.NoError(t, err)
		require.NotEmpty(t, data)

		unmarshaled, err := kdf.UnmarshalParams(data)
		require.NoError(t, err)
		require.NotNil(t, unmarshaled)

		argon2Params, ok := unmarshaled.(*kdf.Argon2idParams)
		require.True(t, ok, "expected *Argon2idParams type")
		assert.Equal(t, original.Iterations, argon2Params.Iterations)
		assert.Equal(t, original.Memory, argon2Params.Memory)
		assert.Equal(t, original.Parallelism, argon2Params.Parallelism)
	})

	t.Run("Scrypt", func(t *testing.T) {
		t.Parallel()

		original := &kdf.ScryptParams{
			Cost:        16384,
			BlockSize:   8,
			Parallelism: 1,
		}

		data, err := kdf.MarshalParams(original)
		require.NoError(t, err)
		require.NotEmpty(t, data)

		unmarshaled, err := kdf.UnmarshalParams(data)
		require.NoError(t, err)
		require.NotNil(t, unmarshaled)

		scryptParams, ok := unmarshaled.(*kdf.ScryptParams)
		require.True(t, ok, "expected *ScryptParams type")
		assert.Equal(t, original.Cost, scryptParams.Cost)
		assert.Equal(t, original.BlockSize, scryptParams.BlockSize)
		assert.Equal(t, original.Parallelism, scryptParams.Parallelism)
	})

	t.Run("UnknownType", func(t *testing.T) {
		t.Parallel()

		invalidJSON := `{"type":"unknown","params":{}}`
		_, err := kdf.UnmarshalParams([]byte(invalidJSON))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown KDF type")
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		t.Parallel()

		_, err := kdf.UnmarshalParams([]byte("not json"))
		require.Error(t, err)
	})
}
