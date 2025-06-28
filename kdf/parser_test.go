package kdf_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jkoelker/schwab-proxy/kdf"
)

func TestParseSpec(t *testing.T) {
	t.Parallel()

	t.Run("EmptySpec", func(t *testing.T) {
		t.Parallel()

		params, err := kdf.ParseSpec("")
		require.NoError(t, err)
		assert.Equal(t, kdf.TypePBKDF2, params.Type())

		// Should be default PBKDF2 params
		pbkdf2Params, ok := params.(*kdf.PBKDF2Params)
		require.True(t, ok, "Expected *kdf.PBKDF2Params, got %T", params)
		assert.Equal(t, 600000, pbkdf2Params.Iterations)
		assert.Equal(t, kdf.HashTypeSHA256, pbkdf2Params.HashFunc)
	})

	t.Run("LegacyShorthand", func(t *testing.T) {
		t.Parallel()

		params, err := kdf.ParseSpec("legacy")
		require.NoError(t, err)
		assert.Equal(t, kdf.TypePBKDF2, params.Type())

		pbkdf2Params, ok := params.(*kdf.PBKDF2Params)
		require.True(t, ok)
		assert.Equal(t, 10000, pbkdf2Params.Iterations)
		assert.Equal(t, kdf.HashTypeSHA256, pbkdf2Params.HashFunc)
	})

	t.Run("PBKDF2", func(t *testing.T) {
		t.Parallel()

		t.Run("TypeOnly", func(t *testing.T) {
			t.Parallel()

			params, err := kdf.ParseSpec("pbkdf2")
			require.NoError(t, err)
			assert.Equal(t, kdf.TypePBKDF2, params.Type())

			pbkdf2Params, ok := params.(*kdf.PBKDF2Params)
			require.True(t, ok)
			assert.Equal(t, 600000, pbkdf2Params.Iterations)
			assert.Equal(t, kdf.HashTypeSHA256, pbkdf2Params.HashFunc)
		})

		t.Run("DefaultPreset", func(t *testing.T) {
			t.Parallel()

			params, err := kdf.ParseSpec("pbkdf2:default")
			require.NoError(t, err)
			assert.Equal(t, kdf.TypePBKDF2, params.Type())

			pbkdf2Params, ok := params.(*kdf.PBKDF2Params)
			require.True(t, ok)
			assert.Equal(t, 600000, pbkdf2Params.Iterations)
			assert.Equal(t, kdf.HashTypeSHA256, pbkdf2Params.HashFunc)
		})

		t.Run("LegacyPreset", func(t *testing.T) {
			t.Parallel()

			params, err := kdf.ParseSpec("pbkdf2:legacy")
			require.NoError(t, err)
			assert.Equal(t, kdf.TypePBKDF2, params.Type())

			pbkdf2Params, ok := params.(*kdf.PBKDF2Params)
			require.True(t, ok)
			assert.Equal(t, 10000, pbkdf2Params.Iterations)
			assert.Equal(t, kdf.HashTypeSHA256, pbkdf2Params.HashFunc)
		})

		t.Run("CustomIterations", func(t *testing.T) {
			t.Parallel()

			params, err := kdf.ParseSpec("pbkdf2:iterations=1000000")
			require.NoError(t, err)
			assert.Equal(t, kdf.TypePBKDF2, params.Type())

			pbkdf2Params, ok := params.(*kdf.PBKDF2Params)
			require.True(t, ok)
			assert.Equal(t, 1000000, pbkdf2Params.Iterations)
			assert.Equal(t, kdf.HashTypeSHA256, pbkdf2Params.HashFunc)
		})

		t.Run("CustomIterationsAndHash", func(t *testing.T) {
			t.Parallel()

			params, err := kdf.ParseSpec("pbkdf2:iterations=500000,hash=sha512")
			require.NoError(t, err)
			assert.Equal(t, kdf.TypePBKDF2, params.Type())

			pbkdf2Params, ok := params.(*kdf.PBKDF2Params)
			require.True(t, ok)
			assert.Equal(t, 500000, pbkdf2Params.Iterations)
			assert.Equal(t, kdf.HashTypeSHA512, pbkdf2Params.HashFunc)
		})

		t.Run("InvalidIterations", func(t *testing.T) {
			t.Parallel()

			_, err := kdf.ParseSpec("pbkdf2:iterations=notanumber")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid iterations value")
		})

		t.Run("UnsupportedHash", func(t *testing.T) {
			t.Parallel()

			_, err := kdf.ParseSpec("pbkdf2:hash=md5")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "unsupported hash function")
		})

		t.Run("UnknownParameter", func(t *testing.T) {
			t.Parallel()

			_, err := kdf.ParseSpec("pbkdf2:unknown=value")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "unknown PBKDF2 parameter")
		})
	})

	t.Run("Argon2", func(t *testing.T) {
		t.Parallel()

		t.Run("TypeOnly", func(t *testing.T) {
			t.Parallel()

			params, err := kdf.ParseSpec("argon2")
			require.NoError(t, err)
			assert.Equal(t, kdf.TypeArgon2id, params.Type())

			argon2Params, ok := params.(*kdf.Argon2idParams)
			require.True(t, ok)
			assert.Equal(t, uint32(2), argon2Params.Iterations)
			assert.Equal(t, uint32(19*1024), argon2Params.Memory)
			assert.Equal(t, uint8(1), argon2Params.Parallelism)
		})

		t.Run("Argon2idAlias", func(t *testing.T) {
			t.Parallel()

			params, err := kdf.ParseSpec("argon2id")
			require.NoError(t, err)
			assert.Equal(t, kdf.TypeArgon2id, params.Type())
		})

		t.Run("DefaultPreset", func(t *testing.T) {
			t.Parallel()

			params, err := kdf.ParseSpec("argon2:default")
			require.NoError(t, err)
			assert.Equal(t, kdf.TypeArgon2id, params.Type())

			argon2Params, ok := params.(*kdf.Argon2idParams)
			require.True(t, ok)
			assert.Equal(t, uint32(2), argon2Params.Iterations)
			assert.Equal(t, uint32(19*1024), argon2Params.Memory)
			assert.Equal(t, uint8(1), argon2Params.Parallelism)
		})

		t.Run("ModeratePreset", func(t *testing.T) {
			t.Parallel()

			params, err := kdf.ParseSpec("argon2:moderate")
			require.NoError(t, err)
			assert.Equal(t, kdf.TypeArgon2id, params.Type())

			argon2Params, ok := params.(*kdf.Argon2idParams)
			require.True(t, ok)
			assert.Equal(t, uint32(3), argon2Params.Iterations)
			assert.Equal(t, uint32(64*1024), argon2Params.Memory)
			assert.Equal(t, uint8(4), argon2Params.Parallelism)
		})

		t.Run("HighPreset", func(t *testing.T) {
			t.Parallel()

			params, err := kdf.ParseSpec("argon2:high")
			require.NoError(t, err)
			assert.Equal(t, kdf.TypeArgon2id, params.Type())

			argon2Params, ok := params.(*kdf.Argon2idParams)
			require.True(t, ok)
			assert.Equal(t, uint32(4), argon2Params.Iterations)
			assert.Equal(t, uint32(128*1024), argon2Params.Memory)
			assert.Equal(t, uint8(8), argon2Params.Parallelism)
		})

		t.Run("CustomParameters", func(t *testing.T) {
			t.Parallel()

			params, err := kdf.ParseSpec("argon2:iterations=5,memory=32768,parallelism=2")
			require.NoError(t, err)
			assert.Equal(t, kdf.TypeArgon2id, params.Type())

			argon2Params, ok := params.(*kdf.Argon2idParams)
			require.True(t, ok)
			assert.Equal(t, uint32(5), argon2Params.Iterations)
			assert.Equal(t, uint32(32768), argon2Params.Memory)
			assert.Equal(t, uint8(2), argon2Params.Parallelism)
		})

		t.Run("TimeAlias", func(t *testing.T) {
			t.Parallel()

			params, err := kdf.ParseSpec("argon2:time=3")
			require.NoError(t, err)

			argon2Params, ok := params.(*kdf.Argon2idParams)
			require.True(t, ok)
			assert.Equal(t, uint32(3), argon2Params.Iterations)
		})

		t.Run("ThreadsAlias", func(t *testing.T) {
			t.Parallel()

			params, err := kdf.ParseSpec("argon2:threads=4")
			require.NoError(t, err)

			argon2Params, ok := params.(*kdf.Argon2idParams)
			require.True(t, ok)
			assert.Equal(t, uint8(4), argon2Params.Parallelism)
		})

		t.Run("InvalidParameter", func(t *testing.T) {
			t.Parallel()

			_, err := kdf.ParseSpec("argon2:unknown=value")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "unknown Argon2 parameter")
		})
	})

	t.Run("Scrypt", func(t *testing.T) {
		t.Parallel()

		t.Run("TypeOnly", func(t *testing.T) {
			t.Parallel()

			params, err := kdf.ParseSpec("scrypt")
			require.NoError(t, err)
			assert.Equal(t, kdf.TypeScrypt, params.Type())

			scryptParams, ok := params.(*kdf.ScryptParams)
			require.True(t, ok)
			assert.Equal(t, 32768, scryptParams.Cost)
			assert.Equal(t, 8, scryptParams.BlockSize)
			assert.Equal(t, 1, scryptParams.Parallelism)
		})

		t.Run("DefaultPreset", func(t *testing.T) {
			t.Parallel()

			params, err := kdf.ParseSpec("scrypt:default")
			require.NoError(t, err)
			assert.Equal(t, kdf.TypeScrypt, params.Type())

			scryptParams, ok := params.(*kdf.ScryptParams)
			require.True(t, ok)
			assert.Equal(t, 32768, scryptParams.Cost)
			assert.Equal(t, 8, scryptParams.BlockSize)
			assert.Equal(t, 1, scryptParams.Parallelism)
		})

		t.Run("ModeratePreset", func(t *testing.T) {
			t.Parallel()

			params, err := kdf.ParseSpec("scrypt:moderate")
			require.NoError(t, err)
			assert.Equal(t, kdf.TypeScrypt, params.Type())

			scryptParams, ok := params.(*kdf.ScryptParams)
			require.True(t, ok)
			assert.Equal(t, 65536, scryptParams.Cost)
			assert.Equal(t, 8, scryptParams.BlockSize)
			assert.Equal(t, 2, scryptParams.Parallelism)
		})

		t.Run("HighPreset", func(t *testing.T) {
			t.Parallel()

			params, err := kdf.ParseSpec("scrypt:high")
			require.NoError(t, err)
			assert.Equal(t, kdf.TypeScrypt, params.Type())

			scryptParams, ok := params.(*kdf.ScryptParams)
			require.True(t, ok)
			assert.Equal(t, 1048576, scryptParams.Cost)
			assert.Equal(t, 8, scryptParams.BlockSize)
			assert.Equal(t, 1, scryptParams.Parallelism)
		})

		t.Run("CustomParameters", func(t *testing.T) {
			t.Parallel()

			params, err := kdf.ParseSpec("scrypt:cost=16384,blocksize=16,parallelism=2")
			require.NoError(t, err)
			assert.Equal(t, kdf.TypeScrypt, params.Type())

			scryptParams, ok := params.(*kdf.ScryptParams)
			require.True(t, ok)
			assert.Equal(t, 16384, scryptParams.Cost)
			assert.Equal(t, 16, scryptParams.BlockSize)
			assert.Equal(t, 2, scryptParams.Parallelism)
		})

		t.Run("ShortAliases", func(t *testing.T) {
			t.Parallel()

			params, err := kdf.ParseSpec("scrypt:n=8192,r=4,p=3")
			require.NoError(t, err)
			assert.Equal(t, kdf.TypeScrypt, params.Type())

			scryptParams, ok := params.(*kdf.ScryptParams)
			require.True(t, ok)
			assert.Equal(t, 8192, scryptParams.Cost)
			assert.Equal(t, 4, scryptParams.BlockSize)
			assert.Equal(t, 3, scryptParams.Parallelism)
		})

		t.Run("InvalidParameter", func(t *testing.T) {
			t.Parallel()

			_, err := kdf.ParseSpec("scrypt:unknown=value")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "unknown Scrypt parameter")
		})
	})

	t.Run("UnknownKDF", func(t *testing.T) {
		t.Parallel()

		_, err := kdf.ParseSpec("unknownkdf")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown KDF type")
	})

	t.Run("UnknownKDFWithParams", func(t *testing.T) {
		t.Parallel()

		_, err := kdf.ParseSpec("unknownkdf:param=value")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown KDF type")
	})

	t.Run("WhitespaceHandling", func(t *testing.T) {
		t.Parallel()

		params, err := kdf.ParseSpec("pbkdf2: iterations = 100000 , hash = sha512 ")
		require.NoError(t, err)

		pbkdf2Params, ok := params.(*kdf.PBKDF2Params)
		require.True(t, ok)
		assert.Equal(t, 100000, pbkdf2Params.Iterations)
		assert.Equal(t, kdf.HashTypeSHA512, pbkdf2Params.HashFunc)
	})

	t.Run("CaseInsensitive", func(t *testing.T) {
		t.Parallel()

		params, err := kdf.ParseSpec("PBKDF2:ITERATIONS=100000,HASH=SHA512")
		require.NoError(t, err)

		pbkdf2Params, ok := params.(*kdf.PBKDF2Params)
		require.True(t, ok)
		assert.Equal(t, 100000, pbkdf2Params.Iterations)
		assert.Equal(t, kdf.HashTypeSHA512, pbkdf2Params.HashFunc)
	})
}
