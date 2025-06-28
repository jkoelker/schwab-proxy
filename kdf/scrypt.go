package kdf

import (
	"fmt"

	"golang.org/x/crypto/scrypt"
)

const (
	// defaultScryptCost is the default CPU/memory cost for Scrypt.
	defaultScryptCost = 32768 // 2^15
	// defaultScryptBlockSize is the default block size for Scrypt.
	defaultScryptBlockSize = 8
	// defaultScryptParallelism is the default parallelization factor for Scrypt.
	defaultScryptParallelism = 1

	// moderateScryptCost is the moderate CPU/memory cost for Scrypt.
	moderateScryptCost = 65536 // 2^16
	// moderateScryptBlockSize is the moderate block size for Scrypt.
	moderateScryptBlockSize = 8
	// moderateScryptParallelism is the moderate parallelization factor for Scrypt.
	moderateScryptParallelism = 2

	// highScryptCost is the high CPU/memory cost for Scrypt.
	highScryptCost = 1048576 // 2^20
	// highScryptBlockSize is the high block size for Scrypt.
	highScryptBlockSize = 8
	// highScryptParallelism is the high parallelization factor for Scrypt.
	highScryptParallelism = 1
)

// ScryptParams holds parameters for Scrypt key derivation.
type ScryptParams struct {
	Cost        int `json:"cost"`        // CPU/memory cost parameter (N, must be power of 2)
	BlockSize   int `json:"block_size"`  // Block size parameter (r)
	Parallelism int `json:"parallelism"` // Parallelization parameter (p)
}

// Type returns the KDF type for Scrypt.
func (p *ScryptParams) Type() Type {
	return TypeScrypt
}

// DeriveKey derives a key using Scrypt.
func (p *ScryptParams) DeriveKey(password, salt []byte, keyLen int) ([]byte, error) {
	// Validate parameters
	if p.Cost <= 1 || p.Cost&(p.Cost-1) != 0 {
		return nil, fmt.Errorf(
			"%w: invalid scrypt cost (must be power of 2): %d",
			ErrInvalidParams,
			p.Cost,
		)
	}

	if p.BlockSize <= 0 {
		return nil, fmt.Errorf("%w: invalid scrypt block size: %d", ErrInvalidParams, p.BlockSize)
	}

	if p.Parallelism <= 0 {
		return nil, fmt.Errorf("%w: invalid scrypt parallelism: %d", ErrInvalidParams, p.Parallelism)
	}

	if keyLen <= 0 || keyLen > 1024 {
		return nil, fmt.Errorf(
			"%w: invalid key length: %d (must be >0 and <=1024)",
			ErrInvalidParams,
			keyLen,
		)
	}

	// Check that cost, blockSize, parallelism don't exceed limits (from scrypt package)
	// cost*blockSize*parallelism must be < 2^30 and blockSize*parallelism < 2^30
	if p.Cost > 1<<30/p.BlockSize/p.Parallelism {
		return nil, fmt.Errorf("%w: scrypt parameters too large", ErrInvalidParams)
	}

	key, err := scrypt.Key(password, salt, p.Cost, p.BlockSize, p.Parallelism, keyLen)
	if err != nil {
		return nil, fmt.Errorf("scrypt key derivation failed: %w", err)
	}

	return key, nil
}

// Equal checks if two Scrypt parameters are equivalent.
func (p *ScryptParams) Equal(other Params) bool {
	otherScrypt, ok := other.(*ScryptParams)
	if !ok {
		return false
	}

	return p.Cost == otherScrypt.Cost &&
		p.BlockSize == otherScrypt.BlockSize &&
		p.Parallelism == otherScrypt.Parallelism
}

// DefaultScryptParams returns default Scrypt parameters (balanced security/performance).
func DefaultScryptParams() *ScryptParams {
	return &ScryptParams{
		Cost:        defaultScryptCost,
		BlockSize:   defaultScryptBlockSize,
		Parallelism: defaultScryptParallelism,
	}
}

// ModerateScryptParams returns moderate security Scrypt parameters.
func ModerateScryptParams() *ScryptParams {
	return &ScryptParams{
		Cost:        moderateScryptCost,
		BlockSize:   moderateScryptBlockSize,
		Parallelism: moderateScryptParallelism,
	}
}

// HighScryptParams returns high security Scrypt parameters.
func HighScryptParams() *ScryptParams {
	return &ScryptParams{
		Cost:        highScryptCost,
		BlockSize:   highScryptBlockSize,
		Parallelism: highScryptParallelism,
	}
}
