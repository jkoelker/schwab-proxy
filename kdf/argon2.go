package kdf

import (
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	// defaultArgon2idIterations is the default number of iterations.
	defaultArgon2idIterations = 2
	// defaultArgon2idMemory in KiB (19 MiB).
	defaultArgon2idMemory = 19 * 1024
	// defaultArgon2idParallelism in threads.
	defaultArgon2idParallelism = 1

	// moderateArgon2idIterations is the moderate number of iterations.
	moderateArgon2idIterations = 3
	// moderateArgon2idMemory in KiB (64 MiB).
	moderateArgon2idMemory = 64 * 1024
	// moderateArgon2idParallelism in threads.
	moderateArgon2idParallelism = 4

	// highArgon2idIterations is the high number of iterations.
	highArgon2idIterations = 4
	// highArgon2idMemory in KiB (128 MiB).
	highArgon2idMemory = 128 * 1024
	// highArgon2idParallelism in threads.
	highArgon2idParallelism = 8
)

// Argon2idParams holds parameters for Argon2id key derivation.
type Argon2idParams struct {
	Iterations  uint32 `json:"iterations"`  // Number of iterations
	Memory      uint32 `json:"memory"`      // Memory in KiB
	Parallelism uint8  `json:"parallelism"` // Degree of parallelism
}

// Type returns the KDF type for Argon2id.
func (p *Argon2idParams) Type() Type {
	return TypeArgon2id
}

// DeriveKey derives a key using Argon2id.
func (p *Argon2idParams) DeriveKey(password, salt []byte, keyLen int) ([]byte, error) {
	// Validate parameters
	if p.Iterations == 0 {
		return nil, fmt.Errorf("%w: invalid argon2id iterations: %d", ErrInvalidParams, p.Iterations)
	}

	if p.Memory == 0 {
		return nil, fmt.Errorf("%w: invalid argon2id memory: %d", ErrInvalidParams, p.Memory)
	}

	if p.Parallelism == 0 {
		return nil, fmt.Errorf(
			"%w: invalid argon2id parallelism: %d",
			ErrInvalidParams,
			p.Parallelism,
		)
	}

	if keyLen <= 0 || keyLen > 1024 {
		return nil, fmt.Errorf("%w: invalid argon2id key length: %d", ErrInvalidParams, keyLen)
	}

	return argon2.IDKey(password, salt, p.Iterations, p.Memory, p.Parallelism, uint32(keyLen)), nil
}

// Equal checks if two Argon2id parameters are equivalent.
func (p *Argon2idParams) Equal(other Params) bool {
	otherArgon2, ok := other.(*Argon2idParams)
	if !ok {
		return false
	}

	return p.Iterations == otherArgon2.Iterations &&
		p.Memory == otherArgon2.Memory &&
		p.Parallelism == otherArgon2.Parallelism
}

// DefaultArgon2idParams returns default Argon2id parameters (OWASP 2023 recommendation).
func DefaultArgon2idParams() *Argon2idParams {
	return &Argon2idParams{
		Iterations:  defaultArgon2idIterations,
		Memory:      defaultArgon2idMemory,
		Parallelism: defaultArgon2idParallelism,
	}
}

// ModerateArgon2idParams returns moderate security Argon2id parameters.
func ModerateArgon2idParams() *Argon2idParams {
	return &Argon2idParams{
		Iterations:  moderateArgon2idIterations,
		Memory:      moderateArgon2idMemory,
		Parallelism: moderateArgon2idParallelism,
	}
}

// HighArgon2idParams returns high security Argon2id parameters.
func HighArgon2idParams() *Argon2idParams {
	return &Argon2idParams{
		Iterations:  highArgon2idIterations,
		Memory:      highArgon2idMemory,
		Parallelism: highArgon2idParallelism,
	}
}
