package kdf

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

type HashType string

const (
	// HashTypeSHA256 is the name for the SHA-256 hash function.
	HashTypeSHA256 HashType = "sha256"

	// HashTypeSHA512 is the name for the SHA-512 hash function.
	HashTypeSHA512 HashType = "sha512"

	// legacyIterations is the number of iterations used in legacy PBKDF2.
	legacyIterations = 10000

	// defaultIterations is the number of iterations recommended by OWASP 2023.
	defaultIterations = 600000
)

// PBKDF2Params holds parameters for PBKDF2 key derivation.
type PBKDF2Params struct {
	Iterations int      `json:"iterations"`
	HashFunc   HashType `json:"hash"` // "sha256", "sha512", etc.
}

// Type returns the KDF type for PBKDF2.
func (p *PBKDF2Params) Type() Type {
	return TypePBKDF2
}

// DeriveKey derives a key using PBKDF2.
func (p *PBKDF2Params) DeriveKey(password, salt []byte, keyLen int) ([]byte, error) {
	if p.Iterations <= 0 {
		return nil, fmt.Errorf("%w: invalid pbkdf2 iterations: %d", ErrInvalidParams, p.Iterations)
	}

	// Select hash function
	hashFunc, err := p.getHashFunc()
	if err != nil {
		return nil, err
	}

	return pbkdf2.Key(password, salt, p.Iterations, keyLen, hashFunc), nil
}

// Equal checks if two PBKDF2 parameters are equivalent.
func (p *PBKDF2Params) Equal(other Params) bool {
	otherPBKDF2, ok := other.(*PBKDF2Params)
	if !ok {
		return false
	}

	// Normalize empty hash func to sha256
	thisHash := p.HashFunc
	if thisHash == "" {
		thisHash = HashTypeSHA256
	}

	otherHash := otherPBKDF2.HashFunc
	if otherHash == "" {
		otherHash = HashTypeSHA256
	}

	return p.Iterations == otherPBKDF2.Iterations && thisHash == otherHash
}

// getHashFunc returns the hash function for PBKDF2.
func (p *PBKDF2Params) getHashFunc() (func() hash.Hash, error) {
	switch p.HashFunc {
	case "", HashTypeSHA256:
		return sha256.New, nil

	case HashTypeSHA512:
		return sha512.New, nil

	default:
		return nil, fmt.Errorf("%w: unsupported hash function: %s", ErrInvalidParams, p.HashFunc)
	}
}

// DefaultPBKDF2Params returns default PBKDF2 parameters (OWASP 2023 recommendation).
func DefaultPBKDF2Params() *PBKDF2Params {
	return &PBKDF2Params{
		Iterations: defaultIterations,
		HashFunc:   HashTypeSHA256,
	}
}

// LegacyPBKDF2Params returns legacy PBKDF2 parameters for migration.
func LegacyPBKDF2Params() *PBKDF2Params {
	return &PBKDF2Params{
		Iterations: legacyIterations,
		HashFunc:   HashTypeSHA256,
	}
}
