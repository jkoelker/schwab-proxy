// Package kdf provides key derivation function implementations.
package kdf

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ErrInvalidParams is returned when KDF parameters are invalid.
var ErrInvalidParams = errors.New("invalid KDF parameters")

// Type represents the key derivation function type.
type Type string

const (
	// TypePBKDF2 represents PBKDF2 key derivation.
	TypePBKDF2 Type = "pbkdf2"
	// TypeArgon2id represents Argon2id key derivation.
	TypeArgon2id Type = "argon2id"
	// TypeScrypt represents Scrypt key derivation.
	TypeScrypt Type = "scrypt"
)

// Params is the interface that all KDF parameter types must implement.
type Params interface {
	// Type returns the KDF type.
	Type() Type
	// DeriveKey derives a key using the KDF parameters.
	DeriveKey(password, salt []byte, keyLen int) ([]byte, error)
	// Equal checks if two KDF parameters are equivalent.
	Equal(other Params) bool
}

// paramsWrapper is used for JSON marshaling/unmarshaling.
type paramsWrapper struct {
	Type   Type            `json:"type"`
	Params json.RawMessage `json:"params"`
}

// MarshalParams marshals KDF parameters to JSON.
func MarshalParams(params Params) ([]byte, error) {
	paramBytes, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal params: %w", err)
	}

	wrapper := paramsWrapper{
		Type:   params.Type(),
		Params: paramBytes,
	}

	data, err := json.Marshal(wrapper)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal wrapper: %w", err)
	}

	return data, nil
}

// UnmarshalParams unmarshals KDF parameters from JSON.
func UnmarshalParams(data []byte) (Params, error) {
	var wrapper paramsWrapper
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("failed to unmarshal wrapper: %w", err)
	}

	switch wrapper.Type {
	case TypePBKDF2:
		var params PBKDF2Params

		if err := json.Unmarshal(wrapper.Params, &params); err != nil {
			return nil, fmt.Errorf("failed to unmarshal pbkdf2 params: %w", err)
		}

		return &params, nil

	case TypeArgon2id:
		var params Argon2idParams

		if err := json.Unmarshal(wrapper.Params, &params); err != nil {
			return nil, fmt.Errorf("failed to unmarshal argon2id params: %w", err)
		}

		return &params, nil
	case TypeScrypt:
		var params ScryptParams

		if err := json.Unmarshal(wrapper.Params, &params); err != nil {
			return nil, fmt.Errorf("failed to unmarshal scrypt params: %w", err)
		}

		return &params, nil

	default:
		return nil, fmt.Errorf("%w: unknown KDF type: %s", ErrInvalidParams, wrapper.Type)
	}
}
