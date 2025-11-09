package kdf

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

const (
	defaultString = "default"
	legacyString  = "legacy"
	// specSeparatorParts is the number of parts when splitting KDF spec by colon.
	specSeparatorParts = 2
	// kvParts is the expected parts for key=value split.
	kvParts = 2
)

// ParseSpec parses a KDF specification string and returns the corresponding Params.
// Supported formats:
//   - "legacy" - PBKDF2 with 10,000 iterations (backward compatibility)
//   - "pbkdf2" - PBKDF2 with default parameters
//   - "pbkdf2:default" - PBKDF2 with default parameters
//   - "pbkdf2:legacy" - PBKDF2 with legacy parameters
//   - "pbkdf2:iterations=1000000" - PBKDF2 with custom iterations
//   - "pbkdf2:iterations=1000000,hash=sha512" - PBKDF2 with custom parameters
//   - "argon2" - Argon2id with default parameters
//   - "argon2:default|moderate|high" - Argon2id with preset parameters
//   - "argon2:iterations=3,memory=65536,parallelism=4" - Argon2id with custom parameters
//   - "scrypt" - Scrypt with default parameters
//   - "scrypt:default|moderate|high" - Scrypt with preset parameters
//   - "scrypt:cost=32768,blocksize=8,parallelism=1" - Scrypt with custom parameters
func ParseSpec(spec string) (Params, error) {
	if spec == "" {
		return DefaultPBKDF2Params(), nil
	}

	// Handle legacy shorthand
	if spec == legacyString {
		return LegacyPBKDF2Params(), nil
	}

	// Split type and parameters
	parts := strings.SplitN(spec, ":", specSeparatorParts)
	kdfType := strings.ToLower(parts[0])

	// Handle type-only specifications
	if len(parts) == 1 {
		return parseTypeOnly(kdfType)
	}

	// Parse parameters
	paramStr := parts[1]

	return parseWithParams(kdfType, paramStr)
}

// parseTypeOnly handles KDF specifications without parameters.
func parseTypeOnly(kdfType string) (Params, error) {
	switch kdfType {
	case "pbkdf2":
		return DefaultPBKDF2Params(), nil

	case "argon2", "argon2id":
		return DefaultArgon2idParams(), nil

	case "scrypt":
		return DefaultScryptParams(), nil

	default:
		return nil, fmt.Errorf("%w: unknown KDF type: %s", ErrInvalidParams, kdfType)
	}
}

// parseWithParams handles KDF specifications with parameters.
func parseWithParams(kdfType, paramStr string) (Params, error) {
	switch kdfType {
	case "pbkdf2":
		return parsePBKDF2Params(paramStr)

	case "argon2", "argon2id":
		return parseArgon2Params(paramStr)

	case "scrypt":
		return parseScryptParams(paramStr)

	default:
		return nil, fmt.Errorf("%w: unknown KDF type: %s", ErrInvalidParams, kdfType)
	}
}

// parsePBKDF2Params parses PBKDF2-specific parameters.
func parsePBKDF2Params(paramStr string) (Params, error) {
	// Handle presets
	switch paramStr {
	case defaultString:
		return DefaultPBKDF2Params(), nil

	case legacyString:
		return LegacyPBKDF2Params(), nil
	}

	// Parse custom parameters
	params := DefaultPBKDF2Params()
	kvPairs := parseKeyValuePairs(paramStr)

	for key, value := range kvPairs {
		if err := applyPBKDF2Param(params, key, value); err != nil {
			return nil, err
		}
	}

	return params, nil
}

// applyPBKDF2Param applies a single parameter to PBKDF2Params.
func applyPBKDF2Param(params *PBKDF2Params, key, value string) error {
	switch key {
	case "iterations":
		iterations, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("%w: invalid iterations value: %s", ErrInvalidParams, value)
		}

		params.Iterations = iterations

	case "hash":
		switch strings.ToLower(value) {
		case "sha256":
			params.HashFunc = HashTypeSHA256

		case "sha512":
			params.HashFunc = HashTypeSHA512

		default:
			return fmt.Errorf("%w: unsupported hash function: %s", ErrInvalidParams, value)
		}

	default:
		return fmt.Errorf("%w: unknown PBKDF2 parameter: %s", ErrInvalidParams, key)
	}

	return nil
}

// parseArgon2Params parses Argon2id-specific parameters.
func parseArgon2Params(paramStr string) (Params, error) {
	// Handle presets
	switch paramStr {
	case "default":
		return DefaultArgon2idParams(), nil
	case "moderate":
		return ModerateArgon2idParams(), nil
	case "high":
		return HighArgon2idParams(), nil
	}

	// Parse custom parameters
	params := DefaultArgon2idParams()
	kvPairs := parseKeyValuePairs(paramStr)

	for key, value := range kvPairs {
		if err := applyArgon2Param(params, key, value); err != nil {
			return nil, err
		}
	}

	return params, nil
}

func parseUint8(value string) (uint8, error) {
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid value: %s", ErrInvalidParams, value)
	}

	if parsed < 1 {
		return 0, fmt.Errorf("%w: value must be at least 1", ErrInvalidParams)
	}

	if parsed > math.MaxUint8 {
		return 0, fmt.Errorf(
			"%w: value exceeds maximum of %d",
			ErrInvalidParams,
			math.MaxUint8,
		)
	}

	return uint8(parsed), nil
}

func parseUint32(value string) (uint32, error) {
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid value: %s", ErrInvalidParams, value)
	}

	if parsed < 1 {
		return 0, fmt.Errorf("%w: value must be at least 1", ErrInvalidParams)
	}

	if parsed > math.MaxUint32 {
		return 0, fmt.Errorf(
			"%w: value exceeds maximum of %d",
			ErrInvalidParams,
			math.MaxUint32,
		)
	}

	return uint32(parsed), nil
}

// applyArgon2Param applies a single parameter to Argon2idParams.
func applyArgon2Param(params *Argon2idParams, key, value string) error {
	switch key {
	case "iterations", "time":
		iterations, err := parseUint32(value)
		if err != nil {
			return fmt.Errorf("invalid iterations value: %w", err)
		}

		params.Iterations = iterations

	case "memory":
		memory, err := parseUint32(value)
		if err != nil {
			return fmt.Errorf("invalid memory value: %w", err)
		}

		params.Memory = memory

	case "parallelism", "threads":
		parallelism, err := parseUint8(value)
		if err != nil {
			return fmt.Errorf("invalid parallelism value: %w", err)
		}

		params.Parallelism = parallelism

	default:
		return fmt.Errorf("%w: unknown Argon2 parameter: %s", ErrInvalidParams, key)
	}

	return nil
}

// parseScryptParams parses Scrypt-specific parameters.
func parseScryptParams(paramStr string) (Params, error) {
	// Handle presets
	switch paramStr {
	case "default":
		return DefaultScryptParams(), nil
	case "moderate":
		return ModerateScryptParams(), nil
	case "high":
		return HighScryptParams(), nil
	}

	// Parse custom parameters
	params := DefaultScryptParams()
	kvPairs := parseKeyValuePairs(paramStr)

	for key, value := range kvPairs {
		if err := applyScryptParam(params, key, value); err != nil {
			return nil, err
		}
	}

	return params, nil
}

// applyScryptParam applies a single parameter to ScryptParams.
func applyScryptParam(params *ScryptParams, key, value string) error {
	switch key {
	case "cost", "n":
		cost, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("%w: invalid cost value: %s", ErrInvalidParams, value)
		}

		params.Cost = cost

	case "blocksize", "r":
		blockSize, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("%w: invalid block size value: %s", ErrInvalidParams, value)
		}

		params.BlockSize = blockSize

	case "parallelism", "p":
		parallelism, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("%w: invalid parallelism value: %s", ErrInvalidParams, value)
		}

		params.Parallelism = parallelism

	default:
		return fmt.Errorf("%w: unknown Scrypt parameter: %s", ErrInvalidParams, key)
	}

	return nil
}

// parseKeyValuePairs parses comma-separated key=value pairs.
func parseKeyValuePairs(s string) map[string]string {
	pairs := make(map[string]string)

	for part := range strings.SplitSeq(s, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", kvParts)
		if len(kv) == kvParts {
			pairs[strings.ToLower(strings.TrimSpace(kv[0]))] = strings.TrimSpace(kv[1])
		}
	}

	return pairs
}
