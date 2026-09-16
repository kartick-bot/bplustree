package bptree

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

// ============================================================
// LEAF FIELD MAPPER
// ============================================================

// FieldMapper maps a leaf entry:
//
//     (key, value)
//
// where:
//
//     value = H(key)
//
// into one element of Z_p.
type FieldMapper[K any] func(
	key K,
	value [32]byte,
	p *big.Int,
) (*big.Int, error)

// ============================================================
// INTERNAL NODE FIELD MAPPER
// ============================================================

// InternalFieldMapper maps one internal-node entry:
//
//     (key, LPC, RPC)
//
// into one element of Z_p.
type InternalFieldMapper[K any] func(
	key K,
	lpc *kzg.Digest,
	rpc *kzg.Digest,
	p *big.Int,
) (*big.Int, error)

// ============================================================
// BN254 SCALAR FIELD MODULUS
// ============================================================

func BN254ScalarModulus() *big.Int {

	p, ok := new(big.Int).SetString(
		"21888242871839275222246405745257275088548364400416034343698204186575808495617",
		10,
	)

	if !ok {
		panic("failed to parse BN254 scalar modulus")
	}

	return p
}

// ============================================================
// LEAF ENTRY -> Z_p
// ============================================================
//
// Maps:
//
//     (key, H(key))
//
// to:
//
//     SHA256(
//         "BPLUS-LEAF-ENTRY"
//         || encode(key)
//         || H(key)
//     ) mod p
//
func MapIntEntryToField(
	key int,
	value [32]byte,
	p *big.Int,
) (*big.Int, error) {

	if p == nil {
		return nil, fmt.Errorf(
			"field modulus is nil",
		)
	}

	if p.Sign() <= 0 {
		return nil, fmt.Errorf(
			"field modulus must be positive",
		)
	}

	// ------------------------------------------------------------
	// Encode key as 8-byte big-endian integer
	// ------------------------------------------------------------

	var keyBytes [8]byte

	binary.BigEndian.PutUint64(
		keyBytes[:],
		uint64(key),
	)

	// ------------------------------------------------------------
	// Domain-separated SHA-256
	// ------------------------------------------------------------

	h := sha256.New()

	h.Write(
		[]byte("BPLUS-LEAF-ENTRY"),
	)

	h.Write(
		keyBytes[:],
	)

	h.Write(
		value[:],
	)

	digest := h.Sum(nil)

	// ------------------------------------------------------------
	// Convert digest to integer and reduce mod p
	// ------------------------------------------------------------

	mapped :=
		new(big.Int).SetBytes(
			digest,
		)

	mapped.Mod(
		mapped,
		p,
	)

	return mapped, nil
}

// ============================================================
// INTERNAL ENTRY -> Z_p
// ============================================================
//
// For every internal separator key:
//
//     (key_i, LPC_i, RPC_i)
//
// compute:
//
//     m_i = SHA256(
//         "BPLUS-INTERNAL-ENTRY"
//         || encode(key_i)
//         || encode(LPC_i)
//         || encode(RPC_i)
//     ) mod p
//
// Therefore:
//
//     ONE internal key
//          +
//     ONE LPC
//          +
//     ONE RPC
//
// produces exactly:
//
//     ONE value m_i in Z_p.
//
func MapIntInternalEntryToField(
	key int,
	lpc *kzg.Digest,
	rpc *kzg.Digest,
	p *big.Int,
) (*big.Int, error) {

	if lpc == nil {
		return nil, fmt.Errorf(
			"LPC is nil for key %d",
			key,
		)
	}

	if rpc == nil {
		return nil, fmt.Errorf(
			"RPC is nil for key %d",
			key,
		)
	}

	if p == nil {
		return nil, fmt.Errorf(
			"field modulus is nil",
		)
	}

	if p.Sign() <= 0 {
		return nil, fmt.Errorf(
			"field modulus must be positive",
		)
	}

	// ------------------------------------------------------------
	// Encode key
	// ------------------------------------------------------------

	var keyBytes [8]byte

	binary.BigEndian.PutUint64(
		keyBytes[:],
		uint64(key),
	)

	// ------------------------------------------------------------
	// Canonical compressed LPC/RPC encodings
	// ------------------------------------------------------------

	lpcBytes :=
		lpc.Bytes()

	rpcBytes :=
		rpc.Bytes()

	// ------------------------------------------------------------
	// Domain-separated hash
	// ------------------------------------------------------------

	h := sha256.New()

	h.Write(
		[]byte("BPLUS-INTERNAL-ENTRY"),
	)

	h.Write(
		keyBytes[:],
	)

	h.Write(
		lpcBytes[:],
	)

	h.Write(
		rpcBytes[:],
	)

	digest :=
		h.Sum(nil)

	// ------------------------------------------------------------
	// Map digest into Z_p
	// ------------------------------------------------------------

	mapped :=
		new(big.Int).SetBytes(
			digest,
		)

	mapped.Mod(
		mapped,
		p,
	)

	return mapped, nil
}