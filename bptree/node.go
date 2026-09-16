package bptree

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

type node[K any, V any] struct {
	isLeaf bool

	// ============================================================
	// INTERNAL NODE DATA
	// ============================================================

	// Separator keys.
	//
	// For:
	//
	//      [k0 k1 k2]
	//
	// there are four children:
	//
	//      C0 C1 C2 C3
	keys []K

	children []*node[K, V]

	// One commitment per child pointer.
	//
	// For separator key keys[i]:
	//
	// LPC[i] = childCommitments[i]
	// RPC[i] = childCommitments[i+1]
	//
	// Therefore:
	//
	// LPC[i] = RPC[i-1]
	//
	// for i > 0.
	childCommitments []*kzg.Digest

	// ------------------------------------------------------------
	// Internal-node mapped values
	// ------------------------------------------------------------
	//
	// For every separator key k_i:
	//
	// internalMappedValues[i]
	//
	// is:
	//
	// H(
	//     domain
	//     ||
	//     encode(k_i)
	//     ||
	//     LPC_i
	//     ||
	//     RPC_i
	// ) mod p
	//
	// Thus:
	//
	// internalMappedValues[i] ∈ Z_p
	//
	// These values will become the evaluations of the
	// internal-node polynomial.
	internalMappedValues []*big.Int

	// ============================================================
	// LEAF NODE DATA
	// ============================================================

	// Leaf entries:
	//
	//     (key, H(key))
	entries []Entry[K]

	// Field values corresponding one-to-one with entries.
	//
	// mappedValues[i] corresponds to entries[i].
	mappedValues []*big.Int

	// ------------------------------------------------------------
	// Existing per-leaf SRS
	// ------------------------------------------------------------
	//
	// KEEP THIS TEMPORARILY.
	//
	// Our existing leaf commitment code currently uses:
	//
	//     leaf.leafSRS
	//
	// We will migrate this to nodeSRS in the next step.
	leafSRS *kzg.SRS

	// ============================================================
	// GENERAL NODE-LEVEL KZG DATA
	// ============================================================

	// Every node -- leaf or internal -- will eventually
	// have its own independently generated KZG SRS.
	//
	// Examples:
	//
	//     Leaf 0       -> SRS_L0
	//     Leaf 1       -> SRS_L1
	//     Internal 0   -> SRS_I0
	//     Internal 1   -> SRS_I1
	//     Root         -> SRS_R
	//
	// For now, leafSRS remains in use by the existing code.
	// We will migrate everything to nodeSRS next.
	nodeSRS *kzg.SRS

	// Commitment to THIS NODE'S polynomial.
	//
	// For a leaf:
	//
	//     commitment = Commit(
	//         polynomial built from mappedValues
	//     )
	//
	// For an internal node:
	//
	//     commitment = Commit(
	//         polynomial built from internalMappedValues
	//     )
	//
	// This is the value that the parent will use as
	// one of its child commitments.
	commitment *kzg.Digest
	// KZG opening proof for every evaluation stored in this node.
//
// If this node contains:
//
//     m0, m1, m2
//
// then:
//
//     openingProofs[0] proves f(0) = m0
//     openingProofs[1] proves f(1) = m1
//     openingProofs[2] proves f(2) = m2
	openingProofs []kzg.OpeningProof

// True ONLY after all KZG opening proofs for this
// node successfully pass bilinear-pairing verification.
	pairingsVerified bool

	// ============================================================
	// LEAF LINKED LIST
	// ============================================================

	next *node[K, V]
}