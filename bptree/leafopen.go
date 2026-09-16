package bptree

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

// generateLeafOpeningProofs creates one KZG opening proof
// for every mapped value stored in a leaf.
//
// If the leaf contains:
//
//	m0, m1, m2
//
// then:
//
//	proof[0] proves f(0) = m0
//	proof[1] proves f(1) = m1
//	proof[2] proves f(2) = m2
//
// No pairing verification is performed here yet.
func (t *Tree[K, V]) generateLeafOpeningProofs(
	leaf *node[K, V],
) error {

	if leaf == nil {
		return fmt.Errorf("leaf is nil")
	}

	if !leaf.isLeaf {
		return fmt.Errorf("generateLeafOpeningProofs called on internal node")
	}

	if leaf.nodeSRS == nil {
		return fmt.Errorf("leaf has no node SRS")
	}

	if len(leaf.mappedValues) == 0 {
		return fmt.Errorf("leaf has no mapped values")
	}

	// ============================================================
	// Convert mapped values to BN254 field elements.
	// ============================================================

	evaluations :=
		make(
			[]fr.Element,
			len(leaf.mappedValues),
		)

	for i, mapped := range leaf.mappedValues {

		if mapped == nil {
			return fmt.Errorf(
				"leaf mapped value %d is nil",
				i,
			)
		}

		evaluations[i].SetBigInt(
			mapped,
		)
	}

	// ============================================================
	// Reconstruct the same polynomial used for the commitment:
	//
	//     f(0) = m0
	//     f(1) = m1
	//     ...
	// ============================================================

	poly :=
		polynomial.InterpolateOnRange(
			evaluations,
		)

	coefficients :=
		[]fr.Element(poly)

	// ============================================================
	// Generate one KZG opening proof at each evaluation point.
	// ============================================================

	leaf.openingProofs =
		make(
			[]kzg.OpeningProof,
			len(evaluations),
		)

	for i := range evaluations {

		var point fr.Element

		point.SetUint64(
			uint64(i),
		)

		proof, err :=
			kzg.Open(
				coefficients,
				point,
				leaf.nodeSRS.Pk,
			)

		if err != nil {
			return fmt.Errorf(
				"failed to generate KZG opening proof at point %d: %w",
				i,
				err,
			)
		}

		leaf.openingProofs[i] =
			proof
	}

	// We have generated proofs, but have NOT verified them yet.
	leaf.pairingsVerified = false

	return nil
}
