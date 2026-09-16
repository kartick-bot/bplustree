package bptree

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

// generateLeafOpeningProofs creates one KZG opening proof
// for every mapped value stored in a leaf.
//
// Leaf evaluation points are GLOBAL across the leaf layer.
//
// For order = 4:
//
//	Leaf 0 -> slots 0, 1, 2
//	Leaf 1 -> slots 3, 4, 5
//	Leaf 2 -> slots 6, 7, 8
//	...
//
// Only occupied slots are used.
//
// Example:
//
//	Leaf 0 = [4, 7]
//
//	mappedValues      = [m0, m1]
//	evaluationPoints  = [0, 1]
//
// so:
//
//	proof[0] proves f(0) = m0
//	proof[1] proves f(1) = m1
//
// For:
//
//	Leaf 1 = [10, 12]
//
//	evaluationPoints = [3, 4]
//
// so:
//
//	proof[0] proves f(3) = m0
//	proof[1] proves f(4) = m1
//
// No pairing verification is performed here.
func (t *Tree[K, V]) generateLeafOpeningProofs(
	leaf *node[K, V],
) error {

	if leaf == nil {
		return fmt.Errorf(
			"leaf is nil",
		)
	}

	if !leaf.isLeaf {
		return fmt.Errorf(
			"generateLeafOpeningProofs called on internal node",
		)
	}

	if leaf.nodeSRS == nil {
		return fmt.Errorf(
			"leaf has no node SRS",
		)
	}

	if len(leaf.mappedValues) == 0 {
		return fmt.Errorf(
			"leaf has no mapped values",
		)
	}

	if len(leaf.evaluationPoints) !=
		len(leaf.mappedValues) {

		return fmt.Errorf(
			"leaf has %d mapped values but %d evaluation points",
			len(leaf.mappedValues),
			len(leaf.evaluationPoints),
		)
	}

	// ============================================================
	// Reconstruct EXACTLY the same polynomial used
	// for the leaf commitment.
	//
	// Unlike the old code, we do NOT interpolate at:
	//
	//     0, 1, 2, ...
	//
	// inside every leaf.
	//
	// Instead we use this leaf's global evaluation points.
	// ============================================================

	coefficients, err :=
		interpolateAtPoints(
			leaf.evaluationPoints,
			leaf.mappedValues,
			t.modulus,
		)

	if err != nil {
		return fmt.Errorf(
			"failed to interpolate leaf polynomial for opening proofs: %w",
			err,
		)
	}

	// ============================================================
	// Generate one KZG opening proof at each GLOBAL
	// evaluation point.
	// ============================================================

	leaf.openingProofs =
		make(
			[]kzg.OpeningProof,
			len(leaf.mappedValues),
		)

	for i := range leaf.mappedValues {

		evaluationPoint :=
			leaf.evaluationPoints[i]

		var point fr.Element

		point.SetUint64(
			evaluationPoint,
		)

		proof, err :=
			kzg.Open(
				coefficients,
				point,
				leaf.nodeSRS.Pk,
			)

		if err != nil {
			return fmt.Errorf(
				"failed to generate KZG opening proof at global evaluation point %d: %w",
				evaluationPoint,
				err,
			)
		}

		leaf.openingProofs[i] =
			proof
	}

	// Proofs have been generated,
	// but they have NOT yet been verified.
	leaf.pairingsVerified = false

	return nil
}
