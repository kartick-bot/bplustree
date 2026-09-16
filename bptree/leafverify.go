package bptree

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

// verifyLeafOpeningProofs verifies every KZG opening proof
// generated for one leaf.
//
// Each proof is verified at that entry's GLOBAL
// evaluation point.
//
// For order = 4:
//
//	Leaf 0 -> 0, 1, 2
//	Leaf 1 -> 3, 4, 5
//	Leaf 2 -> 6, 7, 8
//	...
//
// Only occupied slots are used.
//
// Each call to kzg.Verify performs the KZG verification,
// including the bilinear pairing check.
func (t *Tree[K, V]) verifyLeafOpeningProofs(
	leaf *node[K, V],
) error {

	if leaf == nil {
		return fmt.Errorf(
			"leaf is nil",
		)
	}

	if !leaf.isLeaf {
		return fmt.Errorf(
			"verifyLeafOpeningProofs called on internal node",
		)
	}

	if leaf.commitment == nil {
		return fmt.Errorf(
			"leaf has no commitment",
		)
	}

	if leaf.nodeSRS == nil {
		return fmt.Errorf(
			"leaf has no SRS",
		)
	}

	if len(leaf.openingProofs) !=
		len(leaf.mappedValues) {

		return fmt.Errorf(
			"leaf has %d mapped values but %d opening proofs",
			len(leaf.mappedValues),
			len(leaf.openingProofs),
		)
	}

	if len(leaf.evaluationPoints) !=
		len(leaf.openingProofs) {

		return fmt.Errorf(
			"leaf has %d opening proofs but %d evaluation points",
			len(leaf.openingProofs),
			len(leaf.evaluationPoints),
		)
	}

	// Until every proof succeeds,
	// the leaf is considered unverified.
	leaf.pairingsVerified = false

	for i := range leaf.openingProofs {

		evaluationPoint :=
			leaf.evaluationPoints[i]

		var point fr.Element

		point.SetUint64(
			evaluationPoint,
		)

		proof :=
			&leaf.openingProofs[i]

		// ====================================================
		// KZG verification.
		//
		// Conceptually:
		//
		// e(C - yG1, G2)
		//
		//        =
		//
		// e(pi, [tau]G2 - zG2)
		//
		// where:
		//
		//     z = leaf.evaluationPoints[i]
		//
		// using THIS LEAF'S verification key.
		// ====================================================

		if err :=
			kzg.Verify(
				leaf.commitment,
				proof,
				point,
				leaf.nodeSRS.Vk,
			); err != nil {

			return fmt.Errorf(
				"leaf KZG pairing verification failed at global evaluation point %d: %w",
				evaluationPoint,
				err,
			)
		}
	}

	// Every pairing check passed.
	leaf.pairingsVerified = true

	return nil
}
