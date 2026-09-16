package bptree

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

// verifyLeafOpeningProofs verifies every KZG opening proof
// generated for one leaf.
//
// Each call to kzg.Verify performs the KZG verification,
// including the bilinear pairing check.
//
// The leaf is marked pairingsVerified=true ONLY if
// every opening proof verifies successfully.
func (t *Tree[K, V]) verifyLeafOpeningProofs(
	leaf *node[K, V],
) error {

	if leaf == nil {
		return fmt.Errorf("leaf is nil")
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

	// Until every proof succeeds,
	// the leaf is considered unverified.
	leaf.pairingsVerified = false

	for i := range leaf.openingProofs {

		var point fr.Element

		point.SetUint64(
			uint64(i),
		)

		proof :=
			&leaf.openingProofs[i]
			
			// 		if n != t.root && i == 0 {

			// 	var one fr.Element
			// 	one.SetUint64(1)

			// 	proof.ClaimedValue.Add(
			// 		&proof.ClaimedValue,
			// 		&one,
			// 	)
			// }
			// 		// if i == 0 {

		// 	var one fr.Element
		// 	one.SetUint64(1)

		// 	proof.ClaimedValue.Add(
		// 		&proof.ClaimedValue,
		// 		&one,
		// 	)
		// }

		// ====================================================
		// KZG verification.
		//
		// Conceptually this checks the pairing relation:
		//
		// e(C - yG1, G2)
		//
		//        =
		//
		// e(pi, [tau]G2 - zG2)
		//
		// for:
		//
		//     z = i
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
				"leaf KZG pairing verification failed at evaluation point %d: %w",
				i,
				err,
			)
		}
	}

	// We get here only if EVERY pairing check passed.
	leaf.pairingsVerified = true

	return nil
}
