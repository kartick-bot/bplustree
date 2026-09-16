package bptree

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

// verifyInternalOpeningProofs verifies every KZG opening proof
// generated for one internal node.
//
// The node is marked pairingsVerified=true only if
// every opening proof verifies successfully.
func (t *Tree[K, V]) verifyInternalOpeningProofs(
	n *node[K, V],
) error {

	if n == nil {
		return fmt.Errorf(
			"internal node is nil",
		)
	}

	if n.isLeaf {
		return fmt.Errorf(
			"verifyInternalOpeningProofs called on leaf",
		)
	}

	if n.commitment == nil {
		return fmt.Errorf(
			"internal node has no commitment",
		)
	}

	if n.nodeSRS == nil {
		return fmt.Errorf(
			"internal node has no SRS",
		)
	}

	if len(n.openingProofs) !=
		len(n.internalMappedValues) {

		return fmt.Errorf(
			"internal node has %d mapped values but %d opening proofs",
			len(n.internalMappedValues),
			len(n.openingProofs),
		)
	}

	// Until every opening verifies,
	// this node is considered unverified.
	n.pairingsVerified = false

	for i := range n.openingProofs {

		var point fr.Element

		point.SetUint64(
			uint64(i),
		)

		proof :=
			&n.openingProofs[i]

		// KZG opening verification.
		//
		// Conceptually checks:
		//
		// e(C - yG1, G2)
		//      =
		// e(pi, [tau]G2 - zG2)
		//
		// using this node's own verification key.
		if err :=
			kzg.Verify(
				n.commitment,
				proof,
				point,
				n.nodeSRS.Vk,
			); err != nil {

			return fmt.Errorf(
				"internal-node KZG pairing verification failed at evaluation point %d: %w",
				i,
				err,
			)
		}
	}

	// Every pairing check succeeded.
	n.pairingsVerified = true

	return nil
}
