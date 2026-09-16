package bptree

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

// generateInternalOpeningProofs generates one KZG opening proof
// for every mapped value in an internal node.
//
// No pairing verification is performed here yet.
func (t *Tree[K, V]) generateInternalOpeningProofs(
	n *node[K, V],
) error {

	if n == nil {
		return fmt.Errorf("internal node is nil")
	}

	if n.isLeaf {
		return fmt.Errorf(
			"generateInternalOpeningProofs called on leaf",
		)
	}

	if n.nodeSRS == nil {
		return fmt.Errorf(
			"internal node has no SRS",
		)
	}

	if len(n.internalMappedValues) == 0 {
		return fmt.Errorf(
			"internal node has no mapped values",
		)
	}

	evaluations :=
		make(
			[]fr.Element,
			len(n.internalMappedValues),
		)

	for i, mapped := range n.internalMappedValues {

		if mapped == nil {
			return fmt.Errorf(
				"internal mapped value %d is nil",
				i,
			)
		}

		evaluations[i].SetBigInt(
			mapped,
		)
	}

	// Reconstruct the same polynomial used
	// for the internal-node commitment.
	poly :=
		polynomial.InterpolateOnRange(
			evaluations,
		)

	coefficients :=
		[]fr.Element(poly)

	n.openingProofs =
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
				n.nodeSRS.Pk,
			)

		if err != nil {
			return fmt.Errorf(
				"failed to generate internal KZG opening proof at point %d: %w",
				i,
				err,
			)
		}

		n.openingProofs[i] =
			proof
	}

	// Generated, but not verified yet.
	n.pairingsVerified = false

	return nil
}
