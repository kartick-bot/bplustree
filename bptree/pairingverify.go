package bptree

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

// commitAndVerifyValues performs the complete KZG process:
//
//     field values
//          ↓
//     interpolate polynomial
//          ↓
//     KZG commitment
//          ↓
//     KZG opening proof for every evaluation
//          ↓
//     bilinear-pairing verification for every proof
//
// The node is marked pairingsVerified=true ONLY if
// every opening proof verifies successfully.
func (t *Tree[K, V]) commitAndVerifyValues(
	n *node[K, V],
	values []*big.Int,
) (*kzg.Digest, error) {

	if n == nil {
		return nil, fmt.Errorf(
			"cannot commit and verify nil node",
		)
	}

	if n.nodeSRS == nil {
		return nil, fmt.Errorf(
			"node has no KZG SRS",
		)
	}

	if len(values) == 0 {
		return nil, fmt.Errorf(
			"cannot commit empty value list",
		)
	}

	// Until every pairing succeeds, this node is unverified.
	n.pairingsVerified = false
	n.openingProofs = nil
	n.commitment = nil

	// ============================================================
	// STEP 1:
	// Convert mapped Z_p values to BN254 field elements.
	// ============================================================

	evaluations :=
		make(
			[]fr.Element,
			len(values),
		)

	for i, value := range values {

		if value == nil {
			return nil, fmt.Errorf(
				"nil mapped value at index %d",
				i,
			)
		}

		if value.Sign() < 0 ||
			value.Cmp(t.modulus) >= 0 {

			return nil, fmt.Errorf(
				"mapped value %d is outside Z_p",
				i,
			)
		}

		evaluations[i].SetBigInt(
			value,
		)
	}

	// ============================================================
	// STEP 2:
	//
	// Interpolate:
	//
	//     f(0) = m0
	//     f(1) = m1
	//     ...
	//
	// ============================================================

	poly :=
		polynomial.InterpolateOnRange(
			evaluations,
		)

	coefficients :=
		[]fr.Element(poly)

	if len(coefficients) >
		len(n.nodeSRS.Pk.G1) {

		return nil, fmt.Errorf(
			"polynomial requires %d SRS powers but node SRS contains %d",
			len(coefficients),
			len(n.nodeSRS.Pk.G1),
		)
	}

	// ============================================================
	// STEP 3:
	// Compute the node's KZG commitment.
	// ============================================================

	digest, err :=
		kzg.Commit(
			coefficients,
			n.nodeSRS.Pk,
		)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to compute KZG commitment: %w",
			err,
		)
	}

	// ============================================================
	// STEP 4:
	// Generate and verify one KZG opening for every
	// evaluation contained in the node.
	//
	// For example:
	//
	//     f(0) = m0
	//     f(1) = m1
	//     f(2) = m2
	//
	// produces:
	//
	//     pi_0
	//     pi_1
	//     pi_2
	//
	// Each call to kzg.Verify performs the KZG
	// bilinear-pairing verification.
	// ============================================================

	proofs :=
		make(
			[]kzg.OpeningProof,
			len(values),
		)

	for i := range evaluations {

		// Evaluation point:
		//
		//     z = i
		var point fr.Element

		point.SetUint64(
			uint64(i),
		)

		// --------------------------------------------------------
		// Generate:
		//
		//     pi_i
		//
		// proving:
		//
		//     f(i) = m_i
		// --------------------------------------------------------

		proof, err :=
			kzg.Open(
				coefficients,
				point,
				n.nodeSRS.Pk,
			)

		if err != nil {

			return nil, fmt.Errorf(
				"KZG opening generation failed at evaluation %d: %w",
				i,
				err,
			)
		}

		// --------------------------------------------------------
		// Make sure the opening is claiming exactly the mapped
		// value that belongs at this evaluation point.
		// --------------------------------------------------------

		if !proof.ClaimedValue.Equal(
			&evaluations[i],
		) {

			return nil, fmt.Errorf(
				"KZG opening at point %d claims the wrong field value",
				i,
			)
		}

		// --------------------------------------------------------
		// ACTUAL BILINEAR-PAIRING VERIFICATION.
		//
		// Conceptually checks:
		//
		// e(
		//     C - yG1,
		//     G2
		// )
		//
		// ==
		//
		// e(
		//     pi,
		//     [tau]G2 - zG2
		// )
		//
		// using this node's own verification key.
		// --------------------------------------------------------

		if err :=
			kzg.Verify(
				&digest,
				&proof,
				point,
				n.nodeSRS.Vk,
			); err != nil {

			return nil, fmt.Errorf(
				"KZG PAIRING VERIFICATION FAILED at evaluation %d: %w",
				i,
				err,
			)
		}

		proofs[i] =
			proof
	}

	// ============================================================
	// IMPORTANT:
	//
	// We reach here ONLY if EVERY pairing verification passed.
	//
	// Only now do we publish/store the commitment.
	// ============================================================

	n.commitment =
		&digest

	n.openingProofs =
		proofs

	n.pairingsVerified =
		true

	return n.commitment, nil
}