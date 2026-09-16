package bptree

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

// ensureNodeSRS guarantees that every node has its own SRS.
//
// Leaves created by the older leaf code already have leafSRS.
// For those leaves, nodeSRS points to the same SRS.
//
// Internal nodes receive a fresh independent SRS here.
func (t *Tree[K, V]) ensureNodeSRS(
	n *node[K, V],
) error {

	if n == nil {
		return fmt.Errorf(
			"cannot create SRS for nil node",
		)
	}

	// Already initialized.
	if n.nodeSRS != nil {
		return nil
	}

	// ------------------------------------------------------------
	// Compatibility with existing leaf code.
	// ------------------------------------------------------------

	if n.isLeaf && n.leafSRS != nil {
		n.nodeSRS = n.leafSRS
		return nil
	}

	// ------------------------------------------------------------
	// Generate an independent SRS for this node.
	// ------------------------------------------------------------

	srs, err :=
		newKZGSRS(
			uint64(t.order-1),
			t.modulus,
		)

	if err != nil {
		return fmt.Errorf(
			"failed to generate node SRS: %w",
			err,
		)
	}

	n.nodeSRS = srs

	// Keep old leaf code compatible temporarily.
	if n.isLeaf {
		n.leafSRS = srs
	}

	return nil
}

// commitFieldValues takes:
//
//	[m0, m1, ..., mn-1]
//
// where every m_i is in Z_p,
// interpolates:
//
//	f(0) = m0
//	f(1) = m1
//	...
//
// and produces one KZG commitment using this node's SRS.
//
// IMPORTANT:
// This helper is still used for INTERNAL NODES.
//
// Leaves now use interpolateAtPoints() because their evaluation
// points are global positions across the leaf layer.
func (t *Tree[K, V]) commitFieldValues(
	values []*big.Int,
	srs *kzg.SRS,
) (*kzg.Digest, error) {

	if len(values) == 0 {
		return nil, fmt.Errorf(
			"cannot commit an empty value list",
		)
	}

	if srs == nil {
		return nil, fmt.Errorf(
			"cannot commit without an SRS",
		)
	}

	if len(values) > len(srs.Pk.G1) {
		return nil, fmt.Errorf(
			"%d field values require %d SRS powers, but SRS contains only %d",
			len(values),
			len(values),
			len(srs.Pk.G1),
		)
	}

	fieldValues :=
		make(
			[]fr.Element,
			len(values),
		)

	for i, value := range values {

		if value == nil {
			return nil, fmt.Errorf(
				"nil field value at position %d",
				i,
			)
		}

		if value.Sign() < 0 ||
			value.Cmp(t.modulus) >= 0 {

			return nil, fmt.Errorf(
				"field value %d is outside Z_p",
				i,
			)
		}

		fieldValues[i].SetBigInt(
			value,
		)
	}

	// ------------------------------------------------------------
	// Interpolate:
	//
	//     f(i) = fieldValues[i]
	//
	// Internal nodes continue to use local points:
	//
	//     0, 1, 2, ...
	// ------------------------------------------------------------

	poly :=
		polynomial.InterpolateOnRange(
			fieldValues,
		)

	coefficients :=
		[]fr.Element(poly)

	// ------------------------------------------------------------
	// One KZG commitment for the complete node.
	// ------------------------------------------------------------

	digest, err :=
		kzg.Commit(
			coefficients,
			srs.Pk,
		)

	if err != nil {
		return nil, fmt.Errorf(
			"KZG commitment failed: %w",
			err,
		)
	}

	return &digest, nil
}

// BuildCommitments recursively computes commitments
// from the leaves all the way to the root.
//
// Before commitment construction, every leaf receives
// its global evaluation points.
//
// For order = 4:
//
//	Leaf 0 -> slots 0, 1, 2
//	Leaf 1 -> slots 3, 4, 5
//	Leaf 2 -> slots 6, 7, 8
//	...
//
// Only occupied slots are stored.
//
// After this finishes:
//
//	t.root.commitment
//
// is the commitment to the entire recursive tree structure.
func (t *Tree[K, V]) BuildCommitments() error {

	if t.root == nil {
		return fmt.Errorf(
			"cannot build commitments for empty tree",
		)
	}

	// ------------------------------------------------------------
	// Assign global leaf evaluation points BEFORE any
	// leaf polynomial is constructed.
	// ------------------------------------------------------------

	if err :=
		t.assignLeafEvaluationPoints(); err != nil {

		return fmt.Errorf(
			"failed to assign leaf evaluation points: %w",
			err,
		)
	}

	_, err :=
		t.commitNode(
			t.root,
		)

	return err
}

// commitNode recursively computes the commitment to one node.
//
// LEAF:
//
//	(key,H(key))
//	     |
//	     v
//	mapped values
//	     |
//	     v
//	global evaluation points
//	     |
//	     v
//	polynomial
//	     |
//	     v
//	leaf commitment
//
// INTERNAL:
//
//	recursively commit children
//	     |
//	     v
//	LPC/RPC
//	     |
//	     v
//	(key,LPC,RPC)
//	     |
//	     v
//	one mapped Z_p value per key
//	     |
//	     v
//	polynomial
//	     |
//	     v
//	one internal-node commitment
func (t *Tree[K, V]) commitNode(
	n *node[K, V],
) (*kzg.Digest, error) {

	if n == nil {
		return nil, fmt.Errorf(
			"cannot commit nil node",
		)
	}

	// Every node receives its own SRS.
	if err :=
		t.ensureNodeSRS(n); err != nil {

		return nil, err
	}

	// ============================================================
	// LEAF NODE
	// ============================================================

	if n.isLeaf {

		if len(n.entries) == 0 {
			return nil, fmt.Errorf(
				"cannot commit empty leaf",
			)
		}

		if len(n.entries) !=
			len(n.mappedValues) {

			return nil, fmt.Errorf(
				"leaf has %d entries but %d mapped values",
				len(n.entries),
				len(n.mappedValues),
			)
		}

		if len(n.evaluationPoints) !=
			len(n.mappedValues) {

			return nil, fmt.Errorf(
				"leaf has %d mapped values but %d evaluation points",
				len(n.mappedValues),
				len(n.evaluationPoints),
			)
		}

		// ------------------------------------------------------------
		// Interpolate the leaf polynomial using its GLOBAL
		// evaluation points.
		//
		// Example for order = 4:
		//
		//     Leaf 0:
		//
		//         entries = [4, 7]
		//         points  = [0, 1]
		//
		//     Leaf 1:
		//
		//         entries = [10, 12]
		//         points  = [3, 4]
		//
		//     Leaf 2:
		//
		//         entries = [15, 18]
		//         points  = [6, 7]
		//
		// Each leaf reserves exactly order-1 slots.
		// ------------------------------------------------------------

		coefficients, err :=
			interpolateAtPoints(
				n.evaluationPoints,
				n.mappedValues,
				t.modulus,
			)

		if err != nil {
			return nil, fmt.Errorf(
				"failed to interpolate leaf polynomial: %w",
				err,
			)
		}

		// ------------------------------------------------------------
		// Commit to the leaf polynomial.
		// ------------------------------------------------------------

		digest, err :=
			kzg.Commit(
				coefficients,
				n.nodeSRS.Pk,
			)

		if err != nil {
			return nil, fmt.Errorf(
				"failed to commit leaf polynomial: %w",
				err,
			)
		}

		commitment :=
			&digest

		n.commitment =
			commitment

		// ------------------------------------------------------------
		// Generate one KZG opening proof for every
		// evaluation point in this leaf.
		//
		// NOTE:
		// generateLeafOpeningProofs() will next be changed
		// to use n.evaluationPoints instead of local
		// positions 0, 1, 2.
		// ------------------------------------------------------------

		if err :=
			t.generateLeafOpeningProofs(n); err != nil {

			return nil, fmt.Errorf(
				"failed to generate leaf opening proofs: %w",
				err,
			)
		}

		// ------------------------------------------------------------
		// Verify all leaf KZG openings using bilinear pairings.
		//
		// If even ONE proof fails, commitNode returns an error here,
		// so the parent internal node will never receive this
		// leaf commitment.
		// ------------------------------------------------------------

		if err :=
			t.verifyLeafOpeningProofs(n); err != nil {

			return nil, fmt.Errorf(
				"leaf pairing verification failed: %w",
				err,
			)
		}

		return commitment, nil
	}

	// ============================================================
	// INTERNAL NODE
	// ============================================================

	if len(n.children) !=
		len(n.keys)+1 {

		return nil, fmt.Errorf(
			"internal node has %d keys but %d children",
			len(n.keys),
			len(n.children),
		)
	}

	if len(n.keys) == 0 {
		return nil, fmt.Errorf(
			"cannot commit internal node with zero keys",
		)
	}

	// ------------------------------------------------------------
	// STEP 1:
	//
	// Recursively commit every child.
	// ------------------------------------------------------------

	n.childCommitments =
		make(
			[]*kzg.Digest,
			len(n.children),
		)

	for i, child := range n.children {

		childCommitment, err :=
			t.commitNode(child)

		if err != nil {
			return nil, fmt.Errorf(
				"failed to commit child %d: %w",
				i,
				err,
			)
		}

		// ------------------------------------------------------------
		// SECURITY GATE:
		//
		// A parent is not allowed to use a child's commitment
		// unless that child successfully passed all of its
		// KZG pairing verifications.
		// ------------------------------------------------------------

		if !child.pairingsVerified {
			return nil, fmt.Errorf(
				"child %d commitment rejected: KZG pairing verification has not passed",
				i,
			)
		}

		n.childCommitments[i] =
			childCommitment
	}

	// ------------------------------------------------------------
	// STEP 2:
	//
	// Each key produces ONE mapped value:
	//
	//     m_i =
	//         Map(
	//             key_i,
	//             LPC_i,
	//             RPC_i
	//         )
	//
	// where:
	//
	//     LPC_i = childCommitments[i]
	//
	//     RPC_i = childCommitments[i+1]
	// ------------------------------------------------------------

	n.internalMappedValues =
		make(
			[]*big.Int,
			len(n.keys),
		)

	for i, key := range n.keys {

		lpc :=
			n.childCommitments[i]

		rpc :=
			n.childCommitments[i+1]

		if lpc == nil {
			return nil, fmt.Errorf(
				"internal key %d has nil LPC",
				i,
			)
		}

		if rpc == nil {
			return nil, fmt.Errorf(
				"internal key %d has nil RPC",
				i,
			)
		}

		mapped, err :=
			t.internalFieldMapper(
				key,
				lpc,
				rpc,
				t.modulus,
			)

		if err != nil {
			return nil, fmt.Errorf(
				"failed to map internal entry %d: %w",
				i,
				err,
			)
		}

		if mapped == nil {
			return nil, fmt.Errorf(
				"internal mapper returned nil for entry %d",
				i,
			)
		}

		if mapped.Sign() < 0 ||
			mapped.Cmp(t.modulus) >= 0 {

			return nil, fmt.Errorf(
				"internal mapped value %d is outside Z_p",
				i,
			)
		}

		n.internalMappedValues[i] =
			new(big.Int).Set(
				mapped,
			)
	}

	// ------------------------------------------------------------
	// STEP 3:
	//
	// If the internal node has:
	//
	//     3 keys
	//
	// then we now have:
	//
	//     3 mapped values
	//
	// and interpolate:
	//
	//     f(0) = m0
	//     f(1) = m1
	//     f(2) = m2
	//
	// giving a polynomial of degree <= 2.
	//
	// INTERNAL NODE EVALUATION POINTS ARE UNCHANGED.
	// ------------------------------------------------------------

	commitment, err :=
		t.commitFieldValues(
			n.internalMappedValues,
			n.nodeSRS,
		)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to commit internal node: %w",
			err,
		)
	}

	// ------------------------------------------------------------
	// STEP 4:
	//
	// Store ONE commitment for this complete internal node.
	//
	// Its parent will use this value as an LPC or RPC.
	// ------------------------------------------------------------

	n.commitment =
		commitment

	if err :=
		t.generateInternalOpeningProofs(n); err != nil {

		return nil, fmt.Errorf(
			"failed to generate internal opening proofs: %w",
			err,
		)
	}

	if err :=
		t.verifyInternalOpeningProofs(n); err != nil {

		return nil, fmt.Errorf(
			"internal-node pairing verification failed: %w",
			err,
		)
	}

	return commitment, nil
}

// RootCommitment returns the final recursive root commitment.
//
// BuildCommitments must be called first.
func (t *Tree[K, V]) RootCommitment() (
	*kzg.Digest,
	error,
) {

	if t.root == nil {
		return nil, fmt.Errorf(
			"tree has no root",
		)
	}

	if t.root.commitment == nil {
		return nil, fmt.Errorf(
			"root commitment has not been built",
		)
	}

	// Return a copy.
	result :=
		*t.root.commitment

	return &result, nil
}
