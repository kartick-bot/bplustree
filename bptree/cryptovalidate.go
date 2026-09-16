package bptree

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

// ValidateCommitments recursively validates the complete
// cryptographic commitment structure of the B+ tree.
//
// It checks:
//
// LEAVES:
//   - H(key) is correct
//   - mapped Z_p value is correct
//   - global evaluation points are present
//   - leaf commitment recomputes correctly using those
//     global evaluation points
//
// INTERNAL NODES:
//   - every child commitment matches child.commitment
//   - every (key, LPC, RPC) maps to the stored Z_p value
//   - internal-node polynomial commitment recomputes correctly
//
// ROOT:
//   - recursively validates everything below it
//   - recomputes and checks the final root commitment
func (t *Tree[K, V]) ValidateCommitments() error {

	if t.root == nil {

		return fmt.Errorf(
			"cannot validate commitments: tree has no root",
		)
	}

	if t.root.commitment == nil {

		return fmt.Errorf(
			"cannot validate commitments: root commitment has not been built",
		)
	}

	recomputedRoot, err :=
		t.validateCommitmentNode(
			t.root,
			0,
		)

	if err != nil {

		return err
	}

	if recomputedRoot == nil {

		return fmt.Errorf(
			"recursive validation returned nil root commitment",
		)
	}

	// Final independent root comparison.
	if !t.root.commitment.Equal(
		recomputedRoot,
	) {

		return fmt.Errorf(
			"final root commitment mismatch",
		)
	}

	return nil
}

// validateCommitmentNode recursively validates one node.
//
// The returned commitment is the independently recomputed
// commitment for this node.
func (t *Tree[K, V]) validateCommitmentNode(
	n *node[K, V],
	depth int,
) (*kzg.Digest, error) {

	if n == nil {

		return nil, fmt.Errorf(
			"nil node encountered at depth %d",
			depth,
		)
	}

	if n.nodeSRS == nil {

		return nil, fmt.Errorf(
			"node at depth %d has no node SRS",
			depth,
		)
	}

	if n.commitment == nil {

		return nil, fmt.Errorf(
			"node at depth %d has no stored commitment",
			depth,
		)
	}

	// ============================================================
	// LEAF NODE
	// ============================================================

	if n.isLeaf {

		if len(n.entries) == 0 {

			return nil, fmt.Errorf(
				"empty leaf encountered at depth %d",
				depth,
			)
		}

		if len(n.entries) !=
			len(n.mappedValues) {

			return nil, fmt.Errorf(
				"leaf at depth %d has %d entries but %d mapped values",
				depth,
				len(n.entries),
				len(n.mappedValues),
			)
		}

		if len(n.evaluationPoints) !=
			len(n.mappedValues) {

			return nil, fmt.Errorf(
				"leaf at depth %d has %d mapped values but %d evaluation points",
				depth,
				len(n.mappedValues),
				len(n.evaluationPoints),
			)
		}

		// --------------------------------------------------------
		// Verify each leaf entry independently.
		// --------------------------------------------------------

		for i, entry := range n.entries {

			// ----------------------------------------------
			// Recompute:
			//
			// H(key)
			// ----------------------------------------------

			expectedHash :=
				t.hasher(
					entry.Key,
				)

			if expectedHash != entry.Value {

				return nil, fmt.Errorf(
					"leaf at depth %d entry %d has incorrect H(key)",
					depth,
					i,
				)
			}

			// ----------------------------------------------
			// Recompute:
			//
			// Map(
			//     key,
			//     H(key)
			// ) -> Z_p
			// ----------------------------------------------

			expectedMapped, err :=
				t.fieldMapper(
					entry.Key,
					entry.Value,
					t.modulus,
				)

			if err != nil {

				return nil, fmt.Errorf(
					"failed to recompute leaf mapped value at depth %d entry %d: %w",
					depth,
					i,
					err,
				)
			}

			if expectedMapped == nil {

				return nil, fmt.Errorf(
					"leaf mapper returned nil at depth %d entry %d",
					depth,
					i,
				)
			}

			if n.mappedValues[i] == nil {

				return nil, fmt.Errorf(
					"stored leaf mapped value is nil at depth %d entry %d",
					depth,
					i,
				)
			}

			if expectedMapped.Cmp(
				n.mappedValues[i],
			) != 0 {

				return nil, fmt.Errorf(
					"leaf mapped value mismatch at depth %d entry %d",
					depth,
					i,
				)
			}
		}

		// --------------------------------------------------------
		// Recompute complete leaf polynomial using the SAME
		// GLOBAL evaluation points used during commitment
		// construction.
		//
		// Example for order = 4:
		//
		//   Leaf 0 -> 0, 1
		//   Leaf 1 -> 3, 4
		//   Leaf 2 -> 6, 7
		//   ...
		// --------------------------------------------------------

		coefficients, err :=
			interpolateAtPoints(
				n.evaluationPoints,
				n.mappedValues,
				t.modulus,
			)

		if err != nil {

			return nil, fmt.Errorf(
				"failed to recompute leaf polynomial at depth %d: %w",
				depth,
				err,
			)
		}

		digest, err :=
			kzg.Commit(
				coefficients,
				n.nodeSRS.Pk,
			)

		if err != nil {

			return nil, fmt.Errorf(
				"failed to recompute leaf commitment at depth %d: %w",
				depth,
				err,
			)
		}

		recomputed :=
			&digest

		if !n.commitment.Equal(
			recomputed,
		) {

			return nil, fmt.Errorf(
				"leaf commitment mismatch at depth %d",
				depth,
			)
		}

		return recomputed, nil
	}

	// ============================================================
	// INTERNAL NODE
	// ============================================================

	// ------------------------------------------------------------
	// Structural relationship:
	//
	// k keys -> k+1 children
	// ------------------------------------------------------------

	if len(n.children) !=
		len(n.keys)+1 {

		return nil, fmt.Errorf(
			"internal node at depth %d has %d keys but %d children",
			depth,
			len(n.keys),
			len(n.children),
		)
	}

	if len(n.keys) == 0 {

		return nil, fmt.Errorf(
			"internal node at depth %d contains zero keys",
			depth,
		)
	}

	// ------------------------------------------------------------
	// Must have one stored commitment per child.
	// ------------------------------------------------------------

	if len(n.childCommitments) !=
		len(n.children) {

		return nil, fmt.Errorf(
			"internal node at depth %d has %d children but %d child commitments",
			depth,
			len(n.children),
			len(n.childCommitments),
		)
	}

	// ------------------------------------------------------------
	// Must have one mapped value per separator key.
	// ------------------------------------------------------------

	if len(n.internalMappedValues) !=
		len(n.keys) {

		return nil, fmt.Errorf(
			"internal node at depth %d has %d keys but %d mapped values",
			depth,
			len(n.keys),
			len(n.internalMappedValues),
		)
	}

	// ============================================================
	// STEP 1:
	//
	// Recursively validate every child.
	// ============================================================

	for i, child := range n.children {

		if child == nil {

			return nil, fmt.Errorf(
				"internal node at depth %d has nil child %d",
				depth,
				i,
			)
		}

		childCommitment, err :=
			t.validateCommitmentNode(
				child,
				depth+1,
			)

		if err != nil {

			return nil, fmt.Errorf(
				"child %d validation failed at depth %d: %w",
				i,
				depth,
				err,
			)
		}

		if childCommitment == nil {

			return nil, fmt.Errorf(
				"child %d returned nil commitment at depth %d",
				i,
				depth,
			)
		}

		if n.childCommitments[i] == nil {

			return nil, fmt.Errorf(
				"stored child commitment %d is nil at depth %d",
				i,
				depth,
			)
		}

		// --------------------------------------------------------
		// Parent's pointer commitment must equal the actual
		// independently recomputed child commitment.
		// --------------------------------------------------------

		if !n.childCommitments[i].Equal(
			childCommitment,
		) {

			return nil, fmt.Errorf(
				"child commitment mismatch at depth %d child %d",
				depth,
				i,
			)
		}
	}

	// ============================================================
	// STEP 2:
	//
	// Validate every:
	//
	//     (key_i, LPC_i, RPC_i)
	//
	// mapping.
	// ============================================================

	for i, key := range n.keys {

		// --------------------------------------------------------
		// Pointer interpretation:
		//
		// LPC_i = C_i
		//
		// RPC_i = C_{i+1}
		// --------------------------------------------------------

		lpc :=
			n.childCommitments[i]

		rpc :=
			n.childCommitments[i+1]

		if lpc == nil {

			return nil, fmt.Errorf(
				"LPC[%d] is nil at depth %d",
				i,
				depth,
			)
		}

		if rpc == nil {

			return nil, fmt.Errorf(
				"RPC[%d] is nil at depth %d",
				i,
				depth,
			)
		}

		// --------------------------------------------------------
		// Explicit shared-pointer check.
		//
		// For i > 0:
		//
		//     LPC[i] = RPC[i-1]
		// --------------------------------------------------------

		if i > 0 {

			previousRPC :=
				n.childCommitments[i]

			if !lpc.Equal(
				previousRPC,
			) {

				return nil, fmt.Errorf(
					"LPC[%d] != RPC[%d] at depth %d",
					i,
					i-1,
					depth,
				)
			}
		}

		// --------------------------------------------------------
		// Independently recompute:
		//
		// m_i =
		// H(
		//     key_i ||
		//     LPC_i ||
		//     RPC_i
		// ) mod p
		// --------------------------------------------------------

		expectedMapped, err :=
			t.internalFieldMapper(
				key,
				lpc,
				rpc,
				t.modulus,
			)

		if err != nil {

			return nil, fmt.Errorf(
				"failed to recompute internal mapped value at depth %d entry %d: %w",
				depth,
				i,
				err,
			)
		}

		if expectedMapped == nil {

			return nil, fmt.Errorf(
				"internal mapper returned nil at depth %d entry %d",
				depth,
				i,
			)
		}

		if n.internalMappedValues[i] == nil {

			return nil, fmt.Errorf(
				"stored internal mapped value is nil at depth %d entry %d",
				depth,
				i,
			)
		}

		if expectedMapped.Cmp(
			n.internalMappedValues[i],
		) != 0 {

			return nil, fmt.Errorf(
				"internal mapped value mismatch at depth %d entry %d",
				depth,
				i,
			)
		}
	}

	// ============================================================
	// STEP 3:
	//
	// Recompute this node's polynomial commitment.
	//
	// IMPORTANT:
	//
	// Internal-node behavior is UNCHANGED.
	//
	// Internal-node mapped values are still interpolated at:
	//
	//     0, 1, 2, ...
	//
	// using commitFieldValues().
	// ============================================================

	recomputed, err :=
		t.commitFieldValues(
			n.internalMappedValues,
			n.nodeSRS,
		)

	if err != nil {

		return nil, fmt.Errorf(
			"failed to recompute internal commitment at depth %d: %w",
			depth,
			err,
		)
	}

	// ============================================================
	// STEP 4:
	//
	// Compare independently recomputed node commitment with
	// stored commitment.
	// ============================================================

	if !n.commitment.Equal(
		recomputed,
	) {

		return nil, fmt.Errorf(
			"internal node commitment mismatch at depth %d",
			depth,
		)
	}

	return recomputed, nil
}
