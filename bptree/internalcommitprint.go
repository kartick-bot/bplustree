package bptree

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"
)

// PrintInternalCommitmentDetails prints the recursive
// KZG information for every internal node, including the root.
//
// BuildCommitments() must be called before this function.
func (t *Tree[K, V]) PrintInternalCommitmentDetails() error {

	if t.root == nil {
		return fmt.Errorf(
			"tree has no root",
		)
	}

	if t.root.isLeaf {
		fmt.Println(
			"Tree contains only one leaf; there are no internal nodes.",
		)
		return nil
	}

	fmt.Println()
	fmt.Println("================================================================")
	fmt.Println("RECURSIVE INTERNAL-NODE KZG DETAILS")
	fmt.Println("================================================================")

	internalNumber := 0

	return t.printInternalNodeRecursive(
		t.root,
		&internalNumber,
	)
}

// printInternalNodeRecursive prints internal nodes recursively.
//
// We recurse into internal children first so that the output
// follows the bottom-up commitment construction:
//
//     leaves
//       ↓
//     lower internal nodes
//       ↓
//     root
func (t *Tree[K, V]) printInternalNodeRecursive(
	n *node[K, V],
	internalNumber *int,
) error {

	if n == nil {
		return fmt.Errorf(
			"nil node encountered",
		)
	}

	if n.isLeaf {
		return nil
	}

	// ------------------------------------------------------------
	// First print lower internal nodes.
	// ------------------------------------------------------------

	for _, child := range n.children {

		if child != nil && !child.isLeaf {

			if err := t.printInternalNodeRecursive(
				child,
				internalNumber,
			); err != nil {
				return err
			}
		}
	}

	// ------------------------------------------------------------
	// Now print this internal node.
	// ------------------------------------------------------------

	isRoot := n == t.root

	fmt.Println()
	fmt.Println("================================================================")

	if isRoot {
		fmt.Println("ROOT NODE")
	} else {
		fmt.Printf(
			"INTERNAL NODE %d\n",
			*internalNumber,
		)
	}

	fmt.Println("================================================================")

	fmt.Println()
	fmt.Printf(
		"Keys: %v\n",
		n.keys,
	)

	// ============================================================
	// SANITY CHECKS
	// ============================================================

	if len(n.children) != len(n.keys)+1 {

		return fmt.Errorf(
			"internal node has %d keys but %d children",
			len(n.keys),
			len(n.children),
		)
	}

	if len(n.childCommitments) != len(n.children) {

		return fmt.Errorf(
			"internal node has %d children but %d child commitments",
			len(n.children),
			len(n.childCommitments),
		)
	}

	if len(n.internalMappedValues) != len(n.keys) {

		return fmt.Errorf(
			"internal node has %d keys but %d mapped values",
			len(n.keys),
			len(n.internalMappedValues),
		)
	}

	if n.nodeSRS == nil {

		return fmt.Errorf(
			"internal node has no SRS",
		)
	}

	if n.commitment == nil {

		return fmt.Errorf(
			"internal node has no commitment",
		)
	}

	// ============================================================
	// PRINT EACH INTERNAL ENTRY
	// ============================================================

	fmt.Println()
	fmt.Println("Internal entries:")

	for i, key := range n.keys {

		lpc :=
			n.childCommitments[i]

		rpc :=
			n.childCommitments[i+1]

		if lpc == nil {
			return fmt.Errorf(
				"LPC[%d] is nil",
				i,
			)
		}

		if rpc == nil {
			return fmt.Errorf(
				"RPC[%d] is nil",
				i,
			)
		}

		if n.internalMappedValues[i] == nil {
			return fmt.Errorf(
				"mapped value %d is nil",
				i,
			)
		}

		lpcBytes :=
			lpc.Bytes()

		rpcBytes :=
			rpc.Bytes()

		fmt.Println()
		fmt.Printf(
			"  Entry %d\n",
			i,
		)

		fmt.Printf(
			"    key          = %v\n",
			key,
		)

		fmt.Printf(
			"    LPC[%d]       = %x\n",
			i,
			lpcBytes,
		)

		fmt.Printf(
			"    RPC[%d]       = %x\n",
			i,
			rpcBytes,
		)

		fmt.Printf(
			"    mapped m_%d   = %s\n",
			i,
			n.internalMappedValues[i].String(),
		)

		// --------------------------------------------------------
		// Demonstrate shared child-pointer relationship:
		//
		// LPC[i] = RPC[i-1]
		// --------------------------------------------------------

		if i > 0 {

			previousRPC :=
				n.childCommitments[i]

			equal :=
				lpc.Equal(
					previousRPC,
				)

			fmt.Printf(
				"    LPC[%d] == RPC[%d] = %v\n",
				i,
				i-1,
				equal,
			)
		}
	}

	// ============================================================
	// BUILD FIELD-ELEMENT ARRAY
	// ============================================================

	values :=
		make(
			[]fr.Element,
			len(n.internalMappedValues),
		)

	for i, mapped :=
		range n.internalMappedValues {

		values[i].SetBigInt(
			mapped,
		)
	}

	// ============================================================
	// INTERPOLATE INTERNAL-NODE POLYNOMIAL
	// ============================================================

	poly :=
		polynomial.InterpolateOnRange(
			values,
		)

	coefficients :=
		[]fr.Element(poly)

	fmt.Println()
	fmt.Println("Internal-node polynomial:")

	fmt.Printf(
		"  number of mapped values = %d\n",
		len(values),
	)

	fmt.Printf(
		"  degree <= %d\n",
		len(coefficients)-1,
	)

	// ============================================================
	// EVALUATION FORM
	// ============================================================

	fmt.Println()
	fmt.Println("Evaluation form:")

	for i, mapped :=
		range n.internalMappedValues {

		fmt.Printf(
			"  f(%d) = %s\n",
			i,
			mapped.String(),
		)
	}

	// ============================================================
	// COEFFICIENT FORM
	// ============================================================

	fmt.Println()
	fmt.Println("Coefficient form:")

	for i := range coefficients {

		var coefficient big.Int

		coefficients[i].BigInt(
			&coefficient,
		)

		fmt.Printf(
			"  a_%d = %s\n",
			i,
			coefficient.String(),
		)

		fmt.Printf(
			"        0x%s\n",
			coefficient.Text(16),
		)
	}

	// ============================================================
	// NODE-SPECIFIC SRS
	// ============================================================

	fmt.Println()
	fmt.Println("Node SRS:")

	fmt.Printf(
		"  number of G1 powers = %d\n",
		len(n.nodeSRS.Pk.G1),
	)

	for i :=
		0;
		i < len(coefficients);
		i++ {

		srsBytes :=
			n.nodeSRS.Pk.G1[i].Bytes()

		fmt.Printf(
			"  [tau^%d]G1 = %x\n",
			i,
			srsBytes,
		)
	}

	// ============================================================
	// FINAL NODE COMMITMENT
	// ============================================================

	commitmentBytes :=
		n.commitment.Bytes()

	fmt.Println()
	fmt.Println("Final node KZG commitment:")

	fmt.Printf(
		"  C_node = %x\n",
		commitmentBytes,
	)

	// ============================================================
	// EXPLAIN WHAT THE PARENT SEES
	// ============================================================

	if isRoot {

		fmt.Println()
		fmt.Println(
			"  This is the final recursive ROOT commitment.",
		)

	} else {

		fmt.Println()
		fmt.Println(
			"  This commitment becomes one child commitment",
		)

		fmt.Println(
			"  (LPC or RPC) in the node's parent.",
		)
	}

	if !isRoot {
		*internalNumber =
			*internalNumber + 1
	}

	return nil
}