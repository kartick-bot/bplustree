package bptree

import (
	"fmt"
	"strings"

	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

// PrintLeafCommitments prints the LPC/RPC commitments
// stored at internal nodes whose children are leaves.
func (t *Tree[K, V]) PrintLeafCommitments() {

	if t.root == nil {
		fmt.Println("<empty tree>")
		return
	}

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("LEAF KZG POINTER COMMITMENTS")
	fmt.Println("============================================================")
	fmt.Println()

	t.printLeafCommitmentsNode(
		t.root,
		0,
	)
}

func (t *Tree[K, V]) printLeafCommitmentsNode(
	n *node[K, V],
	depth int,
) {

	if n == nil || n.isLeaf {
		return
	}

	// ------------------------------------------------
	// Determine whether this internal node points
	// directly to leaves.
	// ------------------------------------------------

	childrenAreLeaves := true

	for _, child := range n.children {

		if child == nil || !child.isLeaf {
			childrenAreLeaves = false
			break
		}
	}

	// ------------------------------------------------
	// This is a bottom-level internal node.
	// Its child commitments correspond to leaves.
	// ------------------------------------------------

	if childrenAreLeaves {

		fmt.Printf(
			"Internal node %s\n",
			internalKeysLabel(n),
		)

		fmt.Println(
			"------------------------------------------------------------",
		)

		if len(n.childCommitments) != len(n.children) {

			fmt.Printf(
				"ERROR: %d children but %d child commitments\n\n",
				len(n.children),
				len(n.childCommitments),
			)

			return
		}

		for i, key := range n.keys {

			lpc := n.childCommitments[i]
			rpc := n.childCommitments[i+1]

			fmt.Printf(
				"Separator key %v\n",
				key,
			)

			fmt.Printf(
				"  LPC[%d] = %s\n",
				i,
				shortCommitment(lpc),
			)

			fmt.Printf(
				"  RPC[%d] = %s\n",
				i,
				shortCommitment(rpc),
			)

			// ----------------------------------------
			// For i > 0:
			//
			// LPC[i] must equal RPC[i-1].
			// ----------------------------------------

			if i > 0 {

				previousRPC :=
					n.childCommitments[i]

				equal :=
					commitmentsEqual(
						lpc,
						previousRPC,
					)

				fmt.Printf(
					"  LPC[%d] == RPC[%d] : %v\n",
					i,
					i-1,
					equal,
				)
			}

			fmt.Println()
		}

		return
	}

	// ------------------------------------------------
	// Otherwise recurse until we reach internal nodes
	// that directly index leaves.
	// ------------------------------------------------

	for _, child := range n.children {

		t.printLeafCommitmentsNode(
			child,
			depth+1,
		)
	}
}

// internalKeysLabel formats:
//
//     [30 60 80]
//
func internalKeysLabel[K any, V any](
	n *node[K, V],
) string {

	var builder strings.Builder

	builder.WriteString("[")

	for i, key := range n.keys {

		if i > 0 {
			builder.WriteString(" ")
		}

		builder.WriteString(
			fmt.Sprintf("%v", key),
		)
	}

	builder.WriteString("]")

	return builder.String()
}

// shortCommitment prints a compact representation of
// a BN254 G1 KZG commitment.
//
// The actual commitment is a full compressed G1 point.
// We display only the first 8 bytes for readability.
func shortCommitment(
	commitment *kzg.Digest,
) string {

	if commitment == nil {
		return "<nil>"
	}

	compressed :=
		commitment.Bytes()

	return fmt.Sprintf(
		"%x...",
		compressed[:8],
	)
}

// commitmentsEqual compares two KZG commitments.
func commitmentsEqual(
	a *kzg.Digest,
	b *kzg.Digest,
) bool {

	if a == nil || b == nil {
		return false
	}

	return a.Equal(b)
}