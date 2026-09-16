package bptree

import (
	"fmt"
)

// PrintLeafOpeningProofs prints the KZG opening proofs
// generated for every leaf.
//
// No pairing verification is performed here.
func (t *Tree[K, V]) PrintLeafOpeningProofs() error {

	if t.root == nil {
		return fmt.Errorf("tree has no root")
	}

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("LEAF KZG OPENING PROOFS")
	fmt.Println("============================================================")

	leafNumber := 0

	return t.printLeafOpeningProofsRecursive(
		t.root,
		&leafNumber,
	)
}

func (t *Tree[K, V]) printLeafOpeningProofsRecursive(
	n *node[K, V],
	leafNumber *int,
) error {

	if n == nil {
		return fmt.Errorf("nil node encountered")
	}

	if !n.isLeaf {

		for _, child := range n.children {

			if err :=
				t.printLeafOpeningProofsRecursive(
					child,
					leafNumber,
				); err != nil {

				return err
			}
		}

		return nil
	}

	if len(n.openingProofs) != len(n.mappedValues) {

		return fmt.Errorf(
			"leaf %d has %d mapped values but %d opening proofs",
			*leafNumber,
			len(n.mappedValues),
			len(n.openingProofs),
		)
	}

	fmt.Println()
	fmt.Printf("LEAF %d\n", *leafNumber)
	fmt.Println("------------------------------------------------------------")

	for i, proof := range n.openingProofs {

		proofBytes :=
			proof.H.Bytes()

		fmt.Printf(
			"Evaluation point z = %d\n",
			i,
		)

		fmt.Printf(
			"  mapped value y = %s\n",
			n.mappedValues[i].String(),
		)

		fmt.Printf(
			"  opening proof π = %x\n",
			proofBytes,
		)

		fmt.Println()
	}

	*leafNumber =
		*leafNumber + 1

	return nil
}
