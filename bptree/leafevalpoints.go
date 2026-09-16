package bptree

import "fmt"

// assignLeafEvaluationPoints assigns global evaluation points
// to every leaf entry.
//
// Each leaf reserves exactly order-1 slots.
//
// For order = 4:
//
//	Leaf 0 -> slots 0, 1, 2
//	Leaf 1 -> slots 3, 4, 5
//	Leaf 2 -> slots 6, 7, 8
//	...
//
// Only occupied slots are stored in evaluationPoints.
func (t *Tree[K, V]) assignLeafEvaluationPoints() error {

	if t.root == nil {
		return fmt.Errorf(
			"cannot assign evaluation points to empty tree",
		)
	}

	slotsPerLeaf := t.order - 1

	if slotsPerLeaf <= 0 {
		return fmt.Errorf(
			"invalid slots per leaf: %d",
			slotsPerLeaf,
		)
	}

	// Find the leftmost leaf.
	leaf := t.root

	for !leaf.isLeaf {

		if len(leaf.children) == 0 {
			return fmt.Errorf(
				"internal node has no children",
			)
		}

		leaf = leaf.children[0]
	}

	leafIndex := uint64(0)

	for leaf != nil {

		base :=
			leafIndex *
				uint64(slotsPerLeaf)

		leaf.evaluationPoints =
			make(
				[]uint64,
				len(leaf.entries),
			)

		for i := range leaf.entries {

			leaf.evaluationPoints[i] =
				base + uint64(i)
		}

		leafIndex++

		leaf = leaf.next
	}

	return nil
}
