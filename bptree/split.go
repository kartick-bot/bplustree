package bptree

import (
	"fmt"
	"math/big"
)

// splitLeaf splits an overflowing leaf.
//
// The original left leaf keeps its existing SRS.
//
// The newly created right leaf gets a NEW,
// independently generated KZG SRS.
func (t *Tree[K, V]) splitLeaf(
	left *node[K, V],
) (*splitResult[K, V], error) {

	mid := len(left.entries) / 2

	// ------------------------------------------------
	// Create a new independent SRS for the new leaf
	// ------------------------------------------------

	rightSRS, err := newKZGSRS(
		uint64(t.order-1),
		t.modulus,
	)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to create SRS for new leaf: %w",
			err,
		)
	}

	// ------------------------------------------------
	// Create right leaf
	// ------------------------------------------------

	right := &node[K, V]{
		isLeaf: true,

		entries: append(
			[]Entry[K](nil),
			left.entries[mid:]...,
		),

		mappedValues: cloneBigInts(
			left.mappedValues[mid:],
		),

		// Each newly created leaf gets its own SRS.
		leafSRS: rightSRS,

		next: left.next,
	}

	// ------------------------------------------------
	// Left leaf keeps first half
	// ------------------------------------------------

	left.entries =
		left.entries[:mid]

	left.mappedValues =
		left.mappedValues[:mid]

	// IMPORTANT:
	//
	// left.leafSRS is NOT changed.
	//
	// The original leaf keeps its existing SRS.

	// Maintain linked-list structure.
	left.next = right

	// Separator = first key in right leaf.
	separator :=
		right.entries[0].Key

	return &splitResult[K, V]{
		separator: separator,
		right:     right,
	}, nil
}

// splitInternal splits an overflowing internal node.
//
// Example:
//
//     [20 40 60 80]
//
// promotes:
//
//            60
//
// resulting in:
//
//     [20 40]      [80]
//
// The promoted separator 60 is removed from both
// resulting internal nodes.
func (t *Tree[K, V]) splitInternal(
	left *node[K, V],
) *splitResult[K, V] {

	mid := len(left.keys) / 2

	separator :=
		left.keys[mid]

	right := &node[K, V]{
		isLeaf: false,

		keys: append(
			[]K(nil),
			left.keys[mid+1:]...,
		),

		children: append(
			[]*node[K, V](nil),
			left.children[mid+1:]...,
		),
	}

	// Left internal node keeps everything
	// before the promoted separator.
	left.keys =
		left.keys[:mid]

	// k keys require k+1 children.
	left.children =
		left.children[:mid+1]

	return &splitResult[K, V]{
		separator: separator,
		right:     right,
	}
}

// cloneBigInts makes independent copies of big.Int values.
//
// big.Int is mutable, so we do not want the left and
// right leaves sharing pointers to the same integers.
func cloneBigInts(
	values []*big.Int,
) []*big.Int {

	result := make(
		[]*big.Int,
		len(values),
	)

	for i, value := range values {

		if value != nil {
			result[i] =
				new(big.Int).Set(value)
		}
	}

	return result
}