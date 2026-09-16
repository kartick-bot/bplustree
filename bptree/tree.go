package bptree

import (
	"fmt"
	"math/big"
)

type Comparator[K any] func(a, b K) int

type Tree[K any, V any] struct {
	root *node[K, V]

	// B+ tree order.
	order int

	// Key comparison function.
	compare Comparator[K]

	// Computes:
	//
	//     value = H(key)
	hasher Hasher[K]

	// Maps a leaf entry:
	//
	//     (key, H(key))
	//
	// into Z_p.
	fieldMapper FieldMapper[K]

	// Maps an internal-node entry:
	//
	//     (key, LPC, RPC)
	//
	// into Z_p.
	internalFieldMapper InternalFieldMapper[K]

	// BN254 scalar-field modulus.
	modulus *big.Int
}

func New[K any, V any](
	order int,
	compare Comparator[K],
	hasher Hasher[K],
	fieldMapper FieldMapper[K],
	internalFieldMapper InternalFieldMapper[K],
) (*Tree[K, V], error) {

	if order < 3 {
		return nil, fmt.Errorf(
			"B+ tree order must be at least 3",
		)
	}

	if compare == nil {
		return nil, fmt.Errorf(
			"comparator cannot be nil",
		)
	}

	if hasher == nil {
		return nil, fmt.Errorf(
			"hasher cannot be nil",
		)
	}

	if fieldMapper == nil {
		return nil, fmt.Errorf(
			"leaf field mapper cannot be nil",
		)
	}

	if internalFieldMapper == nil {
		return nil, fmt.Errorf(
			"internal field mapper cannot be nil",
		)
	}

	// ============================================================
	// BN254 scalar field
	// ============================================================

	modulus :=
		BN254ScalarModulus()

	// ============================================================
	// Initial root leaf SRS
	// ============================================================

	leafSRS, err :=
		newKZGSRS(
			uint64(order-1),
			modulus,
		)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to create SRS for initial leaf: %w",
			err,
		)
	}

	// ============================================================
	// Initial root leaf
	// ============================================================

	root := &node[K, V]{
		isLeaf: true,

		entries: make(
			[]Entry[K],
			0,
			order-1,
		),

		mappedValues: make(
			[]*big.Int,
			0,
			order-1,
		),

		// Existing leaf SRS.
		leafSRS: leafSRS,

		// nodeSRS is the generalized SRS field.
		//
		// For leaves these two currently point to
		// the SAME SRS.
		nodeSRS: leafSRS,
	}

	return &Tree[K, V]{
		root:                root,
		order:               order,
		compare:             compare,
		hasher:              hasher,
		fieldMapper:         fieldMapper,
		internalFieldMapper: internalFieldMapper,
		modulus:             modulus,
	}, nil
}

func (t *Tree[K, V]) Order() int {
	return t.order
}

func (t *Tree[K, V]) MaxKeys() int {
	return t.order - 1
}

func (t *Tree[K, V]) Modulus() *big.Int {
	return new(big.Int).Set(
		t.modulus,
	)
}