package bptree

import (
	"fmt"
	"math/big"
)

// splitResult describes what must be inserted into the parent
// after a child node splits.
type splitResult[K any, V any] struct {
	separator K
	right     *node[K, V]
}

// Insert inserts a key into the B+ tree.
//
// For every key k:
//
//	value = H(k)
//
// and:
//
//	mapped = H(domain || encode(k) || value) mod p
//
// The leaf therefore stores:
//
//	entries[i]      = (k, H(k))
//	mappedValues[i] = mapped value in Z_p
func (t *Tree[K, V]) Insert(key K) error {

	result, err := t.insert(
		t.root,
		key,
	)

	if err != nil {
		return err
	}

	// ------------------------------------------------
	// Root did not split
	// ------------------------------------------------

	if result == nil {
		return nil
	}

	// ------------------------------------------------
	// Root split
	// ------------------------------------------------
	//
	// Old root becomes the left child.
	// Newly created node becomes the right child.
	//
	//              separator
	//             /         \
	//       old root        right
	//

	oldRoot := t.root

	t.root = &node[K, V]{
		isLeaf: false,

		keys: []K{
			result.separator,
		},

		children: []*node[K, V]{
			oldRoot,
			result.right,
		},
	}

	return nil
}

// insert recursively inserts key into the subtree rooted at n.
//
// It returns:
//
//	nil, nil
//
// when no split occurs.
//
// If a split occurs, it returns:
//
//	splitResult
//
// containing:
//
//	separator
//	new right node
func (t *Tree[K, V]) insert(
	n *node[K, V],
	key K,
) (*splitResult[K, V], error) {

	// ============================================================
	// LEAF NODE
	// ============================================================

	if n.isLeaf {

		// --------------------------------------------------------
		// Find insertion position
		// --------------------------------------------------------

		position :=
			t.findLeafPosition(
				n,
				key,
			)

		// --------------------------------------------------------
		// Duplicate-key check
		// --------------------------------------------------------

		if position < len(n.entries) &&
			t.compare(
				n.entries[position].Key,
				key,
			) == 0 {

			// Key already exists.
			// Do not insert another copy.
			return nil, nil
		}

		// --------------------------------------------------------
		// Step 1:
		//
		// value = H(key)
		// --------------------------------------------------------

		value :=
			t.hasher(key)

		entry := Entry[K]{
			Key:   key,
			Value: value,
		}

		// --------------------------------------------------------
		// Step 2:
		//
		// mapped =
		//
		// H(
		//     domain ||
		//     encode(key) ||
		//     value
		// ) mod p
		//
		// mapped ∈ Z_p
		// --------------------------------------------------------

		mapped, err :=
			t.fieldMapper(
				key,
				value,
				t.modulus,
			)

		if err != nil {

			return nil, fmt.Errorf(
				"failed to map key %v into Z_p: %w",
				key,
				err,
			)
		}

		if mapped == nil {

			return nil, fmt.Errorf(
				"field mapper returned nil for key %v",
				key,
			)
		}

		// --------------------------------------------------------
		// Sanity check:
		//
		// 0 <= mapped < p
		// --------------------------------------------------------

		if mapped.Sign() < 0 ||
			mapped.Cmp(t.modulus) >= 0 {

			return nil, fmt.Errorf(
				"mapped value for key %v is outside Z_p",
				key,
			)
		}

		// --------------------------------------------------------
		// Insert:
		//
		// entries[position]
		//
		// and:
		//
		// mappedValues[position]
		//
		// at EXACTLY the same index.
		// --------------------------------------------------------

		n.entries =
			insertEntry(
				n.entries,
				position,
				entry,
			)

		n.mappedValues =
			insertMappedValue(
				n.mappedValues,
				position,
				mapped,
			)

		// --------------------------------------------------------
		// No leaf overflow
		// --------------------------------------------------------

		if len(n.entries) <= t.MaxKeys() {
			return nil, nil
		}

		// --------------------------------------------------------
		// Leaf overflow
		// ------------------------------------------------
		//
		// IMPORTANT:
		//
		// splitLeaf now returns:
		//
		// (*splitResult[K,V], error)
		//
		// because the newly created right leaf must receive
		// its own independently generated KZG SRS.
		// --------------------------------------------------------

		result, err :=
			t.splitLeaf(n)

		if err != nil {
			return nil, err
		}

		return result, nil
	}

	// ============================================================
	// INTERNAL NODE
	// ============================================================

	// ------------------------------------------------------------
	// Determine which child should contain key
	// ------------------------------------------------------------

	childIndex :=
		t.findChildIndex(
			n,
			key,
		)

	// ------------------------------------------------------------
	// Recursively insert into child
	// ------------------------------------------------------------

	result, err :=
		t.insert(
			n.children[childIndex],
			key,
		)

	if err != nil {
		return nil, err
	}

	// ------------------------------------------------------------
	// Child did not split
	// ------------------------------------------------------------

	if result == nil {
		return nil, nil
	}

	// ------------------------------------------------------------
	// Child split
	// ------------------------------------------------------------
	//
	// Insert the separator into the internal node.
	//

	n.keys =
		insertKey(
			n.keys,
			childIndex,
			result.separator,
		)

	// Insert the new right child immediately after
	// the original child.
	n.children =
		insertChild(
			n.children,
			childIndex+1,
			result.right,
		)

	// ------------------------------------------------------------
	// Internal node still fits
	// ------------------------------------------------------------

	if len(n.keys) <= t.MaxKeys() {
		return nil, nil
	}

	// ------------------------------------------------------------
	// Internal-node overflow
	// ------------------------------------------------------------

	return t.splitInternal(n), nil
}

// findLeafPosition determines where a key belongs
// inside the sorted leaf entries.
//
// Example:
//
// leaf:
//
//	[20 40 70]
//
// inserting:
//
//	50
//
// returns:
//
//	2
func (t *Tree[K, V]) findLeafPosition(
	n *node[K, V],
	key K,
) int {

	i := 0

	for i < len(n.entries) &&
		t.compare(
			n.entries[i].Key,
			key,
		) < 0 {

		i++
	}

	return i
}

// findChildIndex determines which child of an
// internal node should contain key.
//
// Example:
//
//	         [30 60]
//	        /   |   \
//	      C0   C1   C2
//
// key < 30:
//
//	C0
//
// 30 <= key < 60:
//
//	C1
//
// key >= 60:
//
//	C2
func (t *Tree[K, V]) findChildIndex(
	n *node[K, V],
	key K,
) int {

	i := 0

	for i < len(n.keys) &&
		t.compare(
			key,
			n.keys[i],
		) >= 0 {

		i++
	}

	return i
}

// insertEntry inserts a complete:
//
//	(key, H(key))
//
// entry at the specified position in a leaf.
func insertEntry[K any](
	entries []Entry[K],
	index int,
	entry Entry[K],
) []Entry[K] {

	// Increase slice size by one.
	entries =
		append(
			entries,
			entry,
		)

	// Shift elements to the right.
	copy(
		entries[index+1:],
		entries[index:len(entries)-1],
	)

	// Insert new entry.
	entries[index] =
		entry

	return entries
}

// insertMappedValue inserts the Z_p value corresponding
// to entries[index] at exactly the same index.
//
// Because big.Int is mutable, we store an independent copy.
func insertMappedValue(
	values []*big.Int,
	index int,
	value *big.Int,
) []*big.Int {

	valueCopy :=
		new(big.Int).Set(
			value,
		)

	// Increase slice size.
	values =
		append(
			values,
			valueCopy,
		)

	// Shift existing values right.
	copy(
		values[index+1:],
		values[index:len(values)-1],
	)

	// Insert mapped value.
	values[index] =
		valueCopy

	return values
}

// insertKey inserts a separator key into an internal node.
func insertKey[K any](
	keys []K,
	index int,
	key K,
) []K {

	// Increase slice size.
	keys =
		append(
			keys,
			key,
		)

	// Shift keys right.
	copy(
		keys[index+1:],
		keys[index:len(keys)-1],
	)

	// Insert separator.
	keys[index] =
		key

	return keys
}

// insertChild inserts a child pointer into an internal node.
func insertChild[K any, V any](
	children []*node[K, V],
	index int,
	child *node[K, V],
) []*node[K, V] {

	// Increase slice size.
	children =
		append(
			children,
			child,
		)

	// Shift child pointers right.
	copy(
		children[index+1:],
		children[index:len(children)-1],
	)

	// Insert new child pointer.
	children[index] =
		child

	return children
}