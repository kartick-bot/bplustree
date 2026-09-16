package bptree


import "fmt"

// subtreeInfo contains the smallest and largest data keys
// stored in a subtree.
type subtreeInfo[K any] struct {
	minKey   K
	maxKey   K
	hasValue bool
}

// Validate checks all B+ tree invariants.
//
// It verifies:
//
//  1. Node occupancy rules
//  2. Keys are sorted and unique
//  3. Internal-node child/key relationships
//  4. All leaves occur at the same depth
//  5. Leaf linked-list correctness
//  6. Value = H(Key)
//  7. entries[i] corresponds to mappedValues[i]
//  8. mappedValues[i] is in Z_p
//  9. mappedValues[i] is correctly recomputed
// 10. No two entries map to the same Z_p value
func (t *Tree[K, V]) Validate() error {

	if t.root == nil {
		return fmt.Errorf("tree has no root")
	}

	if t.modulus == nil {
		return fmt.Errorf("field modulus is nil")
	}

	if t.modulus.Sign() <= 0 {
		return fmt.Errorf("field modulus must be positive")
	}

	if t.fieldMapper == nil {
		return fmt.Errorf("field mapper is nil")
	}

	if t.hasher == nil {
		return fmt.Errorf("hasher is nil")
	}

	leafDepth := -1

	var leaves []*node[K, V]

	// Stores all field elements already encountered.
	//
	// We use the decimal string representation as
	// the map key so we can detect collisions.
	seenMappedValues := make(map[string]struct{})

	_, err := t.validateNode(
		t.root,
		true,
		0,
		&leafDepth,
		&leaves,
		seenMappedValues,
	)

	if err != nil {
		return err
	}

	// ==================================================
	// CHECK LEAF LINKED LIST
	// ==================================================

	for i := 0; i < len(leaves); i++ {

		// Every leaf except the final leaf must point
		// exactly to the next leaf encountered during
		// the tree traversal.
		if i < len(leaves)-1 {

			if leaves[i].next != leaves[i+1] {
				return fmt.Errorf(
					"broken leaf next pointer between leaf %d and leaf %d",
					i,
					i+1,
				)
			}

			left := leaves[i]
			right := leaves[i+1]

			// Verify ordering across adjacent leaves.
			if len(left.entries) > 0 &&
				len(right.entries) > 0 {

				leftMax :=
					left.entries[len(left.entries)-1].Key

				rightMin :=
					right.entries[0].Key

				if t.compare(leftMax, rightMin) >= 0 {
					return fmt.Errorf(
						"leaf ordering violation: left maximum key must be smaller than right minimum key",
					)
				}
			}

		} else {

			// The final leaf must terminate the chain.
			if leaves[i].next != nil {
				return fmt.Errorf(
					"last leaf has a non-nil next pointer",
				)
			}
		}
	}

	return nil
}

// validateNode recursively validates one node.
//
// seenMappedValues is shared by every recursive call so
// collisions can be detected across the entire tree.
func (t *Tree[K, V]) validateNode(
	n *node[K, V],
	isRoot bool,
	depth int,
	leafDepth *int,
	leaves *[]*node[K, V],
	seenMappedValues map[string]struct{},
) (subtreeInfo[K], error) {

	var empty subtreeInfo[K]

	if n == nil {
		return empty, fmt.Errorf(
			"nil node encountered at depth %d",
			depth,
		)
	}

	// ==================================================
	// LEAF NODE
	// ==================================================

	if n.isLeaf {

		// Leaves must not contain separator keys.
		if len(n.keys) != 0 {
			return empty, fmt.Errorf(
				"leaf at depth %d contains internal separator keys",
				depth,
			)
		}

		// Leaves must not have children.
		if len(n.children) != 0 {
			return empty, fmt.Errorf(
				"leaf at depth %d has children",
				depth,
			)
		}

		// ==================================================
		// OCCUPANCY
		// ==================================================

		maxEntries := t.order - 1

		if len(n.entries) > maxEntries {
			return empty, fmt.Errorf(
				"leaf at depth %d has %d entries; maximum is %d",
				depth,
				len(n.entries),
				maxEntries,
			)
		}

		// Minimum leaf occupancy:
		//
		// ceil((b - 1) / 2)
		//
		// For integer arithmetic this is:
		//
		// b / 2
		//
		// Examples:
		//
		// order 4 -> min 2
		// order 5 -> min 2
		// order 6 -> min 3
		minEntries := t.order / 2

		if !isRoot && len(n.entries) < minEntries {
			return empty, fmt.Errorf(
				"leaf at depth %d has %d entries; minimum is %d",
				depth,
				len(n.entries),
				minEntries,
			)
		}

		// ==================================================
		// ENTRY / MAPPED-VALUE ALIGNMENT
		// ==================================================

		if len(n.entries) != len(n.mappedValues) {
			return empty, fmt.Errorf(
				"leaf at depth %d has %d entries but %d mapped values",
				depth,
				len(n.entries),
				len(n.mappedValues),
			)
		}

		// ==================================================
		// CHECK SORTED AND UNIQUE KEYS
		// ==================================================

		for i := 1; i < len(n.entries); i++ {

			previous :=
				n.entries[i-1].Key

			current :=
				n.entries[i].Key

			if t.compare(previous, current) >= 0 {
				return empty, fmt.Errorf(
					"leaf at depth %d has duplicate or unsorted keys",
					depth,
				)
			}
		}

		// ==================================================
		// CHECK EACH LEAF ENTRY
		// ==================================================

		for i, entry := range n.entries {

			// ----------------------------------------------
			// Check:
			//
			// value = H(key)
			// ----------------------------------------------

			expectedHash :=
				t.hasher(entry.Key)

			if entry.Value != expectedHash {
				return empty, fmt.Errorf(
					"incorrect hash value for key %v",
					entry.Key,
				)
			}

			// ----------------------------------------------
			// Retrieve corresponding mapped value
			// ----------------------------------------------

			mapped :=
				n.mappedValues[i]

			if mapped == nil {
				return empty, fmt.Errorf(
					"nil mapped value for key %v",
					entry.Key,
				)
			}

			// ----------------------------------------------
			// Check membership in Z_p:
			//
			// 0 <= mapped < p
			// ----------------------------------------------

			if mapped.Sign() < 0 ||
				mapped.Cmp(t.modulus) >= 0 {

				return empty, fmt.Errorf(
					"mapped value for key %v is outside Z_p",
					entry.Key,
				)
			}

			// ----------------------------------------------
			// Recompute:
			//
			// H(
			//   domain ||
			//   encode(key) ||
			//   value
			// ) mod p
			// ----------------------------------------------

			expectedMapped, err :=
				t.fieldMapper(
					entry.Key,
					entry.Value,
					t.modulus,
				)

			if err != nil {
				return empty, fmt.Errorf(
					"failed to recompute mapped value for key %v: %w",
					entry.Key,
					err,
				)
			}

			if expectedMapped == nil {
				return empty, fmt.Errorf(
					"field mapper returned nil for key %v",
					entry.Key,
				)
			}

			// ----------------------------------------------
			// Compare stored and recomputed values
			// ----------------------------------------------

			if mapped.Cmp(expectedMapped) != 0 {
				return empty, fmt.Errorf(
					"incorrect mapped value for key %v",
					entry.Key,
				)
			}

			// ----------------------------------------------
			// Collision check
			// ----------------------------------------------

			mappedID :=
				mapped.String()

			if _, exists :=
				seenMappedValues[mappedID]; exists {

				return empty, fmt.Errorf(
					"Z_p mapping collision detected for key %v",
					entry.Key,
				)
			}

			seenMappedValues[mappedID] =
				struct{}{}
		}

		// ==================================================
		// CHECK LEAF DEPTH
		// ==================================================

		if *leafDepth == -1 {

			// First leaf establishes expected depth.
			*leafDepth = depth

		} else if depth != *leafDepth {

			return empty, fmt.Errorf(
				"leaves occur at different depths: expected %d, found %d",
				*leafDepth,
				depth,
			)
		}

		// Save leaf so Validate() can later check
		// next pointers.
		*leaves =
			append(
				*leaves,
				n,
			)

		// Empty root leaf is valid.
		if len(n.entries) == 0 {
			return empty, nil
		}

		return subtreeInfo[K]{
			minKey: n.entries[0].Key,

			maxKey:
				n.entries[len(n.entries)-1].Key,

			hasValue: true,
		}, nil
	}

	// ==================================================
	// INTERNAL NODE
	// ==================================================

	// Internal nodes must not contain leaf entries.
	if len(n.entries) != 0 {
		return empty, fmt.Errorf(
			"internal node at depth %d contains leaf entries",
			depth,
		)
	}

	// Internal nodes should also have no mapped values.
	if len(n.mappedValues) != 0 {
		return empty, fmt.Errorf(
			"internal node at depth %d contains mapped leaf values",
			depth,
		)
	}

	// Internal nodes are not part of the leaf linked list.
	if n.next != nil {
		return empty, fmt.Errorf(
			"internal node at depth %d has a next pointer",
			depth,
		)
	}

	// ==================================================
	// CHILD / KEY RELATIONSHIP
	// ==================================================
	//
	// An internal node with k keys must have k+1 children.
	//
	// Example:
	//
	//        [30 60]
	//
	//       /   |   \
	//      C0  C1   C2
	//
	if len(n.children) != len(n.keys)+1 {
		return empty, fmt.Errorf(
			"internal node at depth %d has %d keys but %d children",
			depth,
			len(n.keys),
			len(n.children),
		)
	}

	// ==================================================
	// MAXIMUM OCCUPANCY
	// ==================================================

	if len(n.keys) > t.order-1 {
		return empty, fmt.Errorf(
			"internal node at depth %d has %d keys; maximum is %d",
			depth,
			len(n.keys),
			t.order-1,
		)
	}

	if len(n.children) > t.order {
		return empty, fmt.Errorf(
			"internal node at depth %d has %d children; maximum is %d",
			depth,
			len(n.children),
			t.order,
		)
	}

	// ==================================================
	// MINIMUM OCCUPANCY
	// ==================================================

	if isRoot {

		// A non-leaf root needs at least two children.
		if len(n.children) < 2 {
			return empty, fmt.Errorf(
				"internal root must have at least 2 children",
			)
		}

	} else {

		// Minimum internal-node children:
		//
		// ceil(b / 2)
		minChildren :=
			(t.order + 1) / 2

		if len(n.children) < minChildren {
			return empty, fmt.Errorf(
				"internal node at depth %d has %d children; minimum is %d",
				depth,
				len(n.children),
				minChildren,
			)
		}
	}

	// ==================================================
	// SEPARATOR KEYS MUST BE SORTED
	// ==================================================

	for i := 1; i < len(n.keys); i++ {

		if t.compare(
			n.keys[i-1],
			n.keys[i],
		) >= 0 {

			return empty, fmt.Errorf(
				"internal node at depth %d has duplicate or unsorted separator keys",
				depth,
			)
		}
	}

	// ==================================================
	// RECURSIVELY VALIDATE CHILDREN
	// ==================================================

	childInfo :=
		make(
			[]subtreeInfo[K],
			len(n.children),
		)

	for i, child := range n.children {

		info, err :=
			t.validateNode(
				child,
				false,
				depth+1,
				leafDepth,
				leaves,
				seenMappedValues,
			)

		if err != nil {
			return empty, err
		}

		if !info.hasValue {
			return empty, fmt.Errorf(
				"internal node at depth %d has an empty child subtree",
				depth,
			)
		}

		childInfo[i] = info
	}

	// ==================================================
	// VERIFY SEPARATOR RELATIONSHIPS
	// ==================================================
	//
	// For:
	//
	//          [K0 K1]
	//         /   |   \
	//        C0  C1   C2
	//
	// We require:
	//
	// K0 = minimum key in C1
	// K1 = minimum key in C2
	//
	// and:
	//
	// max(C0) < K0
	// max(C1) < K1
	//
	for i, separator := range n.keys {

		leftChild :=
			childInfo[i]

		rightChild :=
			childInfo[i+1]

		// Separator must equal the minimum key
		// in its right child subtree.
		if t.compare(
			separator,
			rightChild.minKey,
		) != 0 {

			return empty, fmt.Errorf(
				"incorrect separator key %v at depth %d",
				separator,
				depth,
			)
		}

		// Everything in the left subtree must
		// be strictly smaller than separator.
		if t.compare(
			leftChild.maxKey,
			separator,
		) >= 0 {

			return empty, fmt.Errorf(
				"subtree ordering violation at separator %v at depth %d",
				separator,
				depth,
			)
		}
	}

	// Return the complete key range covered by this subtree.
	return subtreeInfo[K]{
		minKey:
			childInfo[0].minKey,

		maxKey:
			childInfo[len(childInfo)-1].maxKey,

		hasValue: true,
	}, nil
}