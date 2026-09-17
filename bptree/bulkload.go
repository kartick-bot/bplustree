package bptree

import (
	"fmt"
	"math/big"
)

// ============================================================
// BULK LOAD SORTED KEYS
// ============================================================
//
// BulkLoadSortedKeys constructs a balanced B+ tree directly
// from a strictly increasing list of keys.
//
// IMPORTANT:
//
// This is deliberately different from repeated Insert().
//
// Repeated insertion can leave many nodes only partially full
// depending on insertion order. For scale experiments we want
// a densely packed B+ tree whose depth is determined by:
//
//	number of keys
//	order
//	node capacity
//
// The caller is responsible for generating the random keys and
// sorting them before calling this function.
//
// For order b:
//
//	max leaf entries      = b - 1
//	max internal children = b
//
// Non-root nodes are distributed as evenly as possible so that
// the final group is not under-filled.
func (t *Tree[K, V]) BulkLoadSortedKeys(
	keys []K,
) error {

	if len(keys) == 0 {
		return fmt.Errorf(
			"cannot bulk-load zero keys",
		)
	}

	if t.order < 3 {
		return fmt.Errorf(
			"invalid B+ tree order %d",
			t.order,
		)
	}

	// ========================================================
	// VERIFY STRICT SORTING / UNIQUENESS
	// ========================================================

	for i := 1; i < len(keys); i++ {

		if t.compare(
			keys[i-1],
			keys[i],
		) >= 0 {

			return fmt.Errorf(
				"bulk-load keys must be strictly increasing; invalid order at positions %d and %d",
				i-1,
				i,
			)
		}
	}

	maxLeafEntries :=
		t.order - 1

	// Standard non-root minimum leaf occupancy.
	minLeafEntries :=
		(maxLeafEntries + 1) / 2

	// ========================================================
	// DETERMINE BALANCED LEAF SIZES
	// ========================================================

	leafSizes, err :=
		balancedGroupSizes(
			len(keys),
			maxLeafEntries,
			minLeafEntries,
			true,
		)

	if err != nil {
		return fmt.Errorf(
			"failed computing leaf sizes: %w",
			err,
		)
	}

	// ========================================================
	// BUILD LEAVES
	// ========================================================

	leaves :=
		make(
			[]*node[K, V],
			0,
			len(leafSizes),
		)

	keyOffset := 0

	for leafIndex, leafSize := range leafSizes {

		leaf :=
			&node[K, V]{
				isLeaf: true,

				entries: make(
					[]Entry[K],
					0,
					leafSize,
				),

				mappedValues: make(
					[]*big.Int,
					0,
					leafSize,
				),
			}

		for localIndex := 0; localIndex < leafSize; localIndex++ {

			key :=
				keys[keyOffset]

			keyOffset++

			// --------------------------------------------
			// H(key)
			// --------------------------------------------

			value :=
				t.hasher(
					key,
				)

			// --------------------------------------------
			// Map:
			//
			//     (key, H(key)) -> Z_p
			// --------------------------------------------

			mapped, err :=
				t.fieldMapper(
					key,
					value,
					t.modulus,
				)

			if err != nil {
				return fmt.Errorf(
					"failed mapping key in leaf %d entry %d: %w",
					leafIndex,
					localIndex,
					err,
				)
			}

			if mapped == nil {
				return fmt.Errorf(
					"leaf mapper returned nil for leaf %d entry %d",
					leafIndex,
					localIndex,
				)
			}

			if mapped.Sign() < 0 ||
				mapped.Cmp(t.modulus) >= 0 {

				return fmt.Errorf(
					"mapped value outside Z_p for leaf %d entry %d",
					leafIndex,
					localIndex,
				)
			}

			leaf.entries =
				append(
					leaf.entries,
					Entry[K]{
						Key:   key,
						Value: value,
					},
				)

			leaf.mappedValues =
				append(
					leaf.mappedValues,
					new(big.Int).Set(
						mapped,
					),
				)
		}

		leaves =
			append(
				leaves,
				leaf,
			)
	}

	if keyOffset != len(keys) {
		return fmt.Errorf(
			"bulk loader consumed %d keys but expected %d",
			keyOffset,
			len(keys),
		)
	}

	// ========================================================
	// LINK LEAVES
	// ========================================================

	for i := 0; i+1 < len(leaves); i++ {

		leaves[i].next =
			leaves[i+1]
	}

	// ========================================================
	// SPECIAL CASE:
	//
	// TREE CONSISTS ONLY OF ONE LEAF
	// ========================================================

	if len(leaves) == 1 {

		t.root =
			leaves[0]

		return nil
	}

	// ========================================================
	// BUILD INTERNAL LEVELS BOTTOM-UP
	// ========================================================
	//
	// For order 5:
	//
	//     max children = 5
	//
	// Non-root internal nodes require at least:
	//
	//     ceil(5 / 2) = 3 children.
	// ========================================================

	maxChildren :=
		t.order

	minChildren :=
		(t.order + 1) / 2

	currentLevel :=
		leaves

	// Continue building NON-ROOT internal levels until all
	// remaining nodes can fit directly under one root.
	for len(currentLevel) > maxChildren {

		groupSizes, err :=
			balancedGroupSizes(
				len(currentLevel),
				maxChildren,
				minChildren,
				false,
			)

		if err != nil {
			return fmt.Errorf(
				"failed grouping internal level containing %d nodes: %w",
				len(currentLevel),
				err,
			)
		}

		nextLevel :=
			make(
				[]*node[K, V],
				0,
				len(groupSizes),
			)

		childOffset := 0

		for parentIndex, groupSize := range groupSizes {

			end :=
				childOffset +
					groupSize

			if end >
				len(currentLevel) {

				return fmt.Errorf(
					"internal grouping overflow at parent %d",
					parentIndex,
				)
			}

			children :=
				currentLevel[childOffset:end]

			parent, err :=
				t.newBulkInternalNode(
					children,
				)

			if err != nil {
				return fmt.Errorf(
					"failed creating internal parent %d: %w",
					parentIndex,
					err,
				)
			}

			nextLevel =
				append(
					nextLevel,
					parent,
				)

			childOffset =
				end
		}

		if childOffset !=
			len(currentLevel) {

			return fmt.Errorf(
				"internal bulk-load grouping consumed %d nodes but expected %d",
				childOffset,
				len(currentLevel),
			)
		}

		currentLevel =
			nextLevel
	}

	// ========================================================
	// BUILD ROOT
	// ========================================================
	//
	// Root is allowed to have fewer children than an ordinary
	// non-root internal node, but must still have at least two
	// children when it is internal.
	// ========================================================

	if len(currentLevel) < 2 ||
		len(currentLevel) > t.order {

		return fmt.Errorf(
			"invalid number of root children: %d",
			len(currentLevel),
		)
	}

	root, err :=
		t.newBulkInternalNode(
			currentLevel,
		)

	if err != nil {
		return fmt.Errorf(
			"failed creating bulk-loaded root: %w",
			err,
		)
	}

	t.root =
		root

	return nil
}

// ============================================================
// CREATE ONE INTERNAL NODE
// ============================================================
//
// Given ordered children:
//
//	C0, C1, C2, ...
//
// the separator keys are:
//
//	min(C1), min(C2), ...
//
// Therefore:
//
//	keys[i] = minimum key in children[i+1]
//
// which matches the existing B+ tree search rule:
//
//	key < k0          -> C0
//	k0 <= key < k1    -> C1
//	...
func (t *Tree[K, V]) newBulkInternalNode(
	children []*node[K, V],
) (*node[K, V], error) {

	if len(children) < 2 {
		return nil, fmt.Errorf(
			"internal node requires at least two children",
		)
	}

	if len(children) > t.order {
		return nil, fmt.Errorf(
			"internal node has %d children but order is %d",
			len(children),
			t.order,
		)
	}

	parent :=
		&node[K, V]{
			isLeaf: false,

			children: append(
				[]*node[K, V](nil),
				children...,
			),

			keys: make(
				[]K,
				0,
				len(children)-1,
			),
		}

	// Child 0 has no separator before it.
	//
	// For every child i >= 1, store the minimum key of
	// that child as the preceding separator.
	for i := 1; i < len(children); i++ {

		separator, err :=
			minimumKeyInSubtree(
				children[i],
			)

		if err != nil {
			return nil, fmt.Errorf(
				"failed finding separator for child %d: %w",
				i,
				err,
			)
		}

		parent.keys =
			append(
				parent.keys,
				separator,
			)
	}

	if len(parent.children) !=
		len(parent.keys)+1 {

		return nil, fmt.Errorf(
			"constructed internal node has %d keys but %d children",
			len(parent.keys),
			len(parent.children),
		)
	}

	return parent, nil
}

// ============================================================
// MINIMUM KEY IN SUBTREE
// ============================================================

func minimumKeyInSubtree[K any, V any](
	n *node[K, V],
) (K, error) {

	var zero K

	if n == nil {
		return zero, fmt.Errorf(
			"cannot find minimum key of nil subtree",
		)
	}

	current :=
		n

	// Minimum key of an internal subtree always lies in its
	// left-most child.
	for !current.isLeaf {

		if len(current.children) == 0 {
			return zero, fmt.Errorf(
				"internal node has no children",
			)
		}

		if current.children[0] == nil {
			return zero, fmt.Errorf(
				"internal node has nil left-most child",
			)
		}

		current =
			current.children[0]
	}

	if len(current.entries) == 0 {
		return zero, fmt.Errorf(
			"leaf contains no entries",
		)
	}

	return current.entries[0].Key, nil
}

// ============================================================
// BALANCED GROUP SIZES
// ============================================================
//
// Example:
//
//	total = 15625
//	max   = 4
//
// gives:
//
//	3907 leaves
//
// distributed as:
//
//	3904 leaves with 4 entries
//	   3 leaves with 3 entries
//
// instead of:
//
//	3906 leaves with 4 entries
//	   1 leaf with 1 entry
//
// This prevents an under-filled final node.
func balancedGroupSizes(
	total int,
	maxPerGroup int,
	minPerGroup int,
	allowSingleGroupBelowMinimum bool,
) ([]int, error) {

	if total <= 0 {
		return nil, fmt.Errorf(
			"total must be positive",
		)
	}

	if maxPerGroup <= 0 {
		return nil, fmt.Errorf(
			"maximum group size must be positive",
		)
	}

	if minPerGroup <= 0 {
		return nil, fmt.Errorf(
			"minimum group size must be positive",
		)
	}

	if minPerGroup >
		maxPerGroup {

		return nil, fmt.Errorf(
			"minimum group size %d exceeds maximum %d",
			minPerGroup,
			maxPerGroup,
		)
	}

	// One group is enough.
	if total <= maxPerGroup {

		if !allowSingleGroupBelowMinimum &&
			total < minPerGroup {

			return nil, fmt.Errorf(
				"single group size %d is below minimum %d",
				total,
				minPerGroup,
			)
		}

		return []int{
			total,
		}, nil
	}

	numberOfGroups :=
		(total +
			maxPerGroup -
			1) /
			maxPerGroup

	if total <
		numberOfGroups*
			minPerGroup {

		return nil, fmt.Errorf(
			"cannot distribute %d items into %d groups with minimum size %d",
			total,
			numberOfGroups,
			minPerGroup,
		)
	}

	base :=
		total /
			numberOfGroups

	extra :=
		total %
			numberOfGroups

	sizes :=
		make(
			[]int,
			numberOfGroups,
		)

	for i := 0; i < numberOfGroups; i++ {

		sizes[i] =
			base

		if i < extra {
			sizes[i]++
		}

		if sizes[i] <
			minPerGroup {

			return nil, fmt.Errorf(
				"group %d has size %d below minimum %d",
				i,
				sizes[i],
				minPerGroup,
			)
		}

		if sizes[i] >
			maxPerGroup {

			return nil, fmt.Errorf(
				"group %d has size %d above maximum %d",
				i,
				sizes[i],
				maxPerGroup,
			)
		}
	}

	return sizes, nil
}

// ============================================================
// INTERNAL DEPTH
// ============================================================
//
// InternalDepth returns the number of internal nodes on every
// root -> leaf path.
//
// Examples:
//
//	leaf root
//	    depth = 0
//
//	root -> leaf
//	    depth = 1
//
//	root -> internal -> leaf
//	    depth = 2
//
// The function checks ALL branches and returns an error if the
// tree is not balanced.
func (t *Tree[K, V]) InternalDepth() (
	int,
	error,
) {

	if t.root == nil {
		return 0, fmt.Errorf(
			"cannot compute depth of empty tree",
		)
	}

	expectedLeafDepth :=
		-1

	var walk func(
		n *node[K, V],
		depth int,
	) error

	walk =
		func(
			n *node[K, V],
			depth int,
		) error {

			if n == nil {
				return fmt.Errorf(
					"nil node encountered at depth %d",
					depth,
				)
			}

			if n.isLeaf {

				if expectedLeafDepth == -1 {
					expectedLeafDepth =
						depth

					return nil
				}

				if expectedLeafDepth !=
					depth {

					return fmt.Errorf(
						"unbalanced B+ tree: expected leaf depth %d but found leaf at depth %d",
						expectedLeafDepth,
						depth,
					)
				}

				return nil
			}

			if len(n.children) == 0 {
				return fmt.Errorf(
					"internal node at depth %d has no children",
					depth,
				)
			}

			if len(n.children) !=
				len(n.keys)+1 {

				return fmt.Errorf(
					"internal node at depth %d has %d keys but %d children",
					depth,
					len(n.keys),
					len(n.children),
				)
			}

			for childIndex, child := range n.children {

				if child == nil {
					return fmt.Errorf(
						"internal node at depth %d has nil child %d",
						depth,
						childIndex,
					)
				}

				if err :=
					walk(
						child,
						depth+1,
					); err != nil {

					return err
				}
			}

			return nil
		}

	if err :=
		walk(
			t.root,
			0,
		); err != nil {

		return 0, err
	}

	if expectedLeafDepth < 0 {
		return 0, fmt.Errorf(
			"tree contains no leaves",
		)
	}

	return expectedLeafDepth, nil
}
