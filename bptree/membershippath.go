package bptree

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

// ============================================================
// ONE AUTHENTICATED SEPARATOR RELATION
// ============================================================
//
// For separator k_i:
//
//	child[i] ---- k_i ---- child[i+1]
//	   LPC                    RPC
//
// The internal mapped value is:
//
//	H(
//	    "BPLUS-INTERNAL-ENTRY"
//	    || k_i
//	    || LPC
//	    || RPC
//	) mod p
//
// and this value is opened from the parent's KZG commitment at
// evaluation point i.
type MembershipSeparatorProof[K any] struct {
	SeparatorIndex int
	SeparatorKey   K

	LPC kzg.Digest
	RPC kzg.Digest

	MappedValue *big.Int

	EvaluationPoint uint64

	OpeningProof kzg.OpeningProof
}

// ============================================================
// ONE INTERNAL LEVEL OF A MEMBERSHIP PATH
// ============================================================

type MembershipPathLevel[K any] struct {

	// Child chosen by the normal B+ tree search.
	ChildIndex int

	// ========================================================
	// SINGLE AUTHENTICATED SEPARATOR RELATION
	// ========================================================
	//
	// Exactly ONE separator is authenticated per internal level.
	//
	// If ChildIndex == 0:
	//
	//     use separator 0
	//
	// and prove:
	//
	//     searchKey < separator
	//
	// and:
	//
	//     currentChild == LPC
	//
	//
	// If ChildIndex > 0:
	//
	//     use separator ChildIndex-1
	//
	// and prove:
	//
	//     separator <= searchKey
	//
	// and:
	//
	//     currentChild == RPC
	//
	//
	// Therefore exactly one of LowerRelation or UpperRelation
	// is non-nil at every internal level.

	LowerRelation *MembershipSeparatorProof[K]
	UpperRelation *MembershipSeparatorProof[K]

	// ========================================================
	// PARENT KZG INFORMATION
	// ========================================================

	ParentCommitment kzg.Digest
	VerifyingKey     kzg.VerifyingKey

	// ========================================================
	// EXISTING DISPLAY / CANONICAL FIELDS
	// ========================================================
	//
	// These are retained so the current demo code continues
	// working.
	//
	// Canonical rule:
	//
	// child 0:
	//     use upper separator
	//     current child = LPC
	//
	// child i > 0:
	//     use lower separator
	//     current child = RPC

	SeparatorIndex int
	SeparatorKey   K

	CurrentChildIsLPC bool

	HasLowerBound bool
	LowerBound    K

	HasUpperBound bool
	UpperBound    K

	LPC kzg.Digest
	RPC kzg.Digest

	MappedValue *big.Int

	EvaluationPoint uint64

	OpeningProof kzg.OpeningProof
}

// ============================================================
// COMPLETE MEMBERSHIP PATH FOR ONE KEY
// ============================================================
//
// One object corresponds to:
//
//	ONE KEY
//	   ↓
//	ONE root-to-leaf B+ search
//	   ↓
//	ONE leaf-to-root authentication path
//	   ↓
//	eventually ONE PLONK proof
type MembershipPathData[K any] struct {
	Key     K
	KeyHash [32]byte

	// ========================================================
	// LEAF
	// ========================================================

	LeafEntryIndex int

	LeafEvaluationPoint uint64

	LeafMappedValue *big.Int

	LeafCommitment kzg.Digest

	LeafOpeningProof kzg.OpeningProof

	LeafVerifyingKey kzg.VerifyingKey

	// ========================================================
	// INTERNAL LEVELS
	// ========================================================
	//
	// Stored leaf -> root.
	Levels []MembershipPathLevel[K]

	// ========================================================
	// ROOT
	// ========================================================

	RootCommitment kzg.Digest
}

// ============================================================
// EXPORT MEMBERSHIP PATH
// ============================================================

func (t *Tree[K, V]) ExportMembershipPath(
	key K,
) (*MembershipPathData[K], error) {

	if t.root == nil {
		return nil, fmt.Errorf(
			"cannot export membership path from empty tree",
		)
	}

	if t.root.commitment == nil {
		return nil, fmt.Errorf(
			"tree has no root commitment; call BuildCommitments first",
		)
	}

	// ========================================================
	// ROOT -> LEAF B+ TREE SEARCH
	// ========================================================

	type routingStep struct {
		parent     *node[K, V]
		childIndex int
	}

	var route []routingStep

	current := t.root

	for !current.isLeaf {

		if len(current.children) != len(current.keys)+1 {
			return nil, fmt.Errorf(
				"internal node has %d keys but %d children",
				len(current.keys),
				len(current.children),
			)
		}

		// Exact same search rule as Search().
		childIndex := 0

		for childIndex < len(current.keys) &&
			t.compare(key, current.keys[childIndex]) >= 0 {

			childIndex++
		}

		if childIndex >= len(current.children) {
			return nil, fmt.Errorf(
				"invalid child index %d",
				childIndex,
			)
		}

		route = append(
			route,
			routingStep{
				parent:     current,
				childIndex: childIndex,
			},
		)

		current = current.children[childIndex]
	}

	// ========================================================
	// FIND KEY IN REACHED LEAF
	// ========================================================

	leaf := current

	leafEntryIndex := -1

	for i, entry := range leaf.entries {

		cmp := t.compare(key, entry.Key)

		if cmp == 0 {
			leafEntryIndex = i
			break
		}

		if cmp < 0 {
			break
		}
	}

	if leafEntryIndex < 0 {
		return nil, fmt.Errorf(
			"key not found in B+ tree",
		)
	}

	// ========================================================
	// VALIDATE LEAF CRYPTO
	// ========================================================

	if leaf.commitment == nil {
		return nil, fmt.Errorf(
			"leaf has no KZG commitment",
		)
	}

	if leaf.nodeSRS == nil {
		return nil, fmt.Errorf(
			"leaf has no KZG SRS",
		)
	}

	if leafEntryIndex >= len(leaf.mappedValues) {
		return nil, fmt.Errorf(
			"leaf mapped value missing for entry %d",
			leafEntryIndex,
		)
	}

	if leafEntryIndex >= len(leaf.evaluationPoints) {
		return nil, fmt.Errorf(
			"leaf evaluation point missing for entry %d",
			leafEntryIndex,
		)
	}

	if leafEntryIndex >= len(leaf.openingProofs) {
		return nil, fmt.Errorf(
			"leaf opening proof missing for entry %d",
			leafEntryIndex,
		)
	}

	if leaf.mappedValues[leafEntryIndex] == nil {
		return nil, fmt.Errorf(
			"leaf mapped value %d is nil",
			leafEntryIndex,
		)
	}

	result := &MembershipPathData[K]{
		Key:     key,
		KeyHash: leaf.entries[leafEntryIndex].Value,

		LeafEntryIndex: leafEntryIndex,

		LeafEvaluationPoint: leaf.evaluationPoints[leafEntryIndex],

		LeafMappedValue: new(big.Int).Set(
			leaf.mappedValues[leafEntryIndex],
		),

		LeafCommitment: *leaf.commitment,

		LeafOpeningProof: leaf.openingProofs[leafEntryIndex],

		LeafVerifyingKey: leaf.nodeSRS.Vk,

		Levels: make(
			[]MembershipPathLevel[K],
			0,
			len(route),
		),

		RootCommitment: *t.root.commitment,
	}

	// ========================================================
	// HELPER: EXPORT ONE AUTHENTICATED SEPARATOR
	// ========================================================

	exportSeparator :=
		func(
			parent *node[K, V],
			separatorIndex int,
		) (*MembershipSeparatorProof[K], error) {

			if separatorIndex < 0 ||
				separatorIndex >= len(parent.keys) {

				return nil, fmt.Errorf(
					"invalid separator index %d",
					separatorIndex,
				)
			}

			if separatorIndex >=
				len(parent.internalMappedValues) {

				return nil, fmt.Errorf(
					"mapped value missing for separator %d",
					separatorIndex,
				)
			}

			if separatorIndex >=
				len(parent.openingProofs) {

				return nil, fmt.Errorf(
					"opening proof missing for separator %d",
					separatorIndex,
				)
			}

			if separatorIndex+1 >=
				len(parent.childCommitments) {

				return nil, fmt.Errorf(
					"LPC/RPC missing for separator %d",
					separatorIndex,
				)
			}

			lpc :=
				parent.childCommitments[separatorIndex]

			rpc :=
				parent.childCommitments[separatorIndex+1]

			if lpc == nil {
				return nil, fmt.Errorf(
					"LPC is nil for separator %d",
					separatorIndex,
				)
			}

			if rpc == nil {
				return nil, fmt.Errorf(
					"RPC is nil for separator %d",
					separatorIndex,
				)
			}

			mapped :=
				parent.internalMappedValues[separatorIndex]

			if mapped == nil {
				return nil, fmt.Errorf(
					"mapped value is nil for separator %d",
					separatorIndex,
				)
			}

			return &MembershipSeparatorProof[K]{
				SeparatorIndex: separatorIndex,

				SeparatorKey: parent.keys[separatorIndex],

				LPC: *lpc,

				RPC: *rpc,

				MappedValue: new(big.Int).Set(
					mapped,
				),

				EvaluationPoint: uint64(separatorIndex),

				OpeningProof: parent.openingProofs[separatorIndex],
			}, nil
		}

	// ========================================================
	// LEAF -> ROOT AUTHENTICATION PATH
	// ========================================================

	for routeIndex := len(route) - 1; routeIndex >= 0; routeIndex-- {

		step := route[routeIndex]

		parent := step.parent
		childIndex := step.childIndex

		if parent == nil {
			return nil, fmt.Errorf(
				"nil parent in membership route",
			)
		}

		if parent.isLeaf {
			return nil, fmt.Errorf(
				"leaf unexpectedly appears as parent",
			)
		}

		if parent.commitment == nil {
			return nil, fmt.Errorf(
				"parent has no commitment",
			)
		}

		if parent.nodeSRS == nil {
			return nil, fmt.Errorf(
				"parent has no node-specific SRS",
			)
		}

		if len(parent.childCommitments) !=
			len(parent.children) {

			return nil, fmt.Errorf(
				"parent has %d children but %d child commitments",
				len(parent.children),
				len(parent.childCommitments),
			)
		}

		if childIndex < 0 ||
			childIndex >= len(parent.children) {

			return nil, fmt.Errorf(
				"invalid child index %d",
				childIndex,
			)
		}

		level := MembershipPathLevel[K]{
			ChildIndex: childIndex,

			ParentCommitment: *parent.commitment,

			VerifyingKey: parent.nodeSRS.Vk,
		}

		// ====================================================
		// EXACTLY ONE AUTHENTICATED SEPARATOR PER LEVEL
		// ====================================================
		//
		// childIndex == 0:
		//
		//     key < separator[0]
		//     current child = LPC[0]
		//
		// childIndex > 0:
		//
		//     separator[childIndex-1] <= key
		//     current child = RPC[childIndex-1]
		//
		// Therefore exactly ONE parent KZG opening is exported
		// for every internal authentication level.

		if childIndex == 0 {

			// =================================================
			// LEFT-MOST CHILD
			//
			// Authenticate separator 0 and prove:
			//
			//     key < separator[0]
			//
			//     current child == LPC[0]
			// =================================================

			if len(parent.keys) == 0 {
				return nil, fmt.Errorf(
					"internal node has no separator keys",
				)
			}

			upper, err :=
				exportSeparator(
					parent,
					0,
				)

			if err != nil {
				return nil, err
			}

			level.UpperRelation =
				upper

			level.HasUpperBound =
				true

			level.UpperBound =
				parent.keys[0]

			// Explicitly no lower relation.
			level.LowerRelation =
				nil

			level.HasLowerBound =
				false

		} else {

			// =================================================
			// NON-ZERO CHILD
			//
			// Authenticate the immediately preceding separator:
			//
			//     separator[childIndex-1] <= key
			//
			//     current child == RPC[childIndex-1]
			// =================================================

			separatorIndex :=
				childIndex - 1

			lower, err :=
				exportSeparator(
					parent,
					separatorIndex,
				)

			if err != nil {
				return nil, err
			}

			level.LowerRelation =
				lower

			level.HasLowerBound =
				true

			level.LowerBound =
				parent.keys[separatorIndex]

			// Explicitly no upper relation.
			level.UpperRelation =
				nil

			level.HasUpperBound =
				false
		}

		// ====================================================
		// SANITY CHECK:
		//
		// EXACTLY ONE RELATION MUST EXIST.
		// ====================================================

		relationCount := 0

		if level.LowerRelation != nil {
			relationCount++
		}

		if level.UpperRelation != nil {
			relationCount++
		}

		if relationCount != 1 {
			return nil, fmt.Errorf(
				"internal level has %d authenticated relations; expected exactly 1",
				relationCount,
			)
		}

		// ====================================================
		// PRESERVE OLD CANONICAL DISPLAY FIELDS
		// ====================================================

		var canonical *MembershipSeparatorProof[K]

		if childIndex == 0 {

			// Left-most child.
			//
			// Authenticate as LPC of first separator.
			canonical =
				level.UpperRelation

			level.CurrentChildIsLPC =
				true

		} else {

			// All non-zero children.
			//
			// Authenticate as RPC of preceding separator.
			canonical =
				level.LowerRelation

			level.CurrentChildIsLPC =
				false
		}

		if canonical == nil {
			return nil, fmt.Errorf(
				"canonical separator relation is nil",
			)
		}

		level.SeparatorIndex =
			canonical.SeparatorIndex

		level.SeparatorKey =
			canonical.SeparatorKey

		level.LPC =
			canonical.LPC

		level.RPC =
			canonical.RPC

		level.MappedValue =
			new(big.Int).Set(
				canonical.MappedValue,
			)

		level.EvaluationPoint =
			canonical.EvaluationPoint

		level.OpeningProof =
			canonical.OpeningProof

		result.Levels =
			append(
				result.Levels,
				level,
			)
	}

	return result, nil
}
