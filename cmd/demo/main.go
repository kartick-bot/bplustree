package main

import (
	"fmt"
	"math/rand"

	"bplustree/bptree"
)

func intComparator(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func main() {

	// ============================================================
	// TREE PARAMETERS
	// ============================================================

	const order = 4
	const numberOfKeys = 16

	// ============================================================
	// CREATE TREE
	// ============================================================

	// Order 4 means:
	//
	// maximum children per internal node = 4
	// maximum keys per internal node     = 3
	// maximum entries per leaf           = 3
	tree, err := bptree.New[int, string](
		order,
		intComparator,
		bptree.HashInt,
		bptree.MapIntEntryToField,
		bptree.MapIntInternalEntryToField,
	)

	if err != nil {
		panic(err)
	}

	// ============================================================
	// GENERATE AND INSERT RANDOM UNIQUE KEYS
	// ============================================================

	used := make(map[int]bool)

	insertedKeys :=
		make(
			[]int,
			0,
			numberOfKeys,
		)

	for len(used) < numberOfKeys {

		// Random key in [10, 100].
		key := rand.Intn(91) + 10

		if used[key] {
			continue
		}

		used[key] = true

		if err := tree.Insert(key); err != nil {
			panic(err)
		}

		insertedKeys =
			append(
				insertedKeys,
				key,
			)
	}

	// ============================================================
	// PRINT INPUT KEYS
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("INPUT KEYS")
	fmt.Println("============================================================")

	for _, key := range insertedKeys {
		fmt.Printf("%d ", key)
	}

	fmt.Println()
	fmt.Println()

	// ============================================================
	// PRINT TREE ORDER
	// ============================================================

	fmt.Println("============================================================")
	fmt.Println("B+ TREE PARAMETERS")
	fmt.Println("============================================================")

	fmt.Printf("Order = %d\n", order)

	fmt.Printf(
		"Maximum internal-node keys = %d\n",
		order-1,
	)

	fmt.Printf(
		"Maximum children per internal node = %d\n",
		order,
	)

	fmt.Printf(
		"Maximum entries per leaf = %d\n",
		order-1,
	)

	fmt.Println()

	// ============================================================
	// VALIDATE TREE STRUCTURE
	// ============================================================

	if err := tree.Validate(); err != nil {

		panic(
			fmt.Sprintf(
				"B+ tree validation failed before KZG commitments: %v",
				err,
			),
		)
	}

	// ============================================================
	// PRINT COMPLETE B+ TREE
	// ============================================================

	fmt.Println("============================================================")
	fmt.Println("B+ TREE")
	fmt.Println("============================================================")

	tree.PrintPretty()

	fmt.Println()

	// ============================================================
	// BUILD ALL KZG COMMITMENTS AND OPENING PROOFS
	// ============================================================

	// This recursively:
	//
	// 1. assigns global leaf evaluation points
	// 2. interpolates leaf polynomials
	// 3. creates leaf commitments
	// 4. generates leaf opening proofs
	// 5. verifies leaf pairings
	// 6. constructs internal-node mapped values
	// 7. interpolates internal-node polynomials
	// 8. creates internal-node commitments
	// 9. generates internal opening proofs
	// 10. verifies internal-node pairings
	if err := tree.BuildCommitments(); err != nil {
		panic(err)
	}

	// ============================================================
	// TEST ONE COMPLETE MEMBERSHIP PATH
	// ============================================================
	//
	// We select one key that was actually inserted into the tree.
	//
	// ExportMembershipPath first performs the NORMAL B+ TREE SEARCH:
	//
	//     root -> internal nodes -> leaf
	//
	// and then exports the authentication information in:
	//
	//     leaf -> internal nodes -> root
	//
	// order for the eventual SNARK circuit.

	testKey := insertedKeys[0]

	membershipPath, err :=
		tree.ExportMembershipPath(testKey)

	if err != nil {
		panic(
			fmt.Errorf(
				"failed to export membership path for key %d: %w",
				testKey,
				err,
			),
		)
	}

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("B+ TREE MEMBERSHIP PATH TEST")
	fmt.Println("============================================================")
	fmt.Printf("Search key = %d\n", testKey)
	fmt.Println()

	// ============================================================
	// PRINT ROOT -> LEAF SEARCH
	// ============================================================

	fmt.Println("ROOT -> LEAF B+ TREE SEARCH")
	fmt.Println("------------------------------------------------------------")

	// membershipPath.Levels is stored leaf -> root,
	// so walk it backwards to reconstruct the actual search order.

	for levelIndex :=
		len(membershipPath.Levels) - 1; levelIndex >= 0; levelIndex-- {

		level :=
			membershipPath.Levels[levelIndex]

		fmt.Printf(
			"Internal level %d:\n",
			len(membershipPath.Levels)-levelIndex,
		)

		fmt.Printf(
			"  selected child index = %d\n",
			level.ChildIndex,
		)

		fmt.Printf(
			"  separator index      = %d\n",
			level.SeparatorIndex,
		)

		fmt.Printf(
			"  separator key        = %d\n",
			level.SeparatorKey,
		)

		// --------------------------------------------------------
		// Print the exact B+ tree routing condition.
		// --------------------------------------------------------

		switch {

		case level.HasLowerBound &&
			level.HasUpperBound:

			fmt.Printf(
				"  routing condition    = %d <= %d < %d\n",
				level.LowerBound,
				testKey,
				level.UpperBound,
			)

		case level.HasLowerBound:

			fmt.Printf(
				"  routing condition    = %d <= %d\n",
				level.LowerBound,
				testKey,
			)

		case level.HasUpperBound:

			fmt.Printf(
				"  routing condition    = %d < %d\n",
				testKey,
				level.UpperBound,
			)

		default:

			fmt.Println(
				"  routing condition    = no separator bound",
			)
		}

		fmt.Println()
	}

	// ============================================================
	// PRINT REACHED LEAF
	// ============================================================

	fmt.Println("LEAF REACHED")
	fmt.Println("------------------------------------------------------------")

	fmt.Printf(
		"Key                   = %d\n",
		membershipPath.Key,
	)

	fmt.Printf(
		"Leaf entry index      = %d\n",
		membershipPath.LeafEntryIndex,
	)

	fmt.Printf(
		"Global evaluation z   = %d\n",
		membershipPath.LeafEvaluationPoint,
	)

	fmt.Printf(
		"Leaf mapped value     = %s\n",
		membershipPath.LeafMappedValue.String(),
	)

	fmt.Printf(
		"Leaf commitment       = %x\n",
		membershipPath.LeafCommitment.Bytes(),
	)

	fmt.Println()

	// ============================================================
	// PRINT LEAF -> ROOT AUTHENTICATION PATH
	// ============================================================

	fmt.Println("LEAF -> ROOT AUTHENTICATION PATH")
	fmt.Println("------------------------------------------------------------")

	fmt.Println("Start with leaf commitment:")
	fmt.Printf(
		"  C_leaf = %x\n",
		membershipPath.LeafCommitment.Bytes(),
	)

	fmt.Println()

	for levelIndex, level := range membershipPath.Levels {

		fmt.Printf(
			"Authentication level %d:\n",
			levelIndex+1,
		)

		fmt.Printf(
			"  separator key   = %d\n",
			level.SeparatorKey,
		)

		fmt.Printf(
			"  evaluation z    = %d\n",
			level.EvaluationPoint,
		)

		fmt.Printf(
			"  mapped value    = %s\n",
			level.MappedValue.String(),
		)

		fmt.Printf(
			"  LPC             = %x\n",
			level.LPC.Bytes(),
		)

		fmt.Printf(
			"  RPC             = %x\n",
			level.RPC.Bytes(),
		)

		if level.CurrentChildIsLPC {

			fmt.Println(
				"  current child   = LPC",
			)

		} else {

			fmt.Println(
				"  current child   = RPC",
			)
		}

		fmt.Printf(
			"  parent commit   = %x\n",
			level.ParentCommitment.Bytes(),
		)

		fmt.Println()
	}

	// ============================================================
	// FINAL ROOT CHECK
	// ============================================================

	fmt.Println("PUBLIC ROOT")
	fmt.Println("------------------------------------------------------------")

	fmt.Printf(
		"Root commitment = %x\n",
		membershipPath.RootCommitment.Bytes(),
	)

	fmt.Println()

	fmt.Printf(
		"Membership path contains %d internal authentication levels\n",
		len(membershipPath.Levels),
	)

	fmt.Printf(
		"Total KZG verifications required for key %d = %d\n",
		testKey,
		1+len(membershipPath.Levels),
	)

	fmt.Println()

	fmt.Println(
		"MEMBERSHIP PATH EXPORT PASSED",
	)

	fmt.Println()

	// ============================================================
	// EXPORT REAL TREE DATA FOR SNARK
	// ============================================================

	snarkData, err := tree.ExportSNARKData()
	if err != nil {
		panic(
			fmt.Errorf(
				"failed to export B+ tree for SNARK: %w",
				err,
			),
		)
	}

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("SNARK TREE EXPORT")
	fmt.Println("============================================================")

	fmt.Printf("Tree order       = %d\n", snarkData.Order)
	fmt.Printf("Number of nodes  = %d\n", len(snarkData.Nodes))
	fmt.Printf("Root node index  = %d\n", snarkData.RootIndex)

	fmt.Println()
	fmt.Println("Nodes are exported in post-order:")
	fmt.Println("children -> parents -> root")
	fmt.Println()

	for nodeIndex, node := range snarkData.Nodes {

		nodeType := "INTERNAL"

		if node.IsLeaf {
			nodeType = "LEAF"
		}

		if node.IsRoot {
			nodeType = "ROOT"
		}

		fmt.Println("------------------------------------------------------------")
		fmt.Printf("SNARK NODE %d [%s]\n", nodeIndex, nodeType)
		fmt.Println("------------------------------------------------------------")

		fmt.Printf(
			"Mapped values      = %d\n",
			len(node.MappedValues),
		)

		fmt.Printf(
			"Evaluation points  = %v\n",
			node.EvaluationPoints,
		)

		fmt.Printf(
			"Opening proofs     = %d\n",
			len(node.OpeningProofs),
		)

		if node.IsLeaf {

			fmt.Printf(
				"Leaf entries       = %d\n",
				len(node.Entries),
			)

		} else {

			fmt.Printf(
				"Separator keys     = %v\n",
				node.Keys,
			)

			fmt.Printf(
				"Child indices      = %v\n",
				node.ChildIndices,
			)

			fmt.Printf(
				"Child commitments  = %d\n",
				len(node.ChildCommitments),
			)
		}

		fmt.Println()

		for i, value := range node.MappedValues {

			fmt.Printf(
				"  evaluation %d: z = %d, value = %s\n",
				i,
				node.EvaluationPoints[i],
				value.String(),
			)
		}

		fmt.Println()
	}

	fmt.Println("------------------------------------------------------------")
	fmt.Println("ROOT")
	fmt.Println("------------------------------------------------------------")

	fmt.Printf(
		"Root index      = %d\n",
		snarkData.RootIndex,
	)

	fmt.Printf(
		"Root commitment = %v\n",
		snarkData.RootCommitment,
	)

	fmt.Println()
	fmt.Println("SNARK tree export PASSED")

	// ============================================================
	// LEAF DETAILS
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("LEAF NODE DETAILS")
	fmt.Println("============================================================")

	// PrintKZGDetails() now prints the COMPLETE information
	// for each leaf before moving to the next leaf.
	//
	// For every leaf:
	//
	// 1. keys
	// 2. H(key)
	// 3. global evaluation points
	// 4. mapped field values
	// 5. interpolating polynomial
	// 6. polynomial evaluation checks
	// 7. SRS
	// 8. coefficient contributions
	// 9. final KZG commitment
	// 10. opening proofs
	// 11. pairing equations
	// 12. pairing verification
	// 13. parent LPC/RPC interpretation
	//
	// Thus:
	//
	// LEAF 0
	//   all details
	//
	// LEAF 1
	//   all details
	//
	// ...
	if err := tree.PrintKZGDetails(); err != nil {
		panic(err)
	}

	// ============================================================
	// INTERNAL NODE DETAILS
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("INTERNAL NODE DETAILS")
	fmt.Println("============================================================")

	// For each internal node:
	//
	// separator keys
	// LPC
	// RPC
	// mapped values
	// polynomial
	// SRS
	// commitment
	// opening proofs
	// pairing verification
	if err := tree.PrintInternalCommitmentDetails(); err != nil {
		panic(err)
	}

	// ============================================================
	// FINAL VALIDATION
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("FINAL VALIDATION")
	fmt.Println("============================================================")

	fmt.Println()
	fmt.Println("Validating B+ tree...")

	if err := tree.Validate(); err != nil {

		fmt.Println("B+ tree validation FAILED:")
		fmt.Println(err)

	} else {

		fmt.Println("B+ tree validation PASSED")
	}

	fmt.Println()
	fmt.Println("Validating recursive KZG commitments...")

	if err := tree.ValidateCommitments(); err != nil {

		fmt.Println("Recursive KZG validation FAILED:")
		fmt.Println(err)

	} else {

		fmt.Println("Recursive KZG validation PASSED")
	}
}
