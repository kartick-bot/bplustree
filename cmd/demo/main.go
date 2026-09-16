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
