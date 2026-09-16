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
	// CREATE TREE
	// ============================================================

	// Order 4 means:
	//
	// maximum children per internal node = 4
	// maximum keys per internal node     = 3
	// maximum entries per leaf           = 3
	tree, err := bptree.New[int, string](
		4,
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

	fmt.Println("Randomly generated keys:")

	for len(used) < 16 {

		// Random key in [10, 100].
		key := rand.Intn(91) + 10

		// Prevent duplicate generated keys.
		if used[key] {
			continue
		}

		used[key] = true

		// Insert key.
		//
		// Internally:
		//
		// value = H(key)
		//
		// mapped =
		// H(domain || key || value) mod p
		if err := tree.Insert(key); err != nil {
			panic(err)
		}

		fmt.Printf("%d ", key)
	}

	fmt.Println()
	fmt.Println()

	// ============================================================
	// VALIDATE TREE BEFORE COMMITMENTS
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
	// BUILD LEAF KZG COMMITMENTS
	// ============================================================

	// This MUST happen before PrintLeafCommitments()
	// or PrintKZGDetails().
	if err := tree.BuildCommitments(); err != nil {
		panic(err)
	}
	if err := tree.PrintLeafOpeningProofs(); err != nil {
		panic(err)
	}
	if err := tree.PrintInternalCommitmentDetails(); err != nil {
		panic(err)
	}

	// ============================================================
	// PRINT B+ TREE
	// ============================================================

	fmt.Println("B+ Tree:")
	tree.PrintPretty()

	// ============================================================
	// PRINT LEAF DATA
	// ============================================================

	// Shows:
	//
	// key
	// H(key)
	// mapped value in Z_p
	tree.PrintLeafData()

	// ============================================================
	// PRINT LPC / RPC COMMITMENTS
	// ============================================================

	// Shows commitments associated with each child pointer.
	//
	// For separator i:
	//
	// LPC[i] = childCommitments[i]
	// RPC[i] = childCommitments[i+1]
	//
	// Therefore:
	//
	// LPC[i] = RPC[i-1]
	tree.PrintLeafCommitments()

	// ============================================================
	// PRINT DETAILED KZG INFORMATION
	// ============================================================

	// Shows:
	//
	// mapped values
	// element commitments
	// polynomial evaluations
	// polynomial coefficients
	// SRS points
	// coefficient contributions
	// final leaf commitment
	// LPC/RPC parent mapping
	if err := tree.PrintKZGDetails(); err != nil {
		panic(err)
	}

	// ============================================================
	// FINAL VALIDATION
	// ============================================================

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
