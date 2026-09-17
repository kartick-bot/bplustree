package main

import (
	"fmt"
	"math/rand"
	"os"
	"sort"
	"time"

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

	const (
		order = 5

		numberOfKeys = 15625 // 5^6

		requiredDepth = 6

		// Random values are drawn without replacement from
		// this key space.
		keySpace = numberOfKeys * 20

		// Fixed seed makes the experiment reproducible.
		randomSeed int64 = 20260917

		snapshotFile = "order5_15625_depth6.snapshot"
	)

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("ORDER-5 DEPTH-6 BULK-LOADED B+ TREE")
	fmt.Println("============================================================")

	fmt.Printf(
		"Order                 = %d\n",
		order,
	)

	fmt.Printf(
		"Number of keys        = %d\n",
		numberOfKeys,
	)

	fmt.Printf(
		"Required depth        = %d\n",
		requiredDepth,
	)

	fmt.Printf(
		"Random seed           = %d\n",
		randomSeed,
	)

	fmt.Printf(
		"Random key space      = 1..%d\n",
		keySpace,
	)

	// ============================================================
	// 1. GENERATE UNIQUE RANDOM KEYS
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("GENERATING RANDOM KEYS")
	fmt.Println("============================================================")

	randomStart :=
		time.Now()

	rng :=
		rand.New(
			rand.NewSource(
				randomSeed,
			),
		)

	// Perm gives unique values without replacement.
	permutation :=
		rng.Perm(
			keySpace,
		)

	keys :=
		make(
			[]int,
			numberOfKeys,
		)

	for i := 0; i < numberOfKeys; i++ {

		// Shift from:
		//
		//     0 .. keySpace-1
		//
		// to:
		//
		//     1 .. keySpace
		keys[i] =
			permutation[i] + 1
	}

	// Bulk-loading requires sorted keys.
	sort.Ints(
		keys,
	)

	randomDuration :=
		time.Since(
			randomStart,
		)

	testKey :=
		keys[len(keys)/2]

	fmt.Printf(
		"Unique keys generated = %d\n",
		len(keys),
	)

	fmt.Printf(
		"Minimum key           = %d\n",
		keys[0],
	)

	fmt.Printf(
		"Median test key       = %d\n",
		testKey,
	)

	fmt.Printf(
		"Maximum key           = %d\n",
		keys[len(keys)-1],
	)

	fmt.Printf(
		"Generation + sort     = %v\n",
		randomDuration,
	)

	// ============================================================
	// 2. CREATE EMPTY TREE OBJECT
	// ============================================================

	tree, err :=
		bptree.New[int, string](
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
	// 3. BULK LOAD
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("BULK LOADING B+ TREE")
	fmt.Println("============================================================")

	bulkStart :=
		time.Now()

	if err :=
		tree.BulkLoadSortedKeys(
			keys,
		); err != nil {

		panic(
			fmt.Errorf(
				"bulk load failed: %w",
				err,
			),
		)
	}

	bulkDuration :=
		time.Since(
			bulkStart,
		)

	fmt.Printf(
		"Bulk-load time = %v\n",
		bulkDuration,
	)

	// ============================================================
	// 4. VERIFY ACTUAL TREE DEPTH
	// ============================================================

	depth, err :=
		tree.InternalDepth()

	if err != nil {
		panic(
			fmt.Errorf(
				"depth verification failed: %w",
				err,
			),
		)
	}

	fmt.Printf(
		"Actual internal depth = %d\n",
		depth,
	)

	if depth !=
		requiredDepth {

		panic(
			fmt.Errorf(
				"wrong B+ tree depth: got %d, expected %d",
				depth,
				requiredDepth,
			),
		)
	}

	fmt.Println(
		"Depth check = PASSED",
	)

	// ============================================================
	// 5. BUILD ALL KZG COMMITMENTS / OPENINGS
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("BUILDING KZG COMMITMENTS")
	fmt.Println("============================================================")

	commitStart :=
		time.Now()

	if err :=
		tree.BuildCommitments(); err != nil {

		panic(
			fmt.Errorf(
				"commitment construction failed: %w",
				err,
			),
		)
	}

	commitDuration :=
		time.Since(
			commitStart,
		)

	fmt.Printf(
		"Commitment construction time = %v\n",
		commitDuration,
	)

	// BuildCommitments recursively commits all children,
	// constructs internal LPC/RPC relationships, maps the
	// internal entries, and finally commits the root.
	root, err :=
		tree.RootCommitment()

	if err != nil {
		panic(err)
	}

	rootBytes :=
		root.Bytes()

	fmt.Printf(
		"Root = %x\n",
		rootBytes,
	)

	// ============================================================
	// 6. VALIDATE COMPLETE COMMITMENT TREE
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("VALIDATING AUTHENTICATED TREE")
	fmt.Println("============================================================")

	validationStart :=
		time.Now()

	if err :=
		tree.ValidateCommitments(); err != nil {

		panic(
			fmt.Errorf(
				"recursive commitment validation failed: %w",
				err,
			),
		)
	}

	validationDuration :=
		time.Since(
			validationStart,
		)

	fmt.Println(
		"Recursive commitment validation = PASSED",
	)

	fmt.Printf(
		"Validation time = %v\n",
		validationDuration,
	)

	// ============================================================
	// 7. VERIFY MEMBERSHIP PATH DEPTH BEFORE SAVING
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("CHECKING TEST MEMBERSHIP PATH")
	fmt.Println("============================================================")

	path, err :=
		tree.ExportMembershipPath(
			testKey,
		)

	if err != nil {
		panic(
			fmt.Errorf(
				"failed exporting test membership path: %w",
				err,
			),
		)
	}

	fmt.Printf(
		"Test key                       = %d\n",
		testKey,
	)

	fmt.Printf(
		"Internal authentication levels = %d\n",
		len(path.Levels),
	)

	if len(path.Levels) !=
		requiredDepth {

		panic(
			fmt.Errorf(
				"membership path has %d internal levels; expected %d",
				len(path.Levels),
				requiredDepth,
			),
		)
	}

	// One leaf opening + exactly one opening per internal level.
	expectedKZGChecks :=
		1 +
			len(path.Levels)

	fmt.Printf(
		"Expected membership KZG checks = %d\n",
		expectedKZGChecks,
	)

	if expectedKZGChecks != 7 {
		panic(
			fmt.Errorf(
				"expected 7 total KZG checks but got %d",
				expectedKZGChecks,
			),
		)
	}

	fmt.Println(
		"Depth-6 membership path check = PASSED",
	)

	// ============================================================
	// 8. SAVE EXACT AUTHENTICATED TREE
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("SAVING SNAPSHOT")
	fmt.Println("============================================================")

	saveStart :=
		time.Now()

	if err :=
		tree.SaveSnapshot(
			snapshotFile,
		); err != nil {

		panic(
			fmt.Errorf(
				"failed saving snapshot: %w",
				err,
			),
		)
	}

	saveDuration :=
		time.Since(
			saveStart,
		)

	info, err :=
		os.Stat(
			snapshotFile,
		)

	if err != nil {
		panic(err)
	}

	snapshotBytes :=
		info.Size()

	snapshotMiB :=
		float64(snapshotBytes) /
			(1024.0 * 1024.0)

	fmt.Printf(
		"Snapshot save time = %v\n",
		saveDuration,
	)

	fmt.Printf(
		"Snapshot size = %d bytes\n",
		snapshotBytes,
	)

	fmt.Printf(
		"Snapshot size = %.2f MiB\n",
		snapshotMiB,
	)

	// ============================================================
	// FINAL SUMMARY
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("DEPTH-6 SCALE BUILD PASSED")
	fmt.Println("============================================================")

	fmt.Printf(
		"Order                         = %d\n",
		order,
	)

	fmt.Printf(
		"Random keys                   = %d\n",
		numberOfKeys,
	)

	fmt.Printf(
		"Random seed                   = %d\n",
		randomSeed,
	)

	fmt.Printf(
		"Minimum key                   = %d\n",
		keys[0],
	)

	fmt.Printf(
		"Membership test key           = %d\n",
		testKey,
	)

	fmt.Printf(
		"Maximum key                   = %d\n",
		keys[len(keys)-1],
	)

	fmt.Printf(
		"Internal depth                = %d\n",
		depth,
	)

	fmt.Printf(
		"Membership KZG verifications  = %d\n",
		expectedKZGChecks,
	)

	fmt.Printf(
		"Random generation + sort      = %v\n",
		randomDuration,
	)

	fmt.Printf(
		"Bulk-load time                = %v\n",
		bulkDuration,
	)

	fmt.Printf(
		"KZG commitment/opening time   = %v\n",
		commitDuration,
	)

	fmt.Printf(
		"Commitment validation time    = %v\n",
		validationDuration,
	)

	fmt.Printf(
		"Snapshot save time            = %v\n",
		saveDuration,
	)

	fmt.Printf(
		"Root commitment               = %x\n",
		rootBytes,
	)

	fmt.Printf(
		"Snapshot                      = %s\n",
		snapshotFile,
	)

	fmt.Printf(
		"Snapshot size                 = %.2f MiB\n",
		snapshotMiB,
	)
}
