package main

import (
	"fmt"
	"os"
	"time"

	"bplustree/bptree"
	bpsnark "bplustree/snark"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
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
		snapshotFile = "order5_15625_depth6.snapshot"
		testKey      = 154734

		expectedRoot = "a65e5dff6be24579c7bf255a16ae3fedcd8c222a54a508b4721e270b5fbb02e6"

		expectedInternalLevels = 6
		expectedKZGChecks      = 7
	)

	fmt.Println("============================================================")
	fmt.Println("B+ TREE SCALE MEMBERSHIP + PLONK CIRCUIT TEST")
	fmt.Println("============================================================")
	fmt.Println()

	fmt.Printf("Snapshot = %s\n", snapshotFile)
	fmt.Printf("Test key = %d\n", testKey)

	// ============================================================
	// 1. CONFIRM SNAPSHOT EXISTS
	// ============================================================

	info, err := os.Stat(snapshotFile)
	if err != nil {
		panic(
			fmt.Errorf(
				"cannot access snapshot %s: %w",
				snapshotFile,
				err,
			),
		)
	}

	fmt.Printf(
		"Snapshot size = %.2f MiB\n",
		float64(info.Size())/(1024.0*1024.0),
	)

	// ============================================================
	// 2. LOAD THE EXACT COMMITTED TREE
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("LOADING AUTHENTICATED TREE")
	fmt.Println("============================================================")

	loadStart := time.Now()

	tree, err :=
		bptree.LoadSnapshot[int, string](
			snapshotFile,
			intComparator,
			bptree.HashInt,
			bptree.MapIntEntryToField,
			bptree.MapIntInternalEntryToField,
		)

	if err != nil {
		panic(
			fmt.Errorf(
				"failed loading tree snapshot: %w",
				err,
			),
		)
	}

	loadDuration :=
		time.Since(loadStart)

	fmt.Printf(
		"Snapshot load time = %v\n",
		loadDuration,
	)

	// ============================================================
	// 3. CHECK ROOT
	// ============================================================

	root, err :=
		tree.RootCommitment()

	if err != nil {
		panic(
			fmt.Errorf(
				"failed retrieving loaded root: %w",
				err,
			),
		)
	}

	rootBytes :=
		root.Bytes()

	loadedRoot :=
		fmt.Sprintf(
			"%x",
			rootBytes,
		)

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("ROOT CHECK")
	fmt.Println("============================================================")

	fmt.Printf(
		"Expected root = %s\n",
		expectedRoot,
	)

	fmt.Printf(
		"Loaded root   = %s\n",
		loadedRoot,
	)

	if loadedRoot != expectedRoot {
		panic(
			fmt.Errorf(
				"loaded root does not match original root",
			),
		)
	}

	fmt.Println(
		"Root preserved = YES",
	)

	// ============================================================
	// 4. VALIDATE THE LOADED AUTHENTICATED TREE
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("VALIDATING LOADED TREE")
	fmt.Println("============================================================")

	validationStart :=
		time.Now()

	if err :=
		tree.ValidateCommitments(); err != nil {

		panic(
			fmt.Errorf(
				"loaded commitment tree validation failed: %w",
				err,
			),
		)
	}

	validationDuration :=
		time.Since(validationStart)

	fmt.Println(
		"Recursive commitment validation = PASSED",
	)

	fmt.Printf(
		"Validation time = %v\n",
		validationDuration,
	)

	// ============================================================
	// 5. VERIFY TREE DEPTH
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("CHECKING TREE DEPTH")
	fmt.Println("============================================================")

	depth, err :=
		tree.InternalDepth()

	if err != nil {
		panic(
			fmt.Errorf(
				"failed computing tree depth: %w",
				err,
			),
		)
	}

	fmt.Printf(
		"Internal depth = %d\n",
		depth,
	)

	if depth != expectedInternalLevels {
		panic(
			fmt.Errorf(
				"loaded tree has depth %d; expected %d",
				depth,
				expectedInternalLevels,
			),
		)
	}

	fmt.Println(
		"Depth check = PASSED",
	)

	// ============================================================
	// 6. NORMAL B+ TREE SEARCH
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("NORMAL B+ TREE SEARCH")
	fmt.Println("============================================================")

	searchStart :=
		time.Now()

	_, found :=
		tree.Search(
			testKey,
		)

	searchDuration :=
		time.Since(searchStart)

	if !found {
		panic(
			fmt.Errorf(
				"test key %d was not found",
				testKey,
			),
		)
	}

	fmt.Printf(
		"Key %d = FOUND\n",
		testKey,
	)

	fmt.Printf(
		"Search time = %v\n",
		searchDuration,
	)

	// ============================================================
	// 7. EXPORT COMPLETE MEMBERSHIP PATH
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("EXPORTING MEMBERSHIP PATH")
	fmt.Println("============================================================")

	pathStart :=
		time.Now()

	path, err :=
		tree.ExportMembershipPath(
			testKey,
		)

	if err != nil {
		panic(
			fmt.Errorf(
				"failed exporting membership path: %w",
				err,
			),
		)
	}

	pathDuration :=
		time.Since(pathStart)

	// ============================================================
	// COUNT / VALIDATE KZG RELATIONS
	// ============================================================
	//
	// Exactly:
	//
	//     1 leaf KZG opening
	//
	// plus:
	//
	//     1 internal KZG opening per level
	//
	// With depth 6:
	//
	//     1 + 6 = 7
	// ============================================================

	numberOfKZGChecks := 1

	for levelIndex, level := range path.Levels {

		relationCount := 0

		if level.LowerRelation != nil {
			relationCount++
		}

		if level.UpperRelation != nil {
			relationCount++
		}

		if relationCount != 1 {
			panic(
				fmt.Errorf(
					"internal level %d has %d authenticated relations; expected exactly 1",
					levelIndex+1,
					relationCount,
				),
			)
		}

		numberOfKZGChecks++
	}

	fmt.Printf(
		"Membership path export time = %v\n",
		pathDuration,
	)

	fmt.Printf(
		"Leaf entry index               = %d\n",
		path.LeafEntryIndex,
	)

	fmt.Printf(
		"Leaf evaluation point          = %d\n",
		path.LeafEvaluationPoint,
	)

	fmt.Printf(
		"Internal authentication levels = %d\n",
		len(path.Levels),
	)

	fmt.Printf(
		"Total KZG verifications        = %d\n",
		numberOfKZGChecks,
	)

	if len(path.Levels) !=
		expectedInternalLevels {

		panic(
			fmt.Errorf(
				"membership path contains %d levels; expected %d",
				len(path.Levels),
				expectedInternalLevels,
			),
		)
	}

	if numberOfKZGChecks !=
		expectedKZGChecks {

		panic(
			fmt.Errorf(
				"membership path requires %d KZG checks; expected %d",
				numberOfKZGChecks,
				expectedKZGChecks,
			),
		)
	}

	// ============================================================
	// 8. PRINT EACH AUTHENTICATION LEVEL
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("AUTHENTICATION PATH")
	fmt.Println("============================================================")

	for i, level := range path.Levels {

		fmt.Printf(
			"\nLevel %d\n",
			i+1,
		)

		fmt.Printf(
			"  selected child index = %d\n",
			level.ChildIndex,
		)

		if level.LowerRelation != nil {

			fmt.Printf(
				"  lower relation       = %d <= %d\n",
				level.LowerRelation.SeparatorKey,
				testKey,
			)

			fmt.Printf(
				"  lower eval point     = %d\n",
				level.LowerRelation.EvaluationPoint,
			)

			fmt.Println(
				"  current child link   = RPC",
			)
		}

		if level.UpperRelation != nil {

			fmt.Printf(
				"  upper relation       = %d < %d\n",
				testKey,
				level.UpperRelation.SeparatorKey,
			)

			fmt.Printf(
				"  upper eval point     = %d\n",
				level.UpperRelation.EvaluationPoint,
			)

			fmt.Println(
				"  current child link   = LPC",
			)
		}

		fmt.Printf(
			"  parent commitment    = %x\n",
			level.ParentCommitment.Bytes(),
		)
	}

	// ============================================================
	// 9. FINAL ROOT FROM EXPORTED PATH
	// ============================================================

	pathRootBytes :=
		path.RootCommitment.Bytes()

	pathRoot :=
		fmt.Sprintf(
			"%x",
			pathRootBytes,
		)

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("MEMBERSHIP PATH ROOT CHECK")
	fmt.Println("============================================================")

	fmt.Printf(
		"Loaded tree root = %s\n",
		loadedRoot,
	)

	fmt.Printf(
		"Path root        = %s\n",
		pathRoot,
	)

	if pathRoot != loadedRoot {
		panic(
			fmt.Errorf(
				"membership path root does not match loaded tree root",
			),
		)
	}

	fmt.Println(
		"Membership path reaches authenticated root = YES",
	)

	// ============================================================
	// 10. NATIVE PATH TEST PASSED
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("NATIVE SCALE MEMBERSHIP PATH TEST PASSED")
	fmt.Println("============================================================")

	fmt.Printf(
		"Key                            = %d\n",
		testKey,
	)

	fmt.Printf(
		"Snapshot load time             = %v\n",
		loadDuration,
	)

	fmt.Printf(
		"Search time                    = %v\n",
		searchDuration,
	)

	fmt.Printf(
		"Membership path export time    = %v\n",
		pathDuration,
	)

	fmt.Printf(
		"Internal authentication levels = %d\n",
		len(path.Levels),
	)

	fmt.Printf(
		"KZG verifications              = %d\n",
		numberOfKZGChecks,
	)

	fmt.Printf(
		"Authenticated root             = %s\n",
		pathRoot,
	)

	// ============================================================
	// 11. SNARK STATEMENT
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("PLONK MEMBERSHIP CIRCUIT")
	fmt.Println("============================================================")

	fmt.Printf(
		"Public key              = %d\n",
		path.Key,
	)

	fmt.Printf(
		"Public root commitment  = %x\n",
		path.RootCommitment.Bytes(),
	)

	fmt.Printf(
		"Leaf evaluation point   = %d\n",
		path.LeafEvaluationPoint,
	)

	fmt.Printf(
		"Internal levels         = %d\n",
		len(path.Levels),
	)

	fmt.Printf(
		"KZG verifications       = %d\n",
		numberOfKZGChecks,
	)

	fmt.Println()
	fmt.Println(
		"NOTE: SHA-256 leaf/internal mapping is NOT yet recomputed inside the circuit.",
	)

	// ============================================================
	// 12. PRINT STATIC CIRCUIT PATH SHAPE
	// ============================================================

	fmt.Println()
	fmt.Println("------------------------------------------------------------")
	fmt.Println("COMPILE-TIME PATH SHAPE")
	fmt.Println("------------------------------------------------------------")

	fmt.Printf(
		"Leaf evaluation point = %d\n",
		path.LeafEvaluationPoint,
	)

	for levelIndex, level := range path.Levels {

		fmt.Printf(
			"Level %d: child index = %d",
			levelIndex+1,
			level.ChildIndex,
		)

		if level.LowerRelation != nil {

			fmt.Printf(
				", LOWER/RPC, eval point = %d",
				level.LowerRelation.EvaluationPoint,
			)
		}

		if level.UpperRelation != nil {

			fmt.Printf(
				", UPPER/LPC, eval point = %d",
				level.UpperRelation.EvaluationPoint,
			)
		}

		fmt.Println()
	}

	// ============================================================
	// 13. BUILD DEDICATED COMPILE ASSIGNMENT
	// ============================================================
	//
	// IMPORTANT:
	//
	// We intentionally build a real assignment here instead of
	// compiling a zero-valued circuit shape.
	//
	// The gnark KZG verifier works with emulated BN254 points.
	// Supplying the actual path values gives all of those objects
	// the correct structure during compilation.
	//
	// frontend.Compile() may mutate frontend.Variable values into
	// symbolic gnark expressions.
	//
	// Therefore this object MUST NOT later be reused as the real
	// witness assignment.
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("BUILDING COMPILE-TIME ASSIGNMENT")
	fmt.Println("============================================================")

	compileAssignment, err :=
		bpsnark.NewMembershipCircuitWitness(
			path,
		)

	if err != nil {
		panic(
			fmt.Errorf(
				"failed building compile-time membership assignment: %w",
				err,
			),
		)
	}

	fmt.Println(
		"Compile assignment created = YES",
	)

	// ============================================================
	// 14. COMPILE THE EXACT 7-KZG MEMBERSHIP CIRCUIT
	// ============================================================
	//
	// This is the circuit that corresponds to:
	//
	//     ONE key
	//     ONE leaf opening
	//     SIX parent openings
	//     ONE authenticated root
	//
	// We stop after compilation.
	//
	// NO PLONK SRS is generated in this program yet.
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("COMPILING 7-KZG PLONK MEMBERSHIP CIRCUIT")
	fmt.Println("============================================================")

	compileStart :=
		time.Now()

	ccs, err :=
		frontend.Compile(
			ecc.BN254.ScalarField(),
			scs.NewBuilder,
			compileAssignment,
		)

	if err != nil {
		panic(
			fmt.Errorf(
				"membership circuit compilation failed: %w",
				err,
			),
		)
	}

	compileDuration :=
		time.Since(compileStart)

	// Do not reuse this object as a real witness.
	compileAssignment = nil

	// ============================================================
	// 15. CIRCUIT METRICS
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("DEPTH-6 PLONK CIRCUIT METRICS")
	fmt.Println("============================================================")

	fmt.Printf(
		"Key                            = %d\n",
		testKey,
	)

	fmt.Printf(
		"Internal authentication levels = %d\n",
		len(path.Levels),
	)

	fmt.Printf(
		"KZG verifications              = %d\n",
		numberOfKZGChecks,
	)

	fmt.Printf(
		"Compile time                    = %v\n",
		compileDuration,
	)

	fmt.Printf(
		"PLONK constraints               = %d\n",
		ccs.GetNbConstraints(),
	)

	fmt.Printf(
		"Secret variables                = %d\n",
		ccs.GetNbSecretVariables(),
	)

	fmt.Printf(
		"Public variables                = %d\n",
		ccs.GetNbPublicVariables(),
	)

	fmt.Printf(
		"Authenticated root              = %s\n",
		pathRoot,
	)

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("PLONK CIRCUIT COMPILATION PASSED")
	fmt.Println("============================================================")

	fmt.Println()
	fmt.Println(
		"No PLONK SRS/setup/proving was performed.",
	)

	fmt.Println(
		"Next step: inspect the circuit size before generating the PLONK SRS.",
	)
}
