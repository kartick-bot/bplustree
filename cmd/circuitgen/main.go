package main

import (
	"fmt"
	"os"
	"time"

	"bplustree/bptree"
	bpsnark "bplustree/snark"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
)

const (
	snapshotFile = "order5_15625_depth6.snapshot"
	circuitFile  = "artifacts/membership_depth6.ccs"

	testKey = 154734

	expectedRoot = "a65e5dff6be24579c7bf255a16ae3fedcd8c222a54a508b4721e270b5fbb02e6"

	expectedConstraints = 23957357
	expectedLevels      = 6
	expectedKZGChecks   = 7
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

	fmt.Println("============================================================")
	fmt.Println("GENERATE AND SAVE PLONK MEMBERSHIP CIRCUIT")
	fmt.Println("============================================================")

	fmt.Printf("Snapshot     = %s\n", snapshotFile)
	fmt.Printf("Circuit file = %s\n", circuitFile)
	fmt.Printf("Test key     = %d\n", testKey)

	// ============================================================
	// 1. DO NOT ACCIDENTALLY REGENERATE THE CIRCUIT
	// ============================================================

	if _, err := os.Stat(circuitFile); err == nil {

		panic(
			fmt.Errorf(
				"circuit already exists at %s; refusing to overwrite it",
				circuitFile,
			),
		)

	} else if !os.IsNotExist(err) {

		panic(err)
	}

	// ============================================================
	// 2. LOAD EXACT AUTHENTICATED TREE
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("LOADING AUTHENTICATED TREE")
	fmt.Println("============================================================")

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
				"failed loading snapshot: %w",
				err,
			),
		)
	}

	// ============================================================
	// 3. CHECK AUTHENTICATED ROOT
	// ============================================================

	root, err :=
		tree.RootCommitment()

	if err != nil {
		panic(err)
	}

	rootString :=
		fmt.Sprintf(
			"%x",
			root.Bytes(),
		)

	fmt.Printf(
		"Loaded root = %s\n",
		rootString,
	)

	if rootString != expectedRoot {
		panic(
			fmt.Errorf(
				"root mismatch: got %s, expected %s",
				rootString,
				expectedRoot,
			),
		)
	}

	fmt.Println(
		"Root check = PASSED",
	)

	// ============================================================
	// 4. EXPORT EXACT MEMBERSHIP PATH
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("EXPORTING MEMBERSHIP PATH")
	fmt.Println("============================================================")

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

	if len(path.Levels) != expectedLevels {
		panic(
			fmt.Errorf(
				"expected %d internal levels, got %d",
				expectedLevels,
				len(path.Levels),
			),
		)
	}

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
					"level %d has %d relations; expected exactly 1",
					levelIndex+1,
					relationCount,
				),
			)
		}

		numberOfKZGChecks++
	}

	if numberOfKZGChecks != expectedKZGChecks {
		panic(
			fmt.Errorf(
				"expected %d KZG checks, got %d",
				expectedKZGChecks,
				numberOfKZGChecks,
			),
		)
	}

	fmt.Printf(
		"Internal levels = %d\n",
		len(path.Levels),
	)

	fmt.Printf(
		"KZG checks      = %d\n",
		numberOfKZGChecks,
	)

	// ============================================================
	// 5. BUILD THE COMPILE-TIME ASSIGNMENT
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("BUILDING COMPILE ASSIGNMENT")
	fmt.Println("============================================================")

	compileAssignment, err :=
		bpsnark.NewMembershipCircuitWitness(
			path,
		)

	if err != nil {
		panic(
			fmt.Errorf(
				"failed building compile assignment: %w",
				err,
			),
		)
	}

	fmt.Println(
		"Compile assignment created = YES",
	)

	// ============================================================
	// 6. COMPILE
	//
	// THIS IS THE ONLY PROGRAM THAT WILL CALL frontend.Compile().
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("COMPILING CIRCUIT -- ONE TIME ONLY")
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
				"circuit compilation failed: %w",
				err,
			),
		)
	}

	compileDuration :=
		time.Since(
			compileStart,
		)

	// Never use this object as a real witness after compilation.
	compileAssignment = nil

	fmt.Printf(
		"Compile time       = %v\n",
		compileDuration,
	)

	fmt.Printf(
		"Constraints        = %d\n",
		ccs.GetNbConstraints(),
	)

	fmt.Printf(
		"Secret variables   = %d\n",
		ccs.GetNbSecretVariables(),
	)

	fmt.Printf(
		"Public variables   = %d\n",
		ccs.GetNbPublicVariables(),
	)

	// if ccs.GetNbConstraints() != expectedConstraints {
	// 	panic(
	// 		fmt.Errorf(
	// 			"constraint count changed: got %d, expected %d",
	// 			ccs.GetNbConstraints(),
	// 			expectedConstraints,
	// 		),
	// 	)
	// }

	// ============================================================
	// 7. SAVE COMPILED CONSTRAINT SYSTEM
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("SAVING COMPILED CIRCUIT")
	fmt.Println("============================================================")

	out, err :=
		os.Create(
			circuitFile,
		)

	if err != nil {
		panic(
			fmt.Errorf(
				"failed creating circuit file: %w",
				err,
			),
		)
	}

	bytesWritten, err :=
		ccs.WriteTo(
			out,
		)

	if err != nil {
		_ = out.Close()

		panic(
			fmt.Errorf(
				"failed serializing circuit: %w",
				err,
			),
		)
	}

	if err :=
		out.Close(); err != nil {

		panic(
			fmt.Errorf(
				"failed closing circuit file: %w",
				err,
			),
		)
	}

	fmt.Printf(
		"Circuit saved       = %s\n",
		circuitFile,
	)

	fmt.Printf(
		"Serialized bytes    = %d\n",
		bytesWritten,
	)

	// ============================================================
	// 8. CHECK FILE EXISTS
	// ============================================================

	info, err :=
		os.Stat(
			circuitFile,
		)

	if err != nil {
		panic(err)
	}

	fmt.Printf(
		"File size           = %d bytes\n",
		info.Size(),
	)

	fmt.Printf(
		"File size           = %.2f MiB\n",
		float64(info.Size())/(1024.0*1024.0),
	)

	// ============================================================
	// 9. RELOAD THE SAVED CIRCUIT FROM DISK
	//
	// IMPORTANT:
	//
	// We are NOT compiling again.
	//
	// We instantiate an empty BN254 PLONK constraint system and
	// deserialize the previously compiled circuit into it.
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("RELOADING SAVED CIRCUIT")
	fmt.Println("============================================================")

	in, err :=
		os.Open(
			circuitFile,
		)

	if err != nil {
		panic(
			fmt.Errorf(
				"failed opening saved circuit: %w",
				err,
			),
		)
	}

	loadedCCS :=
		plonk.NewCS(
			ecc.BN254,
		)

	bytesRead, err :=
		loadedCCS.ReadFrom(
			in,
		)

	if err != nil {
		_ = in.Close()

		panic(
			fmt.Errorf(
				"failed deserializing saved circuit: %w",
				err,
			),
		)
	}

	if err :=
		in.Close(); err != nil {

		panic(err)
	}

	fmt.Printf(
		"Bytes read          = %d\n",
		bytesRead,
	)

	fmt.Printf(
		"Loaded constraints  = %d\n",
		loadedCCS.GetNbConstraints(),
	)

	fmt.Printf(
		"Loaded secret vars  = %d\n",
		loadedCCS.GetNbSecretVariables(),
	)

	fmt.Printf(
		"Loaded public vars  = %d\n",
		loadedCCS.GetNbPublicVariables(),
	)

	// ============================================================
	// 10. VERIFY SAVED CIRCUIT IS EXACTLY WHAT WE EXPECT
	// ============================================================

	if loadedCCS.GetNbConstraints() !=
		ccs.GetNbConstraints() {

		panic(
			fmt.Errorf(
				"reloaded circuit constraint mismatch: original=%d loaded=%d",
				ccs.GetNbConstraints(),
				loadedCCS.GetNbConstraints(),
			),
		)
	}

	if loadedCCS.GetNbSecretVariables() !=
		ccs.GetNbSecretVariables() {

		panic(
			fmt.Errorf(
				"reloaded secret variable count mismatch",
			),
		)
	}

	if loadedCCS.GetNbPublicVariables() !=
		ccs.GetNbPublicVariables() {

		panic(
			fmt.Errorf(
				"reloaded public variable count mismatch",
			),
		)
	}

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("CIRCUIT GENERATED, SAVED, AND RELOADED SUCCESSFULLY")
	fmt.Println("============================================================")

	fmt.Printf(
		"File              = %s\n",
		circuitFile,
	)

	fmt.Printf(
		"Constraints       = %d\n",
		loadedCCS.GetNbConstraints(),
	)

	fmt.Printf(
		"Secret variables  = %d\n",
		loadedCCS.GetNbSecretVariables(),
	)

	fmt.Printf(
		"Public variables  = %d\n",
		loadedCCS.GetNbPublicVariables(),
	)

	fmt.Printf(
		"KZG checks        = %d\n",
		numberOfKZGChecks,
	)

	fmt.Printf(
		"Compile time      = %v\n",
		compileDuration,
	)

	fmt.Println()
	fmt.Println(
		"This circuit must now be LOADED, not regenerated, by setup/prove/verify.",
	)
}
