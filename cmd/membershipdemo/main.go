package main

import (
	"fmt"
	"math/rand"
	"time"

	"bplustree/bptree"
	bpsnark "bplustree/snark"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
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
	const order = 4
	const numberOfKeys = 16

	// ============================================================
	// 1. BUILD REAL B+ TREE
	// ============================================================

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

	used := make(map[int]bool)

	insertedKeys := make(
		[]int,
		0,
		numberOfKeys,
	)

	for len(insertedKeys) < numberOfKeys {
		key := rand.Intn(91) + 10

		if used[key] {
			continue
		}

		used[key] = true

		if err := tree.Insert(key); err != nil {
			panic(err)
		}

		insertedKeys = append(
			insertedKeys,
			key,
		)
	}

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("PER-KEY MEMBERSHIP SNARK TEST")
	fmt.Println("============================================================")
	fmt.Printf("Inserted keys: %v\n", insertedKeys)
	fmt.Println()

	// ============================================================
	// 2. BUILD REAL KZG COMMITMENTS / OPENINGS
	// ============================================================

	if err := tree.BuildCommitments(); err != nil {
		panic(err)
	}

	// ============================================================
	// 3. CHOOSE ONE REAL KEY
	// ============================================================

	testKey := insertedKeys[0]

	fmt.Printf("Test key = %d\n", testKey)

	// ============================================================
	// 4. NORMAL B+ TREE SEARCH + EXPORT MEMBERSHIP PATH
	// ============================================================

	path, err :=
		tree.ExportMembershipPath(testKey)

	if err != nil {
		panic(
			fmt.Errorf(
				"failed exporting membership path: %w",
				err,
			),
		)
	}

	fmt.Printf(
		"Internal path levels = %d\n",
		len(path.Levels),
	)

	fmt.Printf(
		"Leaf evaluation point = %d\n",
		path.LeafEvaluationPoint,
	)

	fmt.Println()

	for i, level := range path.Levels {

		fmt.Printf(
			"Level %d: child index = %d",
			i+1,
			level.ChildIndex,
		)

		if level.LowerRelation != nil {
			fmt.Printf(
				", lower separator = %d",
				level.LowerRelation.SeparatorKey,
			)
		}

		if level.UpperRelation != nil {
			fmt.Printf(
				", upper separator = %d",
				level.UpperRelation.SeparatorKey,
			)
		}

		fmt.Println()
	}

	// ============================================================
	// COUNT KZG VERIFICATIONS
	// ============================================================
	//
	// One KZG verification is required for the leaf.
	//
	// Every lower/upper authenticated separator relation requires
	// one additional KZG opening verification.

	numberOfKZGChecks := 1

	for _, level := range path.Levels {
		if level.LowerRelation != nil {
			numberOfKZGChecks++
		}

		if level.UpperRelation != nil {
			numberOfKZGChecks++
		}
	}

	fmt.Println()
	fmt.Printf(
		"Total KZG verifications for key %d = %d\n",
		testKey,
		numberOfKZGChecks,
	)

	// ============================================================
	// 5. PRINT SNARK INPUT CLASSIFICATION
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("SNARK INPUT CLASSIFICATION")
	fmt.Println("============================================================")

	// ============================================================
	// PUBLIC INPUTS
	// ============================================================

	fmt.Println()
	fmt.Println("------------------------------------------------------------")
	fmt.Println("PUBLIC INPUTS")
	fmt.Println("------------------------------------------------------------")

	fmt.Printf(
		"[PUBLIC] Key = %d\n",
		path.Key,
	)

	fmt.Printf(
		"[PUBLIC] Root commitment = %x\n",
		path.RootCommitment.Bytes(),
	)

	fmt.Printf(
		"[PUBLIC] Leaf KZG verification key = %+v\n",
		path.LeafVerifyingKey,
	)

	for levelIndex, level := range path.Levels {

		fmt.Printf(
			"[PUBLIC] Level %d KZG verification key = %+v\n",
			levelIndex+1,
			level.VerifyingKey,
		)
	}

	// ============================================================
	// PRIVATE WITNESS
	// ============================================================

	fmt.Println()
	fmt.Println("------------------------------------------------------------")
	fmt.Println("PRIVATE WITNESS")
	fmt.Println("------------------------------------------------------------")

	fmt.Println()
	fmt.Println("[PRIVATE] LEAF DATA")

	fmt.Printf(
		"[PRIVATE] Leaf mapped value = %s\n",
		path.LeafMappedValue.String(),
	)

	fmt.Printf(
		"[PRIVATE] Leaf commitment = %x\n",
		path.LeafCommitment.Bytes(),
	)

	fmt.Printf(
		"[PRIVATE] Leaf KZG opening proof = %+v\n",
		path.LeafOpeningProof,
	)

	// KeyHash is exported by the native membership path,
	// but it is NOT yet part of MembershipCircuit.
	//
	// Later, when we implement the leaf SHA-256 mapping inside
	// the circuit, this becomes private witness data.

	fmt.Printf(
		"[NOT YET IN CIRCUIT] H(key) = %x\n",
		path.KeyHash,
	)

	// ============================================================
	// INTERNAL AUTHENTICATION PATH
	// ============================================================

	for levelIndex, level := range path.Levels {

		fmt.Println()

		fmt.Printf(
			"[PRIVATE] INTERNAL LEVEL %d\n",
			levelIndex+1,
		)

		fmt.Printf(
			"[PRIVATE] Parent commitment = %x\n",
			level.ParentCommitment.Bytes(),
		)

		// --------------------------------------------------------
		// LOWER RELATION
		// --------------------------------------------------------

		if level.LowerRelation != nil {

			lower :=
				level.LowerRelation

			fmt.Println(
				"[PRIVATE] Lower authenticated relation:",
			)

			fmt.Printf(
				"          separator key   = %d\n",
				lower.SeparatorKey,
			)

			fmt.Printf(
				"          LPC             = %x\n",
				lower.LPC.Bytes(),
			)

			fmt.Printf(
				"          RPC             = %x\n",
				lower.RPC.Bytes(),
			)

			fmt.Printf(
				"          mapped value    = %s\n",
				lower.MappedValue.String(),
			)

			fmt.Printf(
				"          evaluation point = %d\n",
				lower.EvaluationPoint,
			)

			fmt.Printf(
				"          KZG proof       = %+v\n",
				lower.OpeningProof,
			)
		}

		// --------------------------------------------------------
		// UPPER RELATION
		// --------------------------------------------------------

		if level.UpperRelation != nil {

			upper :=
				level.UpperRelation

			fmt.Println(
				"[PRIVATE] Upper authenticated relation:",
			)

			fmt.Printf(
				"          separator key   = %d\n",
				upper.SeparatorKey,
			)

			fmt.Printf(
				"          LPC             = %x\n",
				upper.LPC.Bytes(),
			)

			fmt.Printf(
				"          RPC             = %x\n",
				upper.RPC.Bytes(),
			)

			fmt.Printf(
				"          mapped value    = %s\n",
				upper.MappedValue.String(),
			)

			fmt.Printf(
				"          evaluation point = %d\n",
				upper.EvaluationPoint,
			)

			fmt.Printf(
				"          KZG proof       = %+v\n",
				upper.OpeningProof,
			)
		}
	}

	// ============================================================
	// COMPILE-TIME CONSTANTS
	// ============================================================

	fmt.Println()
	fmt.Println("------------------------------------------------------------")
	fmt.Println("COMPILE-TIME / PATH-SHAPE DATA")
	fmt.Println("------------------------------------------------------------")

	fmt.Printf(
		"[STATIC] Leaf evaluation point = %d\n",
		path.LeafEvaluationPoint,
	)

	fmt.Printf(
		"[STATIC] Number of internal levels = %d\n",
		len(path.Levels),
	)

	for levelIndex, level := range path.Levels {

		fmt.Printf(
			"[PATH METADATA] Level %d selected child index = %d\n",
			levelIndex+1,
			level.ChildIndex,
		)

		if level.LowerRelation != nil {

			fmt.Printf(
				"[STATIC] Level %d lower evaluation point = %d\n",
				levelIndex+1,
				level.LowerRelation.EvaluationPoint,
			)
		}

		if level.UpperRelation != nil {

			fmt.Printf(
				"[STATIC] Level %d upper evaluation point = %d\n",
				levelIndex+1,
				level.UpperRelation.EvaluationPoint,
			)
		}
	}

	// ============================================================
	// SNARK STATEMENT
	// ============================================================

	fmt.Println()
	fmt.Println("------------------------------------------------------------")
	fmt.Println("SNARK STATEMENT")
	fmt.Println("------------------------------------------------------------")

	fmt.Printf(
		"Prove privately that PUBLIC key %d is a member of the B+ tree\n",
		path.Key,
	)

	fmt.Printf(
		"whose PUBLIC root commitment is %x\n",
		path.RootCommitment.Bytes(),
	)

	fmt.Println(
		"without revealing the private leaf and authentication-path data.",
	)

	fmt.Println()
	fmt.Println(
		"NOTE: SHA-256 leaf/internal mapping is NOT yet recomputed inside the circuit.",
	)

	// ============================================================
	// 6. BUILD A DEDICATED COMPILE ASSIGNMENT
	// ============================================================
	//
	// VERY IMPORTANT:
	//
	// frontend.Compile() may replace frontend.Variable values
	// inside the supplied structure with gnark symbolic objects
	// such as expr.Term.
	//
	// Therefore:
	//
	//     compileAssignment
	//
	// must NEVER later be passed to frontend.NewWitness().
	//
	// We throw this object away after compilation.

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
				"failed building compile assignment: %w",
				err,
			),
		)
	}

	fmt.Println("Compile assignment created = YES")

	// ============================================================
	// 7. COMPILE AS PLONK / SCS CIRCUIT
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("COMPILING MEMBERSHIP CIRCUIT")
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

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("CIRCUIT / PLONK METRICS")
	fmt.Println("============================================================")

	fmt.Printf(
		"Compile time          = %v\n",
		compileDuration,
	)

	fmt.Printf(
		"Number of constraints = %d\n",
		ccs.GetNbConstraints(),
	)

	fmt.Printf(
		"Secret variables      = %d\n",
		ccs.GetNbSecretVariables(),
	)

	fmt.Printf(
		"Public variables      = %d\n",
		ccs.GetNbPublicVariables(),
	)

	fmt.Printf(
		"KZG verifications     = %d\n",
		numberOfKZGChecks,
	)

	// ============================================================
	// IMPORTANT
	// ============================================================
	//
	// From this point onward:
	//
	// DO NOT USE compileAssignment AGAIN.
	//
	// The compiler may have replaced frontend.Variable values
	// inside it with internal symbolic expressions.
	//
	// Build a completely fresh assignment from the native path.

	compileAssignment = nil

	// ============================================================
	// 8. BUILD A COMPLETELY FRESH REAL WITNESS ASSIGNMENT
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("BUILDING FRESH REAL WITNESS ASSIGNMENT")
	fmt.Println("============================================================")

	witnessAssignment, err :=
		bpsnark.NewMembershipCircuitWitness(
			path,
		)

	if err != nil {
		panic(
			fmt.Errorf(
				"failed building fresh membership witness: %w",
				err,
			),
		)
	}

	fmt.Println("Fresh witness assignment created = YES")

	// ============================================================
	// 9. CREATE THE REAL GNARK WITNESS
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("BUILDING REAL GNARK WITNESS")
	fmt.Println("============================================================")

	fullWitness, err :=
		frontend.NewWitness(
			witnessAssignment,
			ecc.BN254.ScalarField(),
		)

	if err != nil {
		panic(
			fmt.Errorf(
				"failed creating gnark witness: %w",
				err,
			),
		)
	}

	publicWitness, err :=
		fullWitness.Public()

	if err != nil {
		panic(
			fmt.Errorf(
				"failed extracting public witness: %w",
				err,
			),
		)
	}

	fmt.Println("Full witness created   = YES")
	fmt.Println("Public witness created = YES")

	// We do not use the public witness until the PLONK verify step.
	_ = publicWitness

// ============================================================
	// 10. PRE-PROVING CHECKPOINT
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("PRE-PROVING CHECKPOINT PASSED")
	fmt.Println("============================================================")

	fmt.Println("Circuit compilation       = PASSED")
	fmt.Println("Full witness construction = PASSED")
	fmt.Println("Public witness extraction = PASSED")

	fmt.Println()

	fmt.Printf(
		"Key                            = %d\n",
		testKey,
	)

	fmt.Printf(
		"Internal authentication levels = %d\n",
		len(path.Levels),
	)

	fmt.Printf(
		"KZG verifications               = %d\n",
		numberOfKZGChecks,
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

	// ============================================================
	// 11. GENERATE PLONK KZG SRS
	// ============================================================
	//
	// IMPORTANT:
	//
	// unsafekzg is intended for testing / benchmarking only.
	//
	// For a production deployment, the PLONK SRS must come from
	// an appropriate trusted / MPC setup.
	//
	// For this research prototype, unsafekzg.NewSRS is exactly
	// what gnark's own PLONK examples use.

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("GENERATING PLONK SRS")
	fmt.Println("============================================================")

	srsStart :=
		time.Now()

	srs, srsLagrange, err :=
		unsafekzg.NewSRS(
			ccs,
		)

	if err != nil {
		panic(
			fmt.Errorf(
				"failed generating PLONK SRS: %w",
				err,
			),
		)
	}

	srsDuration :=
		time.Since(srsStart)

	fmt.Printf(
		"PLONK SRS generation time = %v\n",
		srsDuration,
	)

	// ============================================================
	// 12. PLONK SETUP
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("PLONK SETUP")
	fmt.Println("============================================================")

	setupStart :=
		time.Now()

	pk, vk, err :=
		plonk.Setup(
			ccs,
			srs,
			srsLagrange,
		)

	if err != nil {
		panic(
			fmt.Errorf(
				"PLONK setup failed: %w",
				err,
			),
		)
	}

	setupDuration :=
		time.Since(setupStart)

	fmt.Printf(
		"PLONK setup time = %v\n",
		setupDuration,
	)

	// ============================================================
	// 13. GENERATE ONE PLONK MEMBERSHIP PROOF
	// ============================================================
	//
	// This call also performs the actual solving required by
	// PLONK and replaces gnark's BSB22 commitment placeholder
	// with the real commitment computation.

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("PLONK PROVING")
	fmt.Println("============================================================")

	proveStart :=
		time.Now()

	proof, err :=
		plonk.Prove(
			ccs,
			pk,
			fullWitness,
		)

	if err != nil {
		panic(
			fmt.Errorf(
				"PLONK proving failed: %w",
				err,
			),
		)
	}

	proveDuration :=
		time.Since(proveStart)

	fmt.Printf(
		"PLONK proving time = %v\n",
		proveDuration,
	)

	// ============================================================
	// 14. VERIFY THE PLONK MEMBERSHIP PROOF
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("PLONK VERIFICATION")
	fmt.Println("============================================================")

	verifyStart :=
		time.Now()

	if err :=
		plonk.Verify(
			proof,
			vk,
			publicWitness,
		); err != nil {

		panic(
			fmt.Errorf(
				"PLONK verification failed: %w",
				err,
			),
		)
	}

	verifyDuration :=
		time.Since(verifyStart)

	fmt.Printf(
		"PLONK verification time = %v\n",
		verifyDuration,
	)

	// ============================================================
	// 15. FINAL SUCCESS
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("PLONK MEMBERSHIP PROOF VERIFIED")
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
		"KZG verifications               = %d\n",
		numberOfKZGChecks,
	)

	fmt.Printf(
		"PLONK constraints               = %d\n",
		ccs.GetNbConstraints(),
	)

	fmt.Printf(
		"SRS generation time             = %v\n",
		srsDuration,
	)

	fmt.Printf(
		"PLONK setup time                 = %v\n",
		setupDuration,
	)

	fmt.Printf(
		"PLONK proving time               = %v\n",
		proveDuration,
	)

	fmt.Printf(
		"PLONK verification time          = %v\n",
		verifyDuration,
	)

	fmt.Println()
	fmt.Println(
		"Current proof authenticates the KZG openings, B+ tree routing relations,",
	)

	fmt.Println(
		"child-commitment links, and final public root commitment.",
	)

	fmt.Println()
	fmt.Println(
		"SHA-256 leaf/internal mapping is still NOT enforced in-circuit.",
	)
}
