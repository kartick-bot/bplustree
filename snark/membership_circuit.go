package snark

import (
	"fmt"

	"bplustree/bptree"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	stdkzg "github.com/consensys/gnark/std/commitments/kzg"
	"github.com/consensys/gnark/std/math/emulated"
)

// ============================================================
// ONE AUTHENTICATED INTERNAL SEPARATOR
// ============================================================
//
// Native meaning:
//
//	LPC ---- separatorKey ---- RPC
//
// The parent polynomial contains:
//
//	mappedValue =
//	    H(
//	        "BPLUS-INTERNAL-ENTRY"
//	        || separatorKey
//	        || LPC
//	        || RPC
//	    )
//
// at evaluationPoint.
//
// CURRENT CIRCUIT MILESTONE:
//
// We enforce:
//
//	mappedValue == KZG claimed value
//
// but we DO NOT YET recompute the SHA-256 mapping inside
// the circuit.
//
// That will be added after the KZG membership path works.
type MembershipSeparatorCircuit struct {
	// Separator key used in the B+ tree routing condition.
	SeparatorKey frontend.Variable

	// Private witness containing the KZG evaluation point.
	//
	// This value is constrained inside Define() to equal the
	// compile-time evaluationPoint below.
	EvaluationPoint frontend.Variable

	// Left child commitment.
	LPC stdkzg.Commitment[sw_bn254.G1Affine]

	// Right child commitment.
	RPC stdkzg.Commitment[sw_bn254.G1Affine]

	// Value stored in the parent polynomial at evaluationPoint.
	MappedValue emulated.Element[sw_bn254.ScalarField]

	// KZG opening proof for the parent polynomial.
	OpeningProof stdkzg.OpeningProof[
		sw_bn254.ScalarField,
		sw_bn254.G1Affine,
	]

	// Expected evaluation point.
	//
	// Compile-time circuit structure.
	//
	// NOT part of the SNARK witness.
	evaluationPoint uint64
}

// ============================================================
// ONE INTERNAL B+ TREE LEVEL
// ============================================================

type MembershipLevelCircuit struct {
	// Commitment of this parent node.
	ParentCommitment stdkzg.Commitment[sw_bn254.G1Affine]

	// Each B+ tree node currently has an independently generated
	// KZG SRS.
	//
	// Therefore its KZG verification key must also be
	// authenticated.
	//
	// For the current prototype we expose it as PUBLIC input.
	VerifyingKey stdkzg.VerifyingKey[
		sw_bn254.G1Affine,
		sw_bn254.G2Affine,
	] `gnark:",public"`

	// ------------------------------------------------------------
	// LOWER RELATION
	// ------------------------------------------------------------
	//
	// Exists when:
	//
	//	childIndex > 0
	//
	// It proves:
	//
	//	lowerSeparator <= Key
	//
	// and:
	//
	//	currentCommitment == lower.RPC
	Lower MembershipSeparatorCircuit

	// ------------------------------------------------------------
	// UPPER RELATION
	// ------------------------------------------------------------
	//
	// Exists when:
	//
	//	childIndex < len(parent.keys)
	//
	// It proves:
	//
	//	Key < upperSeparator
	//
	// and:
	//
	//	currentCommitment == upper.LPC
	Upper MembershipSeparatorCircuit

	// Compile-time structure.
	//
	// These are not SNARK variables.
	hasLower bool
	hasUpper bool
}

// ============================================================
// ONE KEY -> ONE COMPLETE MEMBERSHIP CIRCUIT
// ============================================================
//
// The circuit authenticates:
//
//	    Key
//	     |
//	     v
//	leaf opening
//	     |
//	     v
//	  C_leaf
//	     |
//	     v
//	parent separator opening(s)
//	     |
//	     v
//	C_parent
//	     |
//	     v
//	   ...
//	     |
//	     v
//	  C_root
//	     |
//	     v
//	PUBLIC ROOT
//
// One satisfying witness will eventually produce:
//
//	ONE PLONK proof for ONE key.
type MembershipCircuit struct {
	// ============================================================
	// PUBLIC INPUTS
	// ============================================================

	// Key whose membership is being proved.
	Key frontend.Variable `gnark:",public"`

	// Public authenticated B+ tree root.
	RootCommitment stdkzg.Commitment[sw_bn254.G1Affine] `gnark:",public"`

	// ============================================================
	// PRIVATE LEAF WITNESS
	// ============================================================

	// Mapped value stored in the leaf polynomial.
	LeafMappedValue emulated.Element[sw_bn254.ScalarField]

	// Private witness containing the global leaf slot.
	//
	// This is constrained to leafEvaluationPoint.
	LeafEvaluationPoint frontend.Variable

	// Leaf polynomial commitment.
	LeafCommitment stdkzg.Commitment[sw_bn254.G1Affine]

	// KZG opening proof for the leaf entry.
	LeafOpeningProof stdkzg.OpeningProof[
		sw_bn254.ScalarField,
		sw_bn254.G1Affine,
	]

	// Current prototype:
	//
	// leaf KZG verification key is public.
	LeafVerifyingKey stdkzg.VerifyingKey[
		sw_bn254.G1Affine,
		sw_bn254.G2Affine,
	] `gnark:",public"`

	// ============================================================
	// INTERNAL AUTHENTICATION LEVELS
	// ============================================================
	//
	// Stored:
	//
	//	leaf parent -> ... -> root
	Levels []MembershipLevelCircuit

	// ============================================================
	// COMPILE-TIME CIRCUIT STRUCTURE
	// ============================================================

	// Exact global leaf evaluation point expected for this
	// particular membership-path circuit.
	//
	// Not a SNARK variable.
	leafEvaluationPoint uint64
}

// ============================================================
// DEFINE CIRCUIT
// ============================================================

func (c *MembershipCircuit) Define(
	api frontend.API,
) error {

	// ============================================================
	// KZG VERIFIER
	// ============================================================

	kzgVerifier, err :=
		stdkzg.NewVerifier[
			sw_bn254.ScalarField,
			sw_bn254.G1Affine,
			sw_bn254.G2Affine,
			sw_bn254.GTEl,
		](api)

	if err != nil {
		return fmt.Errorf(
			"failed creating KZG verifier: %w",
			err,
		)
	}

	// ============================================================
	// BN254 CURVE GADGET
	// ============================================================

	curve, err :=
		sw_emulated.New[
			sw_bn254.BaseField,
			sw_bn254.ScalarField,
		](
			api,
			sw_emulated.GetBN254Params(),
		)

	if err != nil {
		return fmt.Errorf(
			"failed creating BN254 curve gadget: %w",
			err,
		)
	}

	// ============================================================
	// BN254 SCALAR FIELD
	// ============================================================

	scalarField, err :=
		emulated.NewField[sw_bn254.ScalarField](api)

	if err != nil {
		return fmt.Errorf(
			"failed creating BN254 scalar field: %w",
			err,
		)
	}

	// ============================================================
	// 1. VERIFY LEAF OPENING
	// ============================================================

	// The leaf mapped value exported from the native tree must be
	// exactly the value authenticated by the KZG opening.
	scalarField.AssertIsEqual(
		&c.LeafMappedValue,
		&c.LeafOpeningProof.ClaimedValue,
	)

	// ------------------------------------------------------------
	// Bind leaf evaluation-point witness to its exact global slot.
	// ------------------------------------------------------------

	api.AssertIsEqual(
		c.LeafEvaluationPoint,
		c.leafEvaluationPoint,
	)

	// ------------------------------------------------------------
	// Convert evaluation point into an emulated BN254 scalar.
	//
	// IMPORTANT:
	//
	// BN254 Fr is represented by four limbs in this configuration.
	//
	// Supplying only:
	//
	//	scalarField.NewElement(c.LeafEvaluationPoint)
	//
	// gives gnark one limb and causes:
	//
	//	"enforcing width element with inexact number of limbs"
	//
	// Therefore we explicitly provide all four limbs.
	//
	// Evaluation points in our tree are small uint64 values, so:
	//
	//	[z, 0, 0, 0]
	//
	// is the correct representation.
	// ------------------------------------------------------------

	leafPoint :=
		scalarField.NewElement(
			[]frontend.Variable{
				c.LeafEvaluationPoint,
				0,
				0,
				0,
			},
		)

	// Verify leaf KZG opening.
	if err :=
		kzgVerifier.CheckOpeningProof(
			c.LeafCommitment,
			c.LeafOpeningProof,
			*leafPoint,
			c.LeafVerifyingKey,
		); err != nil {

		return fmt.Errorf(
			"leaf KZG verification failed: %w",
			err,
		)
	}

	// ============================================================
	// CURRENT AUTHENTICATED COMMITMENT
	// ============================================================
	//
	// We start at the leaf.
	//
	// Each internal level authenticates the current commitment
	// as one of the parent's children and then promotes the parent
	// commitment upward.

	currentCommitment :=
		&c.LeafCommitment.G1El

	// ============================================================
	// 2. WALK LEAF -> ROOT
	// ============================================================

	for levelIndex := range c.Levels {

		level :=
			&c.Levels[levelIndex]

		if !level.hasLower &&
			!level.hasUpper {

			return fmt.Errorf(
				"membership level %d has no authenticated separator relation",
				levelIndex,
			)
		}

		// ========================================================
		// LOWER RELATION
		// ========================================================
		//
		// For:
		//
		//	C_i
		//
		// where i > 0, the lower separator is:
		//
		//	key_{i-1}
		//
		// and standard B+ tree search requires:
		//
		//	key_{i-1} <= searchKey
		//
		// while the currently authenticated child must equal:
		//
		//	RPC(key_{i-1})

		if level.hasLower {

			lower :=
				&level.Lower

			// ----------------------------------------------------
			// Routing condition:
			//
			//	lowerSeparator <= Key
			// ----------------------------------------------------

			api.AssertIsLessOrEqual(
				lower.SeparatorKey,
				c.Key,
			)

			// ----------------------------------------------------
			// Current child must be the right child of the
			// lower separator.
			// ----------------------------------------------------

			curve.AssertIsEqual(
				currentCommitment,
				&lower.RPC.G1El,
			)

			// ----------------------------------------------------
			// KZG opening value must equal the exported mapped
			// value.
			// ----------------------------------------------------

			scalarField.AssertIsEqual(
				&lower.MappedValue,
				&lower.OpeningProof.ClaimedValue,
			)

			// ----------------------------------------------------
			// Bind evaluation point.
			// ----------------------------------------------------

			api.AssertIsEqual(
				lower.EvaluationPoint,
				lower.evaluationPoint,
			)

			// ----------------------------------------------------
			// Full four-limb BN254-Fr representation.
			// ----------------------------------------------------

			lowerPoint :=
				scalarField.NewElement(
					[]frontend.Variable{
						lower.EvaluationPoint,
						0,
						0,
						0,
					},
				)

			// ----------------------------------------------------
			// Authenticate this separator entry from the parent
			// polynomial.
			// ----------------------------------------------------

			if err :=
				kzgVerifier.CheckOpeningProof(
					level.ParentCommitment,
					lower.OpeningProof,
					*lowerPoint,
					level.VerifyingKey,
				); err != nil {

				return fmt.Errorf(
					"level %d lower KZG verification failed: %w",
					levelIndex,
					err,
				)
			}
		}

		// ========================================================
		// UPPER RELATION
		// ========================================================
		//
		// For child:
		//
		//	C_i
		//
		// where i < len(keys), the upper separator is:
		//
		//	key_i
		//
		// and standard B+ tree search requires:
		//
		//	searchKey < key_i
		//
		// while the currently authenticated child must equal:
		//
		//	LPC(key_i)

		if level.hasUpper {

			upper :=
				&level.Upper

			// ----------------------------------------------------
			// Strict routing condition:
			//
			//	Key < upperSeparator
			//
			// api.Cmp returns:
			//
			//	-1 : a < b
			//	 0 : a == b
			//	 1 : a > b
			// ----------------------------------------------------

			comparison :=
				api.Cmp(
					c.Key,
					upper.SeparatorKey,
				)

			api.AssertIsEqual(
				comparison,
				-1,
			)

			// ----------------------------------------------------
			// Current child must be the left child of the
			// upper separator.
			// ----------------------------------------------------

			curve.AssertIsEqual(
				currentCommitment,
				&upper.LPC.G1El,
			)

			// ----------------------------------------------------
			// KZG claimed value must equal exported mapped value.
			// ----------------------------------------------------

			scalarField.AssertIsEqual(
				&upper.MappedValue,
				&upper.OpeningProof.ClaimedValue,
			)

			// ----------------------------------------------------
			// Bind evaluation point.
			// ----------------------------------------------------

			api.AssertIsEqual(
				upper.EvaluationPoint,
				upper.evaluationPoint,
			)

			// ----------------------------------------------------
			// Full four-limb BN254-Fr representation.
			// ----------------------------------------------------

			upperPoint :=
				scalarField.NewElement(
					[]frontend.Variable{
						upper.EvaluationPoint,
						0,
						0,
						0,
					},
				)

			// ----------------------------------------------------
			// Authenticate separator entry from parent polynomial.
			// ----------------------------------------------------

			if err :=
				kzgVerifier.CheckOpeningProof(
					level.ParentCommitment,
					upper.OpeningProof,
					*upperPoint,
					level.VerifyingKey,
				); err != nil {

				return fmt.Errorf(
					"level %d upper KZG verification failed: %w",
					levelIndex,
					err,
				)
			}
		}

		// ========================================================
		// PROMOTE AUTHENTICATED PARENT
		// ========================================================
		//
		// Once the necessary separator relation(s) are verified,
		// the parent commitment becomes the currently
		// authenticated commitment.

		currentCommitment =
			&level.ParentCommitment.G1El
	}

	// ============================================================
	// 3. FINAL ROOT BINDING
	// ============================================================
	//
	// The commitment reached after the entire leaf -> root path
	// must equal the PUBLIC B+ tree root commitment.

	curve.AssertIsEqual(
		currentCommitment,
		&c.RootCommitment.G1El,
	)

	return nil
}

// ============================================================
// BUILD CIRCUIT SHAPE
// ============================================================
//
// This constructs the static shape for one membership path:
//
//   - number of internal levels
//   - whether each level has lower/upper relations
//   - leaf evaluation point
//   - internal evaluation points
//
// Witness values are not populated here.
func NewMembershipCircuitShape(
	path *bptree.MembershipPathData[int],
) (*MembershipCircuit, error) {

	if path == nil {
		return nil, fmt.Errorf(
			"membership path is nil",
		)
	}

	circuit :=
		&MembershipCircuit{
			Levels: make(
				[]MembershipLevelCircuit,
				len(path.Levels),
			),

			leafEvaluationPoint: path.LeafEvaluationPoint,
		}

	// ============================================================
	// COPY STATIC PATH STRUCTURE
	// ============================================================

	for levelIndex := range path.Levels {

		nativeLevel :=
			&path.Levels[levelIndex]

		circuitLevel :=
			&circuit.Levels[levelIndex]

		// --------------------------------------------------------
		// LOWER RELATION
		// --------------------------------------------------------

		if nativeLevel.LowerRelation != nil {

			circuitLevel.hasLower =
				true

			circuitLevel.Lower.evaluationPoint =
				nativeLevel.LowerRelation.EvaluationPoint
		}

		// --------------------------------------------------------
		// UPPER RELATION
		// --------------------------------------------------------

		if nativeLevel.UpperRelation != nil {

			circuitLevel.hasUpper =
				true

			circuitLevel.Upper.evaluationPoint =
				nativeLevel.UpperRelation.EvaluationPoint
		}

		if !circuitLevel.hasLower &&
			!circuitLevel.hasUpper {

			return nil, fmt.Errorf(
				"membership path level %d has no separator relation",
				levelIndex,
			)
		}
	}

	return circuit, nil
}
