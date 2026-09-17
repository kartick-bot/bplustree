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
// ONE AUTHENTICATED SEPARATOR
// ============================================================
//
// Every internal level now contains EXACTLY ONE separator
// relation and EXACTLY ONE KZG opening.
//
// Which side is followed is determined by MembershipLevelCircuit.IsLPC:
//
//	IsLPC = 1:
//	    Key < SeparatorKey
//	    current child = LPC
//
//	IsLPC = 0:
//	    SeparatorKey <= Key
//	    current child = RPC
//
// Therefore the circuit shape does NOT depend on which key is queried.
type MembershipSeparatorCircuit struct {
	SeparatorKey frontend.Variable

	// This is a real witness variable.
	// It is NOT compiled into the circuit anymore.
	EvaluationPoint frontend.Variable

	LPC stdkzg.Commitment[sw_bn254.G1Affine]
	RPC stdkzg.Commitment[sw_bn254.G1Affine]

	MappedValue emulated.Element[sw_bn254.ScalarField]

	OpeningProof stdkzg.OpeningProof[
		sw_bn254.ScalarField,
		sw_bn254.G1Affine,
	]
}

// ============================================================
// ONE INTERNAL LEVEL
// ============================================================

type MembershipLevelCircuit struct {
	ParentCommitment stdkzg.Commitment[sw_bn254.G1Affine]

	VerifyingKey stdkzg.VerifyingKey[
		sw_bn254.G1Affine,
		sw_bn254.G2Affine,
	] `gnark:",public"`

	// Exactly one relation/opening per level.
	Relation MembershipSeparatorCircuit

	// Private routing selector:
	//
	//     1 -> current child is LPC
	//     0 -> current child is RPC
	//
	// This is a SNARK variable, NOT a Go compile-time boolean.
	IsLPC frontend.Variable
}

// ============================================================
// COMPLETE MEMBERSHIP CIRCUIT
// ============================================================

type MembershipCircuit struct {
	// ========================================================
	// PUBLIC STATEMENT
	// ========================================================

	Key frontend.Variable `gnark:",public"`

	RootCommitment stdkzg.Commitment[sw_bn254.G1Affine] `gnark:",public"`

	// ========================================================
	// PRIVATE LEAF WITNESS
	// ========================================================

	LeafMappedValue emulated.Element[sw_bn254.ScalarField]

	// Different keys can use different leaf slots.
	LeafEvaluationPoint frontend.Variable

	LeafCommitment stdkzg.Commitment[sw_bn254.G1Affine]

	LeafOpeningProof stdkzg.OpeningProof[
		sw_bn254.ScalarField,
		sw_bn254.G1Affine,
	]

	LeafVerifyingKey stdkzg.VerifyingKey[
		sw_bn254.G1Affine,
		sw_bn254.G2Affine,
	] `gnark:",public"`

	// The slice length determines only the tree depth.
	//
	// For our scale tree this is always 6.
	Levels []MembershipLevelCircuit
}

// ============================================================
// BN254 SCALAR FROM A WITNESS VARIABLE
// ============================================================
//
// Evaluation points are small uint64 values.
//
// BN254 Fr is represented using four limbs here, therefore:
//
//	[z, 0, 0, 0]
//
// is used rather than field.NewElement(z).
func newBN254ScalarPointFromVariable(
	field *emulated.Field[sw_bn254.ScalarField],
	value frontend.Variable,
) *emulated.Element[sw_bn254.ScalarField] {

	return field.NewElement(
		[]frontend.Variable{
			value,
			0,
			0,
			0,
		},
	)
}

// ============================================================
// DEFINE
// ============================================================

func (c *MembershipCircuit) Define(
	api frontend.API,
) error {

	// ========================================================
	// KZG VERIFIER
	// ========================================================

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

	// ========================================================
	// BN254 CURVE
	// ========================================================

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

	// ========================================================
	// BN254 SCALAR FIELD
	// ========================================================

	scalarField, err :=
		emulated.NewField[sw_bn254.ScalarField](api)

	if err != nil {
		return fmt.Errorf(
			"failed creating BN254 scalar field: %w",
			err,
		)
	}

	// ========================================================
	// 1. LEAF OPENING
	// ========================================================

	scalarField.AssertIsEqual(
		&c.LeafMappedValue,
		&c.LeafOpeningProof.ClaimedValue,
	)

	leafPoint :=
		newBN254ScalarPointFromVariable(
			scalarField,
			c.LeafEvaluationPoint,
		)

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

	currentCommitment :=
		&c.LeafCommitment.G1El

	// ========================================================
	// 2. WALK LEAF -> ROOT
	// ========================================================

	for levelIndex := range c.Levels {

		level :=
			&c.Levels[levelIndex]

		relation :=
			&level.Relation

		// ----------------------------------------------------
		// ROUTING SELECTOR MUST BE BOOLEAN
		// ----------------------------------------------------

		api.AssertIsBoolean(
			level.IsLPC,
		)

		// ----------------------------------------------------
		// ONE COMPARISON FOR THIS LEVEL
		// ----------------------------------------------------
		//
		// Cmp(Key, SeparatorKey):
		//
		//    -1 : Key < SeparatorKey
		//     0 : Key == SeparatorKey
		//     1 : Key > SeparatorKey

		comparison :=
			api.Cmp(
				c.Key,
				relation.SeparatorKey,
			)

		// ----------------------------------------------------
		// LPC CASE
		// ----------------------------------------------------
		//
		// If:
		//
		//     IsLPC = 1
		//
		// require:
		//
		//     comparison = -1
		//
		// therefore:
		//
		//     Key < SeparatorKey

		api.AssertIsEqual(
			api.Mul(
				level.IsLPC,
				api.Add(
					comparison,
					1,
				),
			),
			0,
		)

		// ----------------------------------------------------
		// RPC CASE
		// ----------------------------------------------------
		//
		// If:
		//
		//     IsLPC = 0
		//
		// comparison must be either:
		//
		//     0 or 1
		//
		// i.e.
		//
		//     SeparatorKey <= Key
		//
		// Since comparison is {-1,0,1},
		//
		//     comparison * (comparison - 1) = 0
		//
		// accepts exactly {0,1}.

		isRPC :=
			api.Sub(
				1,
				level.IsLPC,
			)

		rpcComparisonConstraint :=
			api.Mul(
				comparison,
				api.Sub(
					comparison,
					1,
				),
			)

		api.AssertIsEqual(
			api.Mul(
				isRPC,
				rpcComparisonConstraint,
			),
			0,
		)

		// ----------------------------------------------------
		// SELECT LPC OR RPC INSIDE THE CIRCUIT
		// ----------------------------------------------------

		selectedChild :=
			curve.Select(
				level.IsLPC,
				&relation.LPC.G1El,
				&relation.RPC.G1El,
			)

		curve.AssertIsEqual(
			currentCommitment,
			selectedChild,
		)

		// ----------------------------------------------------
		// AUTHENTICATED MAPPED VALUE
		// ----------------------------------------------------

		scalarField.AssertIsEqual(
			&relation.MappedValue,
			&relation.OpeningProof.ClaimedValue,
		)

		// ----------------------------------------------------
		// EVALUATION POINT IS NOW WITNESS DATA
		// ----------------------------------------------------

		relationPoint :=
			newBN254ScalarPointFromVariable(
				scalarField,
				relation.EvaluationPoint,
			)

		// ----------------------------------------------------
		// EXACTLY ONE KZG VERIFICATION FOR THIS LEVEL
		// ----------------------------------------------------

		if err :=
			kzgVerifier.CheckOpeningProof(
				level.ParentCommitment,
				relation.OpeningProof,
				*relationPoint,
				level.VerifyingKey,
			); err != nil {

			return fmt.Errorf(
				"level %d KZG verification failed: %w",
				levelIndex,
				err,
			)
		}

		// ----------------------------------------------------
		// PROMOTE PARENT
		// ----------------------------------------------------

		currentCommitment =
			&level.ParentCommitment.G1El
	}

	// ========================================================
	// 3. ROOT BINDING
	// ========================================================

	curve.AssertIsEqual(
		currentCommitment,
		&c.RootCommitment.G1El,
	)

	return nil
}

// ============================================================
// CIRCUIT SHAPE
// ============================================================
//
// The shape now depends ONLY on depth.
//
// It no longer copies:
//
//   - leaf evaluation point
//   - internal evaluation points
//   - lower/upper path choices
//
// from a particular key.
func NewMembershipCircuitShape(
	path *bptree.MembershipPathData[int],
) (*MembershipCircuit, error) {

	if path == nil {
		return nil, fmt.Errorf(
			"membership path is nil",
		)
	}

	if len(path.Levels) == 0 {
		return nil, fmt.Errorf(
			"membership path has no internal levels",
		)
	}

	return &MembershipCircuit{
		Levels: make(
			[]MembershipLevelCircuit,
			len(path.Levels),
		),
	}, nil
}
