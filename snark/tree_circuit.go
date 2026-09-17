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
// ONE B+ TREE NODE INSIDE THE SNARK
// ============================================================
//
// Each TreeNodeCircuit represents one node from the real B+ tree.
//
// The native tree has already generated:
//
//   - one KZG commitment for this node
//   - one KZG opening proof for every mapped value
//   - one node-specific KZG verification key
//
// Internal nodes additionally contain the commitments of their
// children.
//
// The topology itself is compile-time information and therefore
// is NOT supplied by the prover as witness data.
type TreeNodeCircuit struct {

	// ------------------------------------------------------------
	// THIS NODE'S KZG COMMITMENT
	// ------------------------------------------------------------

	Commitment stdkzg.Commitment[sw_bn254.G1Affine]

	// ------------------------------------------------------------
	// THIS NODE'S KZG OPENING PROOFS
	// ------------------------------------------------------------
	//
	// Leaf:
	//
	//   proofs correspond to global evaluation points.
	//
	// Internal:
	//
	//   proofs correspond to local evaluation points 0,1,2,...
	OpeningProofs []stdkzg.OpeningProof[
		sw_bn254.ScalarField,
		sw_bn254.G1Affine,
	]

	// ------------------------------------------------------------
	// NODE-SPECIFIC KZG VERIFICATION KEY
	// ------------------------------------------------------------
	//
	// IMPORTANT:
	//
	// Our native B+ tree currently generates an independent SRS
	// for every node.
	//
	// Therefore every node has its own KZG verification key.
	//
	// For this first whole-tree circuit we expose each VK as
	// public input so the prover cannot secretly choose an
	// arbitrary verification key.
	VerifyingKey stdkzg.VerifyingKey[
		sw_bn254.G1Affine,
		sw_bn254.G2Affine,
	] `gnark:",public"`

	// ------------------------------------------------------------
	// CHILD COMMITMENTS
	// ------------------------------------------------------------
	//
	// Empty for leaves.
	//
	// For an internal node:
	//
	//   ChildCommitments[0] = commitment of child 0
	//   ChildCommitments[1] = commitment of child 1
	//   ...
	//
	// The circuit will enforce that these actually equal the
	// commitments of the corresponding nodes in Nodes[].
	ChildCommitments []stdkzg.Commitment[sw_bn254.G1Affine]

	// ============================================================
	// COMPILE-TIME TREE TOPOLOGY
	// ============================================================
	//
	// These fields are intentionally unexported.
	//
	// gnark does NOT treat them as witness variables.
	//
	// They describe the fixed circuit shape.

	// Indices of this node's children inside TreeCircuit.Nodes.
	childIndices []int

	// Evaluation point corresponding to every OpeningProof.
	//
	// Leaves:
	//
	//   global evaluation points
	//
	// Internal nodes:
	//
	//   0,1,2,...
	evaluationPoints []uint64
}

// ============================================================
// COMPLETE B+ TREE CIRCUIT
// ============================================================

type TreeCircuit struct {

	// Nodes use the exact post-order produced by ExportSNARKData:
	//
	//   leaves
	//      ↓
	//   lower internal nodes
	//      ↓
	//   root
	Nodes []TreeNodeCircuit

	// ------------------------------------------------------------
	// PUBLIC ROOT COMMITMENT
	// ------------------------------------------------------------
	//
	// Ultimately this is the authenticated value representing
	// the complete committed B+ tree.
	RootCommitment stdkzg.Commitment[sw_bn254.G1Affine] `gnark:",public"`

	// Compile-time root location inside Nodes.
	rootIndex int
}

// ============================================================
// TREE CIRCUIT DEFINITION
// ============================================================

func (c *TreeCircuit) Define(api frontend.API) error {

	// ============================================================
	// CREATE IN-CIRCUIT KZG VERIFIER
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
			"failed creating in-circuit KZG verifier: %w",
			err,
		)
	}

	// ============================================================
	// CREATE BN254 G1 CURVE GADGET
	// ============================================================
	//
	// We use this for commitment equality checks:
	//
	//   parent's stored child commitment
	//
	//             ==
	//
	//   actual commitment of that child node
	//
	// and later:
	//
	//   actual root commitment
	//
	//             ==
	//
	//   public root commitment

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
	// CREATE BN254 SCALAR FIELD GADGET
	// ============================================================
	//
	// KZG evaluation points live in BN254 Fr.
	//
	// Evaluation points are constants encoded directly in the
	// compiled circuit shape.

	scalarField, err :=
		emulated.NewField[sw_bn254.ScalarField](api)

	if err != nil {
		return fmt.Errorf(
			"failed creating BN254 scalar field gadget: %w",
			err,
		)
	}

	// ============================================================
	// SANITY CHECK TREE SHAPE
	// ============================================================

	if len(c.Nodes) == 0 {
		return fmt.Errorf(
			"tree circuit contains no nodes",
		)
	}

	if c.rootIndex < 0 ||
		c.rootIndex >= len(c.Nodes) {

		return fmt.Errorf(
			"invalid root index %d for %d nodes",
			c.rootIndex,
			len(c.Nodes),
		)
	}

	// ============================================================
	// VERIFY EVERY NODE
	// ============================================================

	for nodeIndex := range c.Nodes {

		node :=
			&c.Nodes[nodeIndex]

		// --------------------------------------------------------
		// SANITY CHECK:
		//
		// one evaluation point per opening proof
		// --------------------------------------------------------

		if len(node.OpeningProofs) !=
			len(node.evaluationPoints) {

			return fmt.Errorf(
				"node %d has %d opening proofs but %d evaluation points",
				nodeIndex,
				len(node.OpeningProofs),
				len(node.evaluationPoints),
			)
		}

		// ========================================================
		// VERIFY ALL KZG OPENINGS FOR THIS NODE
		// ========================================================
		//
		// For every opening j:
		//
		//   KZGVerify(
		//       commitment,
		//       proof_j,
		//       evaluationPoint_j,
		//       verificationKey,
		//   ) = true
		//
		// OpeningProof already contains ClaimedValue.

		for proofIndex := range node.OpeningProofs {

			evaluationPoint :=
				node.evaluationPoints[proofIndex]

			// Convert the fixed uint64 evaluation point into an
			// emulated BN254 scalar-field element.
			point :=
				scalarField.NewElement(
					evaluationPoint,
				)

			if err :=
				kzgVerifier.CheckOpeningProof(
					node.Commitment,
					node.OpeningProofs[proofIndex],
					*point,
					node.VerifyingKey,
				); err != nil {

				return fmt.Errorf(
					"node %d KZG opening %d verification failed: %w",
					nodeIndex,
					proofIndex,
					err,
				)
			}
		}

		// ========================================================
		// VERIFY PARENT -> CHILD COMMITMENT WIRING
		// ========================================================

		if len(node.ChildCommitments) !=
			len(node.childIndices) {

			return fmt.Errorf(
				"node %d has %d child commitments but %d child indices",
				nodeIndex,
				len(node.ChildCommitments),
				len(node.childIndices),
			)
		}

		for childPosition, childIndex := range node.childIndices {

			// ----------------------------------------------------
			// Child index must refer to a valid node.
			// ----------------------------------------------------

			if childIndex < 0 ||
				childIndex >= len(c.Nodes) {

				return fmt.Errorf(
					"node %d contains invalid child index %d",
					nodeIndex,
					childIndex,
				)
			}

			// ----------------------------------------------------
			// Because nodes are exported in post-order, every
			// child MUST occur before its parent.
			// ----------------------------------------------------

			if childIndex >= nodeIndex {

				return fmt.Errorf(
					"node %d has child index %d which is not before the parent in post-order",
					nodeIndex,
					childIndex,
				)
			}

			// ----------------------------------------------------
			// Parent-stored commitment.
			// ----------------------------------------------------

			parentStoredCommitment :=
				&node.ChildCommitments[childPosition].G1El

			// ----------------------------------------------------
			// Commitment belonging to the actual child node.
			// ----------------------------------------------------

			actualChildCommitment :=
				&c.Nodes[childIndex].Commitment.G1El

			// ----------------------------------------------------
			// Enforce:
			//
			// ChildCommitments[childPosition]
			//
			//                ==
			//
			// Nodes[childIndex].Commitment
			// ----------------------------------------------------

			curve.AssertIsEqual(
				parentStoredCommitment,
				actualChildCommitment,
			)
		}
	}

	// ============================================================
	// ROOT BINDING
	// ============================================================
	//
	// Finally enforce:
	//
	//   commitment of actual root node
	//
	//                ==
	//
	//   public RootCommitment

	actualRootCommitment :=
		&c.Nodes[c.rootIndex].Commitment.G1El

	publicRootCommitment :=
		&c.RootCommitment.G1El

	curve.AssertIsEqual(
		actualRootCommitment,
		publicRootCommitment,
	)

	return nil
}

// ============================================================
// BUILD STATIC CIRCUIT SHAPE FROM THE REAL B+ TREE
// ============================================================
//
// This function DOES NOT populate witness values.
//
// It constructs only the static shape gnark needs during
// compilation:
//
//   - number of nodes
//   - number of KZG proofs per node
//   - number of child commitments per node
//   - evaluation points
//   - parent/child topology
//   - root index
//
// The actual cryptographic values will be populated separately
// when we construct the witness.
func NewTreeCircuitShape[K any](
	data *bptree.TreeSNARKData[K],
) (*TreeCircuit, error) {

	// ============================================================
	// VALIDATE EXPORTED TREE DATA
	// ============================================================

	if data == nil {
		return nil, fmt.Errorf(
			"tree SNARK data is nil",
		)
	}

	if len(data.Nodes) == 0 {
		return nil, fmt.Errorf(
			"tree SNARK data contains no nodes",
		)
	}

	if data.RootIndex < 0 ||
		data.RootIndex >= len(data.Nodes) {

		return nil, fmt.Errorf(
			"invalid root index %d for %d nodes",
			data.RootIndex,
			len(data.Nodes),
		)
	}

	// ============================================================
	// ALLOCATE CIRCUIT
	// ============================================================

	circuit :=
		&TreeCircuit{
			Nodes: make(
				[]TreeNodeCircuit,
				len(data.Nodes),
			),

			rootIndex: data.RootIndex,
		}

	// ============================================================
	// COPY ONLY STATIC SHAPE INFORMATION
	// ============================================================

	for nodeIndex, nativeNode := range data.Nodes {

		node :=
			&circuit.Nodes[nodeIndex]

		// --------------------------------------------------------
		// Allocate one circuit opening-proof object for every
		// real KZG opening proof.
		// --------------------------------------------------------

		node.OpeningProofs =
			make(
				[]stdkzg.OpeningProof[
					sw_bn254.ScalarField,
					sw_bn254.G1Affine,
				],
				len(nativeNode.OpeningProofs),
			)

		// --------------------------------------------------------
		// Allocate one circuit child commitment for every native
		// child commitment.
		// --------------------------------------------------------

		node.ChildCommitments =
			make(
				[]stdkzg.Commitment[sw_bn254.G1Affine],
				len(nativeNode.ChildCommitments),
			)

		// --------------------------------------------------------
		// Copy static parent/child topology.
		// --------------------------------------------------------

		node.childIndices =
			append(
				[]int(nil),
				nativeNode.ChildIndices...,
			)

		// --------------------------------------------------------
		// Copy fixed evaluation points.
		//
		// Leaf:
		//
		//   global positions
		//
		// Internal:
		//
		//   local 0,1,2,...
		// --------------------------------------------------------

		node.evaluationPoints =
			append(
				[]uint64(nil),
				nativeNode.EvaluationPoints...,
			)
	}

	return circuit, nil
}
