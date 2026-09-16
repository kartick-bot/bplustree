package bptree

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

// PrintKZGDetails prints all KZG-related information
// for every leaf.
//
// Each leaf has its OWN independently generated SRS.
func (t *Tree[K, V]) PrintKZGDetails() error {

	if t.root == nil {
		return fmt.Errorf("tree has no root")
	}

	fmt.Println()
	fmt.Println("================================================================")
	fmt.Println("KZG DETAILS")
	fmt.Println("================================================================")

	fmt.Println()
	fmt.Println("Field modulus p:")
	fmt.Println(t.modulus.String())

	leafNumber := 0

	// Special case: tree consists of only one leaf.
	if t.root.isLeaf {
		return t.printSingleLeafKZGDetails(
			t.root,
			nil,
			-1,
			&leafNumber,
		)
	}

	return t.printKZGDetailsRecursive(
		t.root,
		&leafNumber,
	)
}

// printKZGDetailsRecursive traverses the tree and prints
// information for every leaf.
func (t *Tree[K, V]) printKZGDetailsRecursive(
	parent *node[K, V],
	leafNumber *int,
) error {

	if parent == nil || parent.isLeaf {
		return nil
	}

	for childIndex, child := range parent.children {

		if child == nil {
			return fmt.Errorf(
				"nil child at index %d",
				childIndex,
			)
		}

		if child.isLeaf {

			if err := t.printSingleLeafKZGDetails(
				child,
				parent,
				childIndex,
				leafNumber,
			); err != nil {
				return err
			}

			continue
		}

		if err := t.printKZGDetailsRecursive(
			child,
			leafNumber,
		); err != nil {
			return err
		}
	}

	return nil
}

// printSingleLeafKZGDetails prints all KZG information
// for one leaf.
func (t *Tree[K, V]) printSingleLeafKZGDetails(
	leaf *node[K, V],
	parent *node[K, V],
	childIndex int,
	leafNumber *int,
) error {

	if leaf == nil {
		return fmt.Errorf(
			"nil leaf encountered",
		)
	}

	if !leaf.isLeaf {
		return fmt.Errorf(
			"printSingleLeafKZGDetails called on internal node",
		)
	}

	if len(leaf.entries) == 0 {
		return fmt.Errorf(
			"cannot print KZG details for empty leaf",
		)
	}

	if len(leaf.entries) != len(leaf.mappedValues) {
		return fmt.Errorf(
			"leaf entry/mapped-value length mismatch",
		)
	}

	// Every leaf must have its own SRS.
	if leaf.leafSRS == nil {
		return fmt.Errorf(
			"leaf %d has no KZG SRS",
			*leafNumber,
		)
	}

	fmt.Println()
	fmt.Println("================================================================")
	fmt.Printf("LEAF %d\n", *leafNumber)
	fmt.Println("================================================================")

	// ============================================================
	// LEAF'S OWN SRS
	// ============================================================

	fmt.Println()
	fmt.Println("----------------------------------------------------------------")
	fmt.Printf("SRS FOR LEAF %d\n", *leafNumber)
	fmt.Println("----------------------------------------------------------------")

	fmt.Printf(
		"Number of G1 proving-key powers: %d\n",
		len(leaf.leafSRS.Pk.G1),
	)

	fmt.Println()
	fmt.Println("Proving-key G1 powers:")

	for i := range leaf.leafSRS.Pk.G1 {

		b := leaf.leafSRS.Pk.G1[i].Bytes()

		fmt.Printf(
			"  SRS_leaf_%d[%d] = [tau_%d^%d]G1\n",
			*leafNumber,
			i,
			*leafNumber,
			i,
		)

		fmt.Printf(
			"    compressed = %x\n",
			b,
		)
	}

	fmt.Println()
	fmt.Println("Verifying-key G1:")

	vkG1 :=
		leaf.leafSRS.Vk.G1.Bytes()

	fmt.Printf(
		"  %x\n",
		vkG1,
	)

	fmt.Println()
	fmt.Println("Verifying-key G2 points:")

	for i := range leaf.leafSRS.Vk.G2 {

		b :=
			leaf.leafSRS.Vk.G2[i].Bytes()

		fmt.Printf(
			"  VK.G2[%d] = %x\n",
			i,
			b,
		)
	}

	fmt.Println()
	fmt.Printf(
		"Leaf %d uses its own independently generated trapdoor tau_%d.\n",
		*leafNumber,
		*leafNumber,
	)

	fmt.Println(
		"The secret trapdoor itself is not stored or printed.",
	)

	// ============================================================
	// CONVERT MAPPED VALUES TO FIELD ELEMENTS
	// ============================================================

	values := make(
		[]fr.Element,
		len(leaf.mappedValues),
	)

	for i, mapped := range leaf.mappedValues {

		if mapped == nil {
			return fmt.Errorf(
				"nil mapped value at leaf %d position %d",
				*leafNumber,
				i,
			)
		}

		values[i].SetBigInt(mapped)
	}

	// ============================================================
	// LEAF ENTRIES
	// ============================================================

	fmt.Println()
	fmt.Println("Leaf entries and mapped field elements:")

	for i, entry := range leaf.entries {

		fmt.Printf("\n  Element %d\n", i)

		fmt.Printf(
			"    key                = %v\n",
			entry.Key,
		)

		fmt.Printf(
			"    H(key)             = %x\n",
			entry.Value,
		)

		fmt.Printf(
			"    evaluation point   = %d\n",
			i,
		)

		fmt.Printf(
			"    mapped m_%d         = %s\n",
			i,
			leaf.mappedValues[i].String(),
		)

		// --------------------------------------------------------
		// Individual commitment to the mapped element.
		//
		// Constant polynomial:
		//
		//     g_i(X) = m_i
		//
		// Uses THIS leaf's SRS.
		// --------------------------------------------------------

		elementPoly := []fr.Element{
			values[i],
		}

		elementCommitment, err :=
			kzg.Commit(
				elementPoly,
				leaf.leafSRS.Pk,
			)

		if err != nil {
			return fmt.Errorf(
				"failed element commitment for leaf %d element %d: %w",
				*leafNumber,
				i,
				err,
			)
		}

		elementBytes :=
			elementCommitment.Bytes()

		fmt.Printf(
			"    element commitment = %x\n",
			elementBytes,
		)
	}

	// ============================================================
	// INTERPOLATING POLYNOMIAL
	// ============================================================

	poly :=
		polynomial.InterpolateOnRange(
			values,
		)

	coefficients :=
		[]fr.Element(poly)

	fmt.Println()
	fmt.Println("Interpolating polynomial:")

	fmt.Printf(
		"  degree <= %d\n",
		len(coefficients)-1,
	)

	fmt.Println()
	fmt.Println("  Evaluation form:")

	for i, mapped := range leaf.mappedValues {

		fmt.Printf(
			"    f_%d(%d) = %s\n",
			*leafNumber,
			i,
			mapped.String(),
		)
	}

	// ============================================================
	// COEFFICIENTS
	// ============================================================

	fmt.Println()
	fmt.Println("  Coefficient form:")

	for i := range coefficients {

		var coefficientBig big.Int

		coefficients[i].BigInt(
			&coefficientBig,
		)

		fmt.Printf(
			"    a_%d = %s\n",
			i,
			coefficientBig.String(),
		)

		fmt.Printf(
			"          0x%s\n",
			coefficientBig.Text(16),
		)
	}

	// ============================================================
	// SRS POWERS USED BY THIS POLYNOMIAL
	// ============================================================

	if len(coefficients) >
		len(leaf.leafSRS.Pk.G1) {

		return fmt.Errorf(
			"leaf %d requires %d SRS powers but its SRS has only %d",
			*leafNumber,
			len(coefficients),
			len(leaf.leafSRS.Pk.G1),
		)
	}

	fmt.Println()
	fmt.Println("SRS points actually used by this leaf polynomial:")

	for i := range coefficients {

		srsBytes :=
			leaf.leafSRS.Pk.G1[i].Bytes()

		fmt.Printf(
			"  [tau_%d^%d]G1 = %x\n",
			*leafNumber,
			i,
			srsBytes,
		)
	}

	// ============================================================
	// COEFFICIENT CONTRIBUTIONS
	// ============================================================

	fmt.Println()
	fmt.Println("Coefficient KZG contributions:")

	fmt.Printf(
		"  C_leaf_%d = Σ a_i [tau_%d^i]G1\n",
		*leafNumber,
		*leafNumber,
	)

	for i := range coefficients {

		var coefficientBig big.Int

		coefficients[i].BigInt(
			&coefficientBig,
		)

		var contribution kzg.Digest

		contribution.ScalarMultiplication(
			&leaf.leafSRS.Pk.G1[i],
			&coefficientBig,
		)

		contributionBytes :=
			contribution.Bytes()

		fmt.Printf(
			"  a_%d * [tau_%d^%d]G1 = %x\n",
			i,
			*leafNumber,
			i,
			contributionBytes,
		)
	}

	// ============================================================
	// FINAL LEAF COMMITMENT
	// ============================================================

	leafCommitment, err :=
		kzg.Commit(
			coefficients,
			leaf.leafSRS.Pk,
		)

	if err != nil {
		return fmt.Errorf(
			"failed to recompute leaf %d commitment: %w",
			*leafNumber,
			err,
		)
	}

	leafCommitmentBytes :=
		leafCommitment.Bytes()

	fmt.Println()
	fmt.Println("Final leaf KZG commitment:")

	fmt.Printf(
		"  C_leaf_%d = %x\n",
		*leafNumber,
		leafCommitmentBytes,
	)

	// ============================================================
	// PARENT LPC / RPC
	// ============================================================

	if parent != nil {

		fmt.Println()
		fmt.Println("Parent-pointer interpretation:")

		fmt.Printf(
			"  child index = %d\n",
			childIndex,
		)

		// child[i] corresponds to LPC[i].
		if childIndex < len(parent.keys) {

			fmt.Printf(
				"  LPC[%d] for separator key %v\n",
				childIndex,
				parent.keys[childIndex],
			)
		}

		// child[i] also corresponds to RPC[i-1].
		if childIndex > 0 {

			fmt.Printf(
				"  RPC[%d] for separator key %v\n",
				childIndex-1,
				parent.keys[childIndex-1],
			)
		}

		if childIndex <
			len(parent.childCommitments) &&
			parent.childCommitments[childIndex] != nil {

			stored :=
				parent.childCommitments[childIndex]

			storedBytes :=
				stored.Bytes()

			fmt.Printf(
				"  stored parent commitment = %x\n",
				storedBytes,
			)

			equal :=
				stored.Equal(
					&leafCommitment,
				)

			fmt.Printf(
				"  stored == recomputed     = %v\n",
				equal,
			)

		} else {

			fmt.Println(
				"  stored parent commitment = <missing>",
			)
		}
	}

	*leafNumber =
		*leafNumber + 1

	return nil
}