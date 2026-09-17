package snark

import (
	"fmt"

	"bplustree/bptree"

	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdkzg "github.com/consensys/gnark/std/commitments/kzg"
)

// NewTreeCircuitWitness converts the REAL native B+ tree
// cryptographic data into a gnark TreeCircuit assignment.
//
// This function does NOT:
//   - generate new commitments
//   - generate new KZG proofs
//   - generate new verification keys
//
// It converts the exact objects already produced by the native
// B+ tree implementation.
func NewTreeCircuitWitness[K any](
	data *bptree.TreeSNARKData[K],
) (*TreeCircuit, error) {

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
	// ALLOCATE COMPLETE CIRCUIT ASSIGNMENT
	// ============================================================

	assignment :=
		&TreeCircuit{
			Nodes: make(
				[]TreeNodeCircuit,
				len(data.Nodes),
			),

			rootIndex: data.RootIndex,
		}

	// ============================================================
	// CONVERT EVERY REAL TREE NODE
	// ============================================================

	for nodeIndex, nativeNode := range data.Nodes {

		circuitNode :=
			&assignment.Nodes[nodeIndex]

		// --------------------------------------------------------
		// THIS NODE'S KZG COMMITMENT
		// --------------------------------------------------------

		commitment, err :=
			stdkzg.ValueOfCommitment[sw_bn254.G1Affine](
				nativeNode.Commitment,
			)

		if err != nil {
			return nil, fmt.Errorf(
				"node %d: failed converting commitment: %w",
				nodeIndex,
				err,
			)
		}

		circuitNode.Commitment =
			commitment

		// --------------------------------------------------------
		// THIS NODE'S KZG VERIFICATION KEY
		// --------------------------------------------------------

		verifyingKey, err :=
			stdkzg.ValueOfVerifyingKey[
				sw_bn254.G1Affine,
				sw_bn254.G2Affine,
			](
				nativeNode.VerifyingKey,
			)

		if err != nil {
			return nil, fmt.Errorf(
				"node %d: failed converting verification key: %w",
				nodeIndex,
				err,
			)
		}

		circuitNode.VerifyingKey =
			verifyingKey

		// --------------------------------------------------------
		// THIS NODE'S KZG OPENING PROOFS
		// --------------------------------------------------------

		circuitNode.OpeningProofs =
			make(
				[]stdkzg.OpeningProof[
					sw_bn254.ScalarField,
					sw_bn254.G1Affine,
				],
				len(nativeNode.OpeningProofs),
			)

		for proofIndex, nativeProof := range nativeNode.OpeningProofs {

			openingProof, err :=
				stdkzg.ValueOfOpeningProof[
					sw_bn254.ScalarField,
					sw_bn254.G1Affine,
				](
					nativeProof,
				)

			if err != nil {
				return nil, fmt.Errorf(
					"node %d opening proof %d: conversion failed: %w",
					nodeIndex,
					proofIndex,
					err,
				)
			}

			circuitNode.OpeningProofs[proofIndex] =
				openingProof
		}

		// --------------------------------------------------------
		// CHILD COMMITMENTS
		// --------------------------------------------------------
		//
		// Leaves have zero child commitments.
		//
		// Internal nodes contain the exact commitments already
		// stored by the native B+ tree.

		circuitNode.ChildCommitments =
			make(
				[]stdkzg.Commitment[sw_bn254.G1Affine],
				len(nativeNode.ChildCommitments),
			)

		for childPosition, nativeCommitment := range nativeNode.ChildCommitments {

			childCommitment, err :=
				stdkzg.ValueOfCommitment[sw_bn254.G1Affine](
					nativeCommitment,
				)

			if err != nil {
				return nil, fmt.Errorf(
					"node %d child commitment %d: conversion failed: %w",
					nodeIndex,
					childPosition,
					err,
				)
			}

			circuitNode.ChildCommitments[childPosition] =
				childCommitment
		}

		// --------------------------------------------------------
		// COPY STATIC TOPOLOGY
		// --------------------------------------------------------
		//
		// These are not witness variables.
		//
		// We copy them here so the assignment retains the same
		// structural description as the compiled circuit.

		circuitNode.childIndices =
			append(
				[]int(nil),
				nativeNode.ChildIndices...,
			)

		circuitNode.evaluationPoints =
			append(
				[]uint64(nil),
				nativeNode.EvaluationPoints...,
			)
	}

	// ============================================================
	// PUBLIC ROOT COMMITMENT
	// ============================================================

	rootCommitment, err :=
		stdkzg.ValueOfCommitment[sw_bn254.G1Affine](
			data.RootCommitment,
		)

	if err != nil {
		return nil, fmt.Errorf(
			"failed converting public root commitment: %w",
			err,
		)
	}

	assignment.RootCommitment =
		rootCommitment

	return assignment, nil
}
