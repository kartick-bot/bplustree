package bptree

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

const treeSnapshotVersion uint32 = 1

// ============================================================
// SERIALIZABLE TREE SNAPSHOT
// ============================================================
//
// We deliberately do NOT serialize:
//
//   - Tree.compare
//   - Tree.hasher
//   - Tree.fieldMapper
//   - Tree.internalFieldMapper
//   - node.next
//
// Function values cannot be serialized, so they are supplied again
// when loading.
//
// node.next is reconstructed from the left-to-right leaf order.
//
// Everything cryptographically relevant to the authenticated tree
// IS serialized:
//
//   - exact tree shape
//   - keys / leaf entries
//   - global leaf evaluation points
//   - leaf mapped values
//   - internal mapped values
//   - child commitments
//   - node commitments
//   - per-node KZG SRS
//   - opening proofs
//   - pairing-verification status
//
// Therefore loading a snapshot does NOT generate new SRS values and
// does NOT change the authenticated root commitment.

type treeSnapshot[K any] struct {
	Version uint32
	Order   int
	Root    *nodeSnapshot[K]
}

type nodeSnapshot[K any] struct {
	IsLeaf bool

	// ------------------------------------------------------------
	// INTERNAL NODE DATA
	// ------------------------------------------------------------

	Keys []K

	Children []*nodeSnapshot[K]

	ChildCommitments [][]byte

	InternalMappedValues []string

	// ------------------------------------------------------------
	// LEAF DATA
	// ------------------------------------------------------------

	Entries []Entry[K]

	MappedValues []string

	EvaluationPoints []uint64

	// ------------------------------------------------------------
	// KZG DATA
	// ------------------------------------------------------------

	NodeSRS []byte

	Commitment []byte

	OpeningProofs [][]byte

	PairingsVerified bool
}

// ============================================================
// PUBLIC SAVE
// ============================================================

// SaveSnapshot writes the complete authenticated B+ tree to disk.
//
// BuildCommitments() must already have been called.
//
// The snapshot contains the exact KZG material belonging to every node.
// In particular, loading the snapshot does NOT regenerate node SRSs.
func (t *Tree[K, V]) SaveSnapshot(
	filename string,
) error {

	if t == nil {
		return fmt.Errorf(
			"cannot save nil tree",
		)
	}

	if t.root == nil {
		return fmt.Errorf(
			"cannot save tree with nil root",
		)
	}

	if filename == "" {
		return fmt.Errorf(
			"snapshot filename is empty",
		)
	}

	// We require the authenticated root to exist.
	if t.root.commitment == nil {
		return fmt.Errorf(
			"tree has no root commitment; call BuildCommitments first",
		)
	}

	rootSnapshot, err :=
		makeNodeSnapshot(
			t.root,
		)

	if err != nil {
		return fmt.Errorf(
			"failed building tree snapshot: %w",
			err,
		)
	}

	snapshot :=
		treeSnapshot[K]{
			Version: treeSnapshotVersion,
			Order:   t.order,
			Root:    rootSnapshot,
		}

	file, err :=
		os.Create(
			filename,
		)

	if err != nil {
		return fmt.Errorf(
			"failed creating snapshot file: %w",
			err,
		)
	}

	defer file.Close()

	encoder :=
		gob.NewEncoder(
			file,
		)

	if err :=
		encoder.Encode(
			&snapshot,
		); err != nil {

		return fmt.Errorf(
			"failed encoding tree snapshot: %w",
			err,
		)
	}

	return nil
}

// ============================================================
// PUBLIC LOAD
// ============================================================

// LoadSnapshot restores an authenticated tree previously written by
// SaveSnapshot.
//
// The functions are supplied again because Go function values cannot
// be serialized.
//
// Importantly, no KZG SRS is regenerated here.
func LoadSnapshot[K any, V any](
	filename string,
	compare Comparator[K],
	hasher Hasher[K],
	fieldMapper FieldMapper[K],
	internalFieldMapper InternalFieldMapper[K],
) (*Tree[K, V], error) {

	if filename == "" {
		return nil, fmt.Errorf(
			"snapshot filename is empty",
		)
	}

	file, err :=
		os.Open(
			filename,
		)

	if err != nil {
		return nil, fmt.Errorf(
			"failed opening snapshot file: %w",
			err,
		)
	}

	defer file.Close()

	var snapshot treeSnapshot[K]

	decoder :=
		gob.NewDecoder(
			file,
		)

	if err :=
		decoder.Decode(
			&snapshot,
		); err != nil {

		return nil, fmt.Errorf(
			"failed decoding tree snapshot: %w",
			err,
		)
	}

	if snapshot.Version !=
		treeSnapshotVersion {

		return nil, fmt.Errorf(
			"unsupported snapshot version %d; expected %d",
			snapshot.Version,
			treeSnapshotVersion,
		)
	}

	if snapshot.Order < 3 {
		return nil, fmt.Errorf(
			"invalid snapshot tree order %d",
			snapshot.Order,
		)
	}

	if snapshot.Root == nil {
		return nil, fmt.Errorf(
			"snapshot contains nil root",
		)
	}

	// Create an ordinary Tree so that:
	//
	//   - comparator
	//   - hashing function
	//   - leaf mapper
	//   - internal mapper
	//   - BN254 modulus
	//
	// are initialized exactly as they are for a fresh tree.
	tree, err :=
		New[K, V](
			snapshot.Order,
			compare,
			hasher,
			fieldMapper,
			internalFieldMapper,
		)

	if err != nil {
		return nil, fmt.Errorf(
			"failed creating tree during snapshot load: %w",
			err,
		)
	}

	loadedRoot, leaves, err :=
		restoreNodeSnapshot[K, V](
			snapshot.Root,
		)

	if err != nil {
		return nil, fmt.Errorf(
			"failed restoring tree nodes: %w",
			err,
		)
	}

	tree.root =
		loadedRoot

	// ------------------------------------------------------------
	// REBUILD LEAF CHAIN
	// ------------------------------------------------------------

	for i :=
		0; i < len(leaves)-1; i++ {

		leaves[i].next =
			leaves[i+1]
	}

	if len(leaves) > 0 {
		leaves[len(leaves)-1].next =
			nil
	}

	return tree, nil
}

// ============================================================
// TREE -> SNAPSHOT
// ============================================================

func makeNodeSnapshot[K any, V any](
	n *node[K, V],
) (*nodeSnapshot[K], error) {

	if n == nil {
		return nil, fmt.Errorf(
			"cannot snapshot nil node",
		)
	}

	result :=
		&nodeSnapshot[K]{
			IsLeaf: n.isLeaf,

			Keys: append(
				[]K(nil),
				n.keys...,
			),

			Entries: append(
				[]Entry[K](nil),
				n.entries...,
			),

			EvaluationPoints: append(
				[]uint64(nil),
				n.evaluationPoints...,
			),

			PairingsVerified: n.pairingsVerified,
		}

	// ============================================================
	// MAPPED VALUES
	// ============================================================

	var err error

	result.MappedValues, err =
		encodeBigInts(
			n.mappedValues,
		)

	if err != nil {
		return nil, fmt.Errorf(
			"failed encoding leaf mapped values: %w",
			err,
		)
	}

	result.InternalMappedValues, err =
		encodeBigInts(
			n.internalMappedValues,
		)

	if err != nil {
		return nil, fmt.Errorf(
			"failed encoding internal mapped values: %w",
			err,
		)
	}

	// ============================================================
	// NODE SRS
	// ============================================================

	if n.nodeSRS != nil {

		result.NodeSRS, err =
			encodeSRS(
				n.nodeSRS,
			)

		if err != nil {
			return nil, fmt.Errorf(
				"failed encoding node SRS: %w",
				err,
			)
		}
	}

	// ============================================================
	// NODE COMMITMENT
	// ============================================================

	if n.commitment != nil {

		result.Commitment =
			encodeDigest(
				n.commitment,
			)
	}

	// ============================================================
	// CHILD COMMITMENTS
	// ============================================================

	result.ChildCommitments =
		make(
			[][]byte,
			len(n.childCommitments),
		)

	for i, commitment := range n.childCommitments {

		if commitment == nil {
			continue
		}

		result.ChildCommitments[i] =
			encodeDigest(
				commitment,
			)
	}

	// ============================================================
	// OPENING PROOFS
	// ============================================================

	result.OpeningProofs =
		make(
			[][]byte,
			len(n.openingProofs),
		)

	for i := range n.openingProofs {

		proofBytes, err :=
			encodeOpeningProof(
				&n.openingProofs[i],
			)

		if err != nil {
			return nil, fmt.Errorf(
				"failed encoding opening proof %d: %w",
				i,
				err,
			)
		}

		result.OpeningProofs[i] =
			proofBytes
	}

	// ============================================================
	// CHILDREN
	// ============================================================

	result.Children =
		make(
			[]*nodeSnapshot[K],
			len(n.children),
		)

	for i, child := range n.children {

		childSnapshot, err :=
			makeNodeSnapshot(
				child,
			)

		if err != nil {
			return nil, fmt.Errorf(
				"failed snapshotting child %d: %w",
				i,
				err,
			)
		}

		result.Children[i] =
			childSnapshot
	}

	return result, nil
}

// ============================================================
// SNAPSHOT -> TREE
// ============================================================
//
// Returns:
//
//   - restored node
//   - all leaves below that node, left-to-right
//
// The leaf list is used to reconstruct node.next.

func restoreNodeSnapshot[K any, V any](
	snapshot *nodeSnapshot[K],
) (
	*node[K, V],
	[]*node[K, V],
	error,
) {

	if snapshot == nil {
		return nil, nil, fmt.Errorf(
			"cannot restore nil node snapshot",
		)
	}

	n :=
		&node[K, V]{
			isLeaf: snapshot.IsLeaf,

			keys: append(
				[]K(nil),
				snapshot.Keys...,
			),

			entries: append(
				[]Entry[K](nil),
				snapshot.Entries...,
			),

			evaluationPoints: append(
				[]uint64(nil),
				snapshot.EvaluationPoints...,
			),

			pairingsVerified: snapshot.PairingsVerified,
		}

	// ============================================================
	// MAPPED VALUES
	// ============================================================

	var err error

	n.mappedValues, err =
		decodeBigInts(
			snapshot.MappedValues,
		)

	if err != nil {
		return nil, nil, fmt.Errorf(
			"failed decoding leaf mapped values: %w",
			err,
		)
	}

	n.internalMappedValues, err =
		decodeBigInts(
			snapshot.InternalMappedValues,
		)

	if err != nil {
		return nil, nil, fmt.Errorf(
			"failed decoding internal mapped values: %w",
			err,
		)
	}

	// ============================================================
	// NODE SRS
	// ============================================================

	if len(snapshot.NodeSRS) > 0 {

		n.nodeSRS, err =
			decodeSRS(
				snapshot.NodeSRS,
			)

		if err != nil {
			return nil, nil, fmt.Errorf(
				"failed decoding node SRS: %w",
				err,
			)
		}

		// Legacy compatibility:
		//
		// leaves previously also stored the same SRS through leafSRS.
		if n.isLeaf {
			n.leafSRS =
				n.nodeSRS
		}
	}

	// ============================================================
	// NODE COMMITMENT
	// ============================================================

	if len(snapshot.Commitment) > 0 {

		n.commitment, err =
			decodeDigest(
				snapshot.Commitment,
			)

		if err != nil {
			return nil, nil, fmt.Errorf(
				"failed decoding node commitment: %w",
				err,
			)
		}
	}

	// ============================================================
	// CHILD COMMITMENTS
	// ============================================================

	n.childCommitments =
		make(
			[]*kzg.Digest,
			len(snapshot.ChildCommitments),
		)

	for i, commitmentBytes := range snapshot.ChildCommitments {

		if len(commitmentBytes) == 0 {
			continue
		}

		commitment, err :=
			decodeDigest(
				commitmentBytes,
			)

		if err != nil {
			return nil, nil, fmt.Errorf(
				"failed decoding child commitment %d: %w",
				i,
				err,
			)
		}

		n.childCommitments[i] =
			commitment
	}

	// ============================================================
	// OPENING PROOFS
	// ============================================================

	n.openingProofs =
		make(
			[]kzg.OpeningProof,
			len(snapshot.OpeningProofs),
		)

	for i, proofBytes := range snapshot.OpeningProofs {

		proof, err :=
			decodeOpeningProof(
				proofBytes,
			)

		if err != nil {
			return nil, nil, fmt.Errorf(
				"failed decoding opening proof %d: %w",
				i,
				err,
			)
		}

		n.openingProofs[i] =
			*proof
	}

	// ============================================================
	// CHILDREN
	// ============================================================

	n.children =
		make(
			[]*node[K, V],
			len(snapshot.Children),
		)

	var leaves []*node[K, V]

	for i, childSnapshot := range snapshot.Children {

		child, childLeaves, err :=
			restoreNodeSnapshot[K, V](
				childSnapshot,
			)

		if err != nil {
			return nil, nil, fmt.Errorf(
				"failed restoring child %d: %w",
				i,
				err,
			)
		}

		n.children[i] =
			child

		leaves =
			append(
				leaves,
				childLeaves...,
			)
	}

	// A leaf has no child snapshots, so add itself to the
	// left-to-right leaf list.
	if n.isLeaf {

		if len(n.children) != 0 {
			return nil, nil, fmt.Errorf(
				"leaf contains %d children",
				len(n.children),
			)
		}

		leaves =
			append(
				leaves,
				n,
			)
	}

	return n, leaves, nil
}

// ============================================================
// BIG INTEGER SERIALIZATION
// ============================================================

func encodeBigInts(
	values []*big.Int,
) ([]string, error) {

	if values == nil {
		return nil, nil
	}

	result :=
		make(
			[]string,
			len(values),
		)

	for i, value := range values {

		if value == nil {
			return nil, fmt.Errorf(
				"nil big.Int at index %d",
				i,
			)
		}

		result[i] =
			value.String()
	}

	return result, nil
}

func decodeBigInts(
	values []string,
) ([]*big.Int, error) {

	if values == nil {
		return nil, nil
	}

	result :=
		make(
			[]*big.Int,
			len(values),
		)

	for i, value := range values {

		decoded, ok :=
			new(big.Int).SetString(
				value,
				10,
			)

		if !ok {
			return nil, fmt.Errorf(
				"invalid decimal big.Int at index %d",
				i,
			)
		}

		result[i] =
			decoded
	}

	return result, nil
}

// ============================================================
// KZG SRS SERIALIZATION
// ============================================================

func encodeSRS(
	srs *kzg.SRS,
) ([]byte, error) {

	if srs == nil {
		return nil, fmt.Errorf(
			"cannot encode nil SRS",
		)
	}

	var buffer bytes.Buffer

	if _, err :=
		srs.WriteTo(
			&buffer,
		); err != nil {

		return nil, fmt.Errorf(
			"SRS WriteTo failed: %w",
			err,
		)
	}

	return append(
		[]byte(nil),
		buffer.Bytes()...,
	), nil
}

func decodeSRS(
	data []byte,
) (*kzg.SRS, error) {

	if len(data) == 0 {
		return nil, fmt.Errorf(
			"cannot decode empty SRS",
		)
	}

	var result kzg.SRS

	if _, err :=
		result.ReadFrom(
			bytes.NewReader(
				data,
			),
		); err != nil {

		return nil, fmt.Errorf(
			"SRS ReadFrom failed: %w",
			err,
		)
	}

	return &result, nil
}

// ============================================================
// KZG COMMITMENT SERIALIZATION
// ============================================================
//
// kzg.Digest is an alias of BN254 G1Affine.
//
// Bytes() returns the canonical compressed representation.
// SetBytes() restores it and performs curve/subgroup checks.

func encodeDigest(
	digest *kzg.Digest,
) []byte {

	if digest == nil {
		return nil
	}

	compressed :=
		digest.Bytes()

	return append(
		[]byte(nil),
		compressed[:]...,
	)
}

func decodeDigest(
	data []byte,
) (*kzg.Digest, error) {

	if len(data) == 0 {
		return nil, fmt.Errorf(
			"cannot decode empty KZG digest",
		)
	}

	var digest kzg.Digest

	consumed, err :=
		digest.SetBytes(
			data,
		)

	if err != nil {
		return nil, fmt.Errorf(
			"digest SetBytes failed: %w",
			err,
		)
	}

	if consumed != len(data) {
		return nil, fmt.Errorf(
			"digest consumed %d bytes but snapshot contained %d",
			consumed,
			len(data),
		)
	}

	return &digest, nil
}

// ============================================================
// KZG OPENING-PROOF SERIALIZATION
// ============================================================

func encodeOpeningProof(
	proof *kzg.OpeningProof,
) ([]byte, error) {

	if proof == nil {
		return nil, fmt.Errorf(
			"cannot encode nil opening proof",
		)
	}

	var buffer bytes.Buffer

	if _, err :=
		proof.WriteTo(
			&buffer,
		); err != nil {

		return nil, fmt.Errorf(
			"opening proof WriteTo failed: %w",
			err,
		)
	}

	return append(
		[]byte(nil),
		buffer.Bytes()...,
	), nil
}

func decodeOpeningProof(
	data []byte,
) (*kzg.OpeningProof, error) {

	if len(data) == 0 {
		return nil, fmt.Errorf(
			"cannot decode empty opening proof",
		)
	}

	var proof kzg.OpeningProof

	if _, err :=
		proof.ReadFrom(
			bytes.NewReader(
				data,
			),
		); err != nil {

		return nil, fmt.Errorf(
			"opening proof ReadFrom failed: %w",
			err,
		)
	}

	return &proof, nil
}
