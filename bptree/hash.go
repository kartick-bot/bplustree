package bptree

import (
	"crypto/sha256"
	"encoding/binary"
)

// HashInt computes SHA-256 over a canonical 8-byte
// representation of an integer key.
func HashInt(key int) [32]byte {
	var buf [8]byte

	binary.BigEndian.PutUint64(
		buf[:],
		uint64(key),
	)

	return sha256.Sum256(buf[:])
}