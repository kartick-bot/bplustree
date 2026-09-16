package bptree

// Entry represents the actual data stored in a B+ tree leaf.
//
// For our tree:
//
// Value = Hash(Key)
type Entry[K any] struct {
	Key   K
	Value [32]byte
}

// Hasher defines how a key is converted into its 32-byte value.
type Hasher[K any] func(key K) [32]byte