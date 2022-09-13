// Package lwotg implements a lightweight, extensible OpenTrafficGenerator
// (github.com/open-traffic-generator) implementation. OpenTrafficGenerator is
// often abbreviated to OTG.
package lwotg

// Hint is <group, key, value> tuple that can be handed to modules of the
// OTG implementation to perform their functions. For example, it may be
// used to communicate mappings between system interfaces and the names that
// are used in OTG for them.
type Hint struct {
	// Group is a string used to specify a name for a set of hints that
	// are associated with one another.
	Group string
	// Key is the name of the hint.
	Key string
	// Value is the value stored for the hint.
	Value string
}
