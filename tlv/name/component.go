package name

import (
	"bytes"
)
// name Component is a string
type Component struct {
	Value string
}

//converts a slice of bytes to a string and returns a component with that value
func ComponentFromBytes(b []byte) Component {
	return Component{
		Value: string(b),
	}
}

//converts a component to a slice of bytes
func (c Component) ComponentToBytes() []byte {
	return []byte(c.Value)
}

//returns a Component with the given value in s
func ComponentFromString(s string) Component {
	return Component{
		Value: s,
	}
}

//returns the value stored in the component c
func (c Component) GetValue() string {
	return c.Value
}

// copies the caller's value into a new component and returns it
func (c Component) Copy() Component {
	return Component{
		Value: c.Value,
	}
}

//Compares 2 components and returns (0: if equal, -1: if c < other, and +1: if c > other)
func (c Component) Compare(other Component) int {
	return bytes.Compare([]byte(c.Value), []byte(other.Value))
}

// returns a boolean instead of an integer
func (c Component) Equals(other Component) bool {
	return c.Value == other.Value
}
