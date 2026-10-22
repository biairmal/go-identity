// Package clock is the time source services take instead of calling
// time.Now, so expiry logic can be tested without sleeping.
package clock

import "time"

// Clock tells the current time.
type Clock interface {
	Now() time.Time
}

// System is the real clock.
type System struct{}

// Now returns time.Now().
func (System) Now() time.Time { return time.Now() }
