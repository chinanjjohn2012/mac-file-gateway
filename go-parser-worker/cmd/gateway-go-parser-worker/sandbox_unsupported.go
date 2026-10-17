//go:build !darwin || !cgo

package main

import "errors"

// Non-Darwin and Darwin without cgo must never advertise a sandbox.
func initializeSandbox() error { return errors.New("sandbox_unavailable") }
