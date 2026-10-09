//go:build !linux

package cmd

// hardenProcess is a no-op off Linux/Android; see harden_linux.go.
func hardenProcess() {}

// tracerAttached is not checked off Linux/Android.
func tracerAttached() bool { return false }
