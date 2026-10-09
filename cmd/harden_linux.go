//go:build linux

package cmd

import (
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// hardenProcess makes usque non-dumpable: no core dumps, and other processes of the
// same user (on Android: anything else running as the app) can no longer ptrace it
// or read its memory through /proc/<pid>/mem, so the tunnel keys cannot be lifted
// from a running process without root. Covers Android too (GOOS=android implies
// the linux build tag).
func hardenProcess() {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0); errno != 0 {
		log.Printf("Warning: could not make the process non-dumpable: %v", errno)
	}
}

// tracerAttached reports whether a debugger or tracer (gdb, strace, frida) is
// attached to this process.
func tracerAttached() bool {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "TracerPid:"); ok {
			pid, err := strconv.Atoi(strings.TrimSpace(v))
			return err == nil && pid != 0
		}
	}
	return false
}
