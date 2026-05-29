// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package util // import "go.opentelemetry.io/ebpf-profiler/util"

import (
	"math/bits"
	"strconv"
	"sync"
	"sync/atomic"
	"unicode"
	"unicode/utf8"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/libpf/hash"
)

// HexToUint64 is a convenience function to extract a hex string to a uint64 and
// not worry about errors. Essentially a "mustConvertHexToUint64".
func HexToUint64(str string) uint64 {
	v, err := strconv.ParseUint(str, 16, 64)
	if err != nil {
		logrus.Fatalf("Failure to hex-convert %s to uint64: %v", str, err)
	}
	return v
}

// DecToUint64 is a convenience function to extract a decimal string to a uint64
// and not worry about errors. Essentially a "mustConvertDecToUint64".
func DecToUint64(str string) uint64 {
	v, err := strconv.ParseUint(str, 10, 64)
	if err != nil {
		logrus.Fatalf("Failure to dec-convert %s to uint64: %v", str, err)
	}
	return v
}

// IsValidString checks if string is UTF-8-encoded and only contains expected characters.
func IsValidString(s string) bool {
	if s == "" {
		return false
	}
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// NextPowerOfTwo returns input value if it's a power of two,
// otherwise it returns the next power of two.
func NextPowerOfTwo(v uint32) uint32 {
	if v == 0 {
		return 1
	}
	return 1 << bits.Len32(v-1)
}

// AtomicUpdateMaxUint32 updates the value in store using atomic memory primitives. newValue will
// only be placed in store if newValue is larger than the current value in store.
// To avoid inconsistency parallel updates to store should be avoided.
func AtomicUpdateMaxUint32(store *atomic.Uint32, newValue uint32) {
	for {
		// Load the current value
		oldValue := store.Load()
		if newValue <= oldValue {
			// No update needed.
			break
		}
		if store.CompareAndSwap(oldValue, newValue) {
			// The value was atomically updated.
			break
		}
		// The value changed between load and update attempt.
		// Retry with the new value.
	}
}

// VersionUint returns a single integer composed of major, minor, patch.
func VersionUint(major, minor, patch uint32) uint32 {
	return (major << 16) + (minor << 8) + patch
}

// Range describes a range with Start and End values.
type Range struct {
	Start uint64
	End   uint64
}

// OnDiskFileIdentifier can be used as unique identifier for a file.
// It is a structure to identify a particular file on disk by
// deviceID and inode number.
type OnDiskFileIdentifier struct {
	DeviceID uint64 // dev_t as reported by stat.
	InodeNum uint64 // ino_t should fit into 64 bits
}

func (odfi OnDiskFileIdentifier) Hash32() uint32 {
	return uint32(hash.Uint64(odfi.InodeNum) + odfi.DeviceID)
}

// probeBpfGetAttachCookie tests if the kernel supports bpf_get_attach_cookie by attempting
// to load a minimal BPF program that uses it. This is more reliable than checking kernel
// versions since support can be backported.
var probeBpfGetAttachCookie = sync.OnceValue[bool](func() bool {
	// Create a minimal program that calls bpf_get_attach_cookie
	// This is equivalent to libbpf's probe_kern_bpf_cookie function
	insns := asm.Instructions{
		// Call bpf_get_attach_cookie() - BPF_FUNC_get_attach_cookie = 80
		asm.FnGetAttachCookie.Call(),
		// Exit
		asm.Return(),
	}

	spec := &ebpf.ProgramSpec{
		Type:         ebpf.TracePoint,
		Instructions: insns,
		License:      "GPL",
	}

	prog, err := ebpf.NewProgramWithOptions(spec, ebpf.ProgramOptions{
		LogDisabled: true,
	})
	if err != nil {
		return false
	}
	if err := prog.Close(); err != nil {
		logrus.Warnf("Failed to close test program: %v", err)
	}
	return true
})

// HasBpfGetAttachCookie checks if the kernel supports the bpf_get_attach_cookie helper.
// This function uses a cached, once-calculated value for performance.
//
// Note: This function requires CAP_BPF or CAP_SYS_ADMIN capabilities to load the probe
// program. The profiler should already have these privileges.
func HasBpfGetAttachCookie() bool { return probeBpfGetAttachCookie() }
