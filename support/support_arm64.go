//go:build arm64

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package support // import "github.com/toliu/opentelemetry-ebpf-profiler/support"

import (
	_ "embed"
)

//go:embed ebpf/tracer.ebpf.release.arm64
var tracerData []byte
