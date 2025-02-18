//go:build !arm64

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "github.com/toliu/opentelemetry-ebpf-profiler/processmanager"

var createVDSOSyntheticRecord = createVDSOSyntheticRecordNone
