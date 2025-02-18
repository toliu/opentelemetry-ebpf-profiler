//go:build arm64

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tpbase // import "github.com/toliu/opentelemetry-ebpf-profiler/tpbase"

func ExtractTSDInfoX64_64(_ []byte) (TSDInfo, error) {
	return TSDInfo{}, errArchNotImplemented
}

func ExtractTSDInfoNative(code []byte) (TSDInfo, error) {
	return ExtractTSDInfoARM64(code)
}
