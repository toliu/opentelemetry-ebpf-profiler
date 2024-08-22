/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package readatbuf_test

import (
	"bytes"
	"testing"

	"github.com/toliu/opentelemetry-ebpf-profiler/libpf/readatbuf"
	"github.com/toliu/opentelemetry-ebpf-profiler/testsupport"
	"github.com/stretchr/testify/require"
)

func testVariant(t *testing.T, fileSize, granularity, cacheSize uint) {
	file := testsupport.GenerateTestInputFile(255, fileSize)
	rawReader := bytes.NewReader(file)
	cachingReader, err := readatbuf.New(rawReader, granularity, cacheSize)
	require.NoError(t, err)
	testsupport.ValidateReadAtWrapperTransparency(t, 10000, file, cachingReader)
}

func TestCaching(t *testing.T) {
	testVariant(t, 1024, 64, 1)
	testVariant(t, 1346, 11, 55)
	testVariant(t, 889, 34, 111)
}
