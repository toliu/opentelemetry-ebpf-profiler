SHELL ?= bash
BPF_CLANG ?= clang-17
BPF_LINK ?= llvm-link-17
LLC ?= llc-17
CLANG_FORMAT ?= clang-format-17

DEBUG_FLAGS = -DOPTI_DEBUG -g

# Detect native architecture and translate to GOARCH.
NATIVE_ARCH := $(shell uname -m)
ifeq ($(NATIVE_ARCH),x86_64)
NATIVE_ARCH := amd64
else ifneq (,$(filter $(NATIVE_ARCH),aarch64 arm64))
NATIVE_ARCH := arm64
else
$(error Unsupported architecture: $(NATIVE_ARCH))
endif

# Valid values: amd64, arm64.
TARGET_ARCH ?= $(NATIVE_ARCH)

# Valid values: release, debug
BUILD_TYPE ?= release

TRACER_NAME ?= tracer.ebpf.$(BUILD_TYPE).$(TARGET_ARCH)

ifeq ($(TARGET_ARCH),arm64)
TARGET_FLAGS = -target aarch64-linux-gnu
else
TARGET_FLAGS = -target x86_64-linux-gnu
endif

ifeq ($(BUILD_TYPE),debug)
	TARGET_FLAGS+=$(DEBUG_FLAGS)
endif

# Resolve the path to the parca-dev/usdt eBPF headers via the Go module
# cache (honors any `replace` directive in go.mod). The headers
# (usdt_defs.h, usdt_args.h) live there as the single source of truth and
# are not duplicated in this repo.
#
# Lazy assignment (`=`, not `:=`): only computed when an actual compile
# rule expands FLAGS, so `clean`/`format`/`lint` don't trigger it. We
# `go mod download` first because `go list -m -f '{{.Dir}}'` does not
# auto-download a specific module path on a cold cache.
USDT_HEADERS = $(shell cd $(CURDIR)/../.. && \
	go mod download github.com/parca-dev/usdt >/dev/null && \
	go list -m -f '{{.Dir}}' github.com/parca-dev/usdt)/ebpf

FLAGS=$(TARGET_FLAGS) \
	-fno-jump-tables \
	-nostdlib \
	-nostdinc \
	-ffreestanding \
	-O2 -emit-llvm -c $< \
	-I$(USDT_HEADERS) \
	-Wall -Wextra -Werror \
	-Wno-address-of-packed-member \
	-Wno-unused-label \
	-Wno-unused-parameter \
	-Wno-sign-compare \
	-fno-stack-protector

SRCS := $(wildcard *.ebpf.c)
OBJS := $(SRCS:.c=.$(BUILD_TYPE).$(TARGET_ARCH).o)

.DEFAULT_GOAL := all

all: $(TRACER_NAME)

debug:
	$(MAKE) BUILD_TYPE=debug

amd64:
	$(MAKE) TARGET_ARCH=amd64

arm64:
	$(MAKE) TARGET_ARCH=arm64

debug-amd64:
	$(MAKE) BUILD_TYPE=debug TARGET_ARCH=amd64

debug-arm64:
	$(MAKE) BUILD_TYPE=debug TARGET_ARCH=arm64

errors.h: ../../tools/errors-codegen/errors.json
	go run ../../tools/errors-codegen/main.go bpf $@

%.ebpf.c: errors.h ;

%.ebpf.$(BUILD_TYPE).$(TARGET_ARCH).o: %.ebpf.c
	$(BPF_CLANG) $(FLAGS) -o $@

$(TRACER_NAME): $(OBJS)
	$(BPF_LINK) $^ -o - | $(LLC) -march=bpf -mcpu=v2 -filetype=obj -o $@
	@./print_instruction_count.sh $@

baseline: $(TRACER_NAME)
	cp $< $(TRACER_NAME).$@

bloatcheck: $(TRACER_NAME)
	python3 bloat-o-meter $(TRACER_NAME).baseline $(TRACER_NAME)

lint:
	$(CLANG_FORMAT) -Werror --dry-run -style=file *.[ch]

format:
	$(CLANG_FORMAT) -i -style=file *.[ch]

clean:
	rm -f *.o
