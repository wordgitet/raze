CC ?= cc
TARGET ?= raze
BUILD_DIR ?= build
USE_ISAL ?= 1
SANITIZE ?=
RUN_SECS ?= 30
SOAK_SECS ?= 300
CI_LOCAL_EXPANDED ?= 0
ENABLE_LTO ?= 1
PGO_PROFILE_DIR ?= $(BUILD_DIR)/pgo-profile
PGO_TRAIN_RUNS ?= 3

BASE_CFLAGS := -std=c11 -O3 -fno-semantic-interposition \
	-Wall -Wextra -Wpedantic -MMD -MP -Iinclude
BASE_LDFLAGS :=
ifeq ($(strip $(SANITIZE)),)
ifneq ($(ENABLE_LTO),0)
BASE_CFLAGS += -flto
BASE_LDFLAGS += -flto
endif
endif
CFLAGS := $(BASE_CFLAGS) $(EXTRA_CFLAGS)
LDFLAGS := $(BASE_LDFLAGS) $(EXTRA_LDFLAGS)

OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null)

ifneq ($(strip $(OPENSSL_LIBS)),)
CFLAGS += $(OPENSSL_CFLAGS) -DRAZE_HAVE_OPENSSL=1
LDFLAGS += $(OPENSSL_LIBS)
endif

ifneq ($(strip $(SANITIZE)),)
SAN_FLAGS := -fsanitize=$(SANITIZE) -fno-omit-frame-pointer -O1 -g3
CFLAGS += $(SAN_FLAGS)
LDFLAGS += $(SAN_FLAGS)
endif

TEST_EXTRA_CFLAGS := $(EXTRA_CFLAGS) $(SAN_FLAGS)
TEST_EXTRA_LDFLAGS := $(EXTRA_LDFLAGS) $(SAN_FLAGS)

ISAL_DIR := third_party/isa-l
ISAL_LIB := $(ISAL_DIR)/bin/isa-l.a
ISAL_MAKEFILE := $(ISAL_DIR)/Makefile.unx

ifneq ($(USE_ISAL),0)
ifneq ($(wildcard $(ISAL_MAKEFILE)),)
CFLAGS += -I$(ISAL_DIR)/include -DRAZE_USE_ISAL=1
LDFLAGS += $(ISAL_LIB)
ISAL_PREREQ := $(ISAL_LIB)
endif
endif

FUZZ_CC ?= clang
FUZZ_BUILD_DIR ?= $(BUILD_DIR)/fuzz
FUZZ_SAN_FLAGS ?= -fsanitize=fuzzer,address,undefined
FUZZ_CFLAGS := -std=c11 -O1 -g3 -Wall -Wextra -Wpedantic -Iinclude $(EXTRA_CFLAGS) $(FUZZ_SAN_FLAGS)
FUZZ_LDFLAGS := $(EXTRA_LDFLAGS) $(FUZZ_SAN_FLAGS)

ifneq ($(USE_ISAL),0)
ifneq ($(wildcard $(ISAL_MAKEFILE)),)
FUZZ_CFLAGS += -I$(ISAL_DIR)/include -DRAZE_USE_ISAL=1
FUZZ_LDFLAGS += $(ISAL_LIB)
FUZZ_ISAL_PREREQ := $(ISAL_LIB)
endif
endif

FUZZ_TARGETS := \
	$(FUZZ_BUILD_DIR)/fuzz_vint \
	$(FUZZ_BUILD_DIR)/fuzz_block_reader \
	$(FUZZ_BUILD_DIR)/fuzz_file_header \
	$(FUZZ_BUILD_DIR)/fuzz_unpack_v50

SRCS := $(shell find src -type f -name '*.c' | sort)
OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(SRCS))
DEPS := $(OBJS:.o=.d)

.PHONY: all clean run deps deps-isa-l check-isal test test-expanded ci-local test-parser-units test-asan-ubsan fuzz-build fuzz-smoke fuzz-soak bench-store bench-compressed bench-solid bench-hot-solid bench-split bench-encrypted bench-expanded bench-external pgo-train pgo-build corpus corpus-fetch corpus-local corpus-themed corpus-expanded

all: check-isal $(TARGET)

deps: deps-isa-l

deps-isa-l:
	git submodule sync -- third_party/isa-l
	git submodule update --init --recursive third_party/isa-l

check-isal:
ifneq ($(USE_ISAL),0)
ifeq ($(wildcard $(ISAL_MAKEFILE)),)
	@echo "raze: ISA-L submodule is not initialized." >&2
	@echo "raze: run 'make deps' or build with 'make USE_ISAL=0'." >&2
	@exit 2
endif
endif

$(TARGET): check-isal $(ISAL_PREREQ) $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

$(ISAL_LIB):
	$(MAKE) -C $(ISAL_DIR) -f Makefile.unx -j$$(nproc)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	./$(TARGET) --help

test: $(TARGET)
	CC="$(CC)" \
	EXTRA_CFLAGS="$(TEST_EXTRA_CFLAGS)" \
	EXTRA_LDFLAGS="$(TEST_EXTRA_LDFLAGS)" \
	./tests/run_tests.sh

test-expanded: $(TARGET)
	CC="$(CC)" \
	EXTRA_CFLAGS="$(TEST_EXTRA_CFLAGS)" \
	EXTRA_LDFLAGS="$(TEST_EXTRA_LDFLAGS)" \
	./tests/run_tests_expanded.sh

ci-local: $(TARGET)
	$(MAKE) test </dev/null
ifneq ($(CI_LOCAL_EXPANDED),0)
	$(MAKE) test-expanded </dev/null
endif
	$(MAKE) test-asan-ubsan USE_ISAL=0
	$(MAKE) fuzz-build USE_ISAL=0
	$(MAKE) fuzz-smoke USE_ISAL=0 RUN_SECS=$(RUN_SECS)

test-parser-units:
	./tests/test_parser_units.sh

test-asan-ubsan:
	$(MAKE) clean
	@if command -v rar >/dev/null 2>&1; then \
		ASAN_OPTIONS=detect_leaks=0 \
		$(MAKE) USE_ISAL=0 SANITIZE=address,undefined test; \
	else \
		ASAN_OPTIONS=detect_leaks=0 \
		$(MAKE) USE_ISAL=0 SANITIZE=address,undefined test-parser-units; \
	fi
	$(MAKE) clean

fuzz-build: $(FUZZ_ISAL_PREREQ) $(FUZZ_TARGETS)

fuzz-smoke: fuzz-build
	./tests/fuzz/run_fuzz_smoke.sh "$(FUZZ_BUILD_DIR)" "$(RUN_SECS)"

fuzz-soak: fuzz-build
	./tests/fuzz/run_fuzz_soak.sh "$(FUZZ_BUILD_DIR)" "$(SOAK_SECS)"

bench-store: $(TARGET)
	./bench/bench_store.sh

bench-compressed: $(TARGET)
	./bench/bench_compressed.sh

bench-solid: $(TARGET)
	./bench/bench_solid.sh

bench-hot-solid: $(TARGET)
	./bench/bench_hot_solid.sh

bench-split: $(TARGET)
	./bench/bench_split.sh

bench-encrypted: $(TARGET)
	./bench/bench_encrypted.sh

bench-expanded: $(TARGET)
	./bench/bench_expanded.sh

bench-external: $(TARGET)
	./bench/bench_external.sh

pgo-train:
	rm -rf "$(PGO_PROFILE_DIR)"
	$(MAKE) clean
	$(MAKE) ENABLE_LTO=0 \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS) -fprofile-generate=$(PGO_PROFILE_DIR)" \
		EXTRA_LDFLAGS="$(EXTRA_LDFLAGS) -fprofile-generate=$(PGO_PROFILE_DIR)"
	@mkdir -p "$(PGO_PROFILE_DIR)"
	@./scripts/corpus_fetch.sh >/dev/null
	@./scripts/corpus_build_local.sh >/dev/null
	@if [ ! -f corpus/local/external/archives/enwik8_solid.rar ]; then \
		if command -v rar >/dev/null 2>&1; then \
			mkdir -p corpus/local/external/archives; \
			( cd corpus/upstream/enwik8 && \
			  rar a -idq -ma5 -m5 -s \
			  "$(CURDIR)/corpus/local/external/archives/enwik8_solid.rar" . ); \
		else \
			echo "pgo-train: enwik8_solid.rar missing and rar not found; skipping enwik8 training"; \
		fi; \
	fi
	@if [ -f corpus/local/external/archives/enwik8_solid.rar ]; then \
		for _ in $$(seq 1 "$(PGO_TRAIN_RUNS)"); do \
			rm -rf build/pgo_train_enwik8; \
			./raze x -idq -o+ -opbuild/pgo_train_enwik8 \
				corpus/local/external/archives/enwik8_solid.rar >/dev/null; \
		done; \
	fi
	@for _ in $$(seq 1 "$(PGO_TRAIN_RUNS)"); do \
		rm -rf build/pgo_train_fast; \
		./raze x -idq -o+ -opbuild/pgo_train_fast \
			corpus/local/archives/local_fast.rar >/dev/null; \
	done
	@echo "pgo-train: profile data generated in $(PGO_PROFILE_DIR)"

pgo-build:
	$(MAKE) clean
	$(MAKE) ENABLE_LTO=0 \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS) -fprofile-use=$(PGO_PROFILE_DIR) -fprofile-correction -Wno-missing-profile" \
		EXTRA_LDFLAGS="$(EXTRA_LDFLAGS) -fprofile-use=$(PGO_PROFILE_DIR)"

corpus-fetch:
	./scripts/corpus_fetch.sh

corpus-local:
	./scripts/corpus_build_local.sh

corpus-themed:
	./scripts/corpus_build_thematic.sh

corpus-expanded:
	./scripts/corpus_build_expanded.sh

corpus: corpus-fetch corpus-local corpus-themed

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

$(FUZZ_BUILD_DIR):
	@mkdir -p $@

$(FUZZ_BUILD_DIR)/fuzz_vint: tests/fuzz/fuzz_vint.c src/format/rar5/vint.c | $(FUZZ_BUILD_DIR)
	$(FUZZ_CC) $(FUZZ_CFLAGS) $^ -o $@ $(FUZZ_LDFLAGS)

$(FUZZ_BUILD_DIR)/fuzz_block_reader: tests/fuzz/fuzz_block_reader.c src/format/rar5/block_reader.c src/format/rar5/vint.c src/checksum/crc32.c | $(FUZZ_BUILD_DIR)
	$(FUZZ_CC) $(FUZZ_CFLAGS) $^ -o $@ $(FUZZ_LDFLAGS)

$(FUZZ_BUILD_DIR)/fuzz_file_header: tests/fuzz/fuzz_file_header.c src/format/rar5/file_header.c src/format/rar5/vint.c | $(FUZZ_BUILD_DIR)
	$(FUZZ_CC) $(FUZZ_CFLAGS) $^ -o $@ $(FUZZ_LDFLAGS)

$(FUZZ_BUILD_DIR)/fuzz_unpack_v50: tests/fuzz/fuzz_unpack_v50.c src/decode/rar5/unpack_v50.c src/decode/rar5/bit_reader.c src/decode/rar5/huff.c src/decode/rar5/filter.c src/decode/rar5/window.c src/decode/rar5/copy_kernels.c src/platform/cpu_features.c | $(FUZZ_BUILD_DIR)
	$(FUZZ_CC) $(FUZZ_CFLAGS) $^ -o $@ $(FUZZ_LDFLAGS)

-include $(DEPS)
