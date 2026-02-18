CC := cc
CFLAGS := -std=c11 -O2 -Wall -Wextra -Wpedantic -MMD -MP -Iinclude
LDFLAGS :=

OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null)

ifneq ($(strip $(OPENSSL_LIBS)),)
CFLAGS += $(OPENSSL_CFLAGS) -DRAZE_HAVE_OPENSSL=1
LDFLAGS += $(OPENSSL_LIBS)
endif

TARGET := raze
BUILD_DIR := build
ISAL_DIR := third_party/isa-l
ISAL_LIB := $(ISAL_DIR)/bin/isa-l.a
ISAL_MAKEFILE := $(ISAL_DIR)/Makefile.unx

ifneq ($(wildcard $(ISAL_MAKEFILE)),)
CFLAGS += -I$(ISAL_DIR)/include -DRAZE_USE_ISAL=1
LDFLAGS += $(ISAL_LIB)
ISAL_PREREQ := $(ISAL_LIB)
endif

SRCS := $(shell find src -type f -name '*.c' | sort)
OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(SRCS))
DEPS := $(OBJS:.o=.d)

.PHONY: all clean run test bench-store bench-compressed bench-solid bench-split bench-encrypted corpus corpus-fetch corpus-local corpus-themed

all: $(TARGET)

$(TARGET): $(ISAL_PREREQ) $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

$(ISAL_LIB):
	$(MAKE) -C $(ISAL_DIR) -f Makefile.unx -j$$(nproc)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	./$(TARGET) --help

test: $(TARGET)
	./tests/run_tests.sh

bench-store: $(TARGET)
	./bench/bench_store.sh

bench-compressed: $(TARGET)
	./bench/bench_compressed.sh

bench-solid: $(TARGET)
	./bench/bench_solid.sh

bench-split: $(TARGET)
	./bench/bench_split.sh

bench-encrypted: $(TARGET)
	./bench/bench_encrypted.sh

corpus-fetch:
	./scripts/corpus_fetch.sh

corpus-local:
	./scripts/corpus_build_local.sh

corpus-themed:
	./scripts/corpus_build_thematic.sh

corpus: corpus-fetch corpus-local corpus-themed

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

-include $(DEPS)
