CC := cc
CFLAGS := -std=c11 -O2 -Wall -Wextra -Wpedantic -Iinclude
LDFLAGS :=

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

.PHONY: all clean run test bench-store corpus corpus-fetch corpus-local

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

corpus-fetch:
	./scripts/corpus_fetch.sh

corpus-local:
	./scripts/corpus_build_local.sh

corpus: corpus-fetch corpus-local

clean:
	rm -rf $(BUILD_DIR) $(TARGET)
