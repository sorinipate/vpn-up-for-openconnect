# Build for the VPN Up privileged-helper policy engine.
#
# Step 4 of PRIVILEGED-HELPER-DESIGN.md §16: the policy engine only. There is
# no privileged code here yet — nothing calls execve, setuid, or touches a
# root-owned path — so this builds and runs as an ordinary user.
#
# How the shipped binaries are built and distributed is still open (§17.2:
# compile at install time vs prebuilt per-architecture artefacts). This Makefile
# deliberately assumes nothing about that: plain C99, no external dependencies,
# no install target yet.

CC      ?= cc
CSTD    ?= -std=c99
# Warnings are errors: this code will run as root, and "probably fine" is not a
# standard we can apply to it later by remembering to look.
WARN     = -Wall -Wextra -Werror -Wshadow -Wconversion -Wsign-conversion \
           -Wpointer-arith -Wwrite-strings -Wcast-qual -Wmissing-prototypes \
           -Wstrict-prototypes -Wold-style-definition -Wvla
HARDEN   = -D_FORTIFY_SOURCE=2 -fstack-protector-strong
OPT     ?= -O2
CFLAGS  += $(CSTD) $(WARN) $(HARDEN) $(OPT) -Iinclude -It

SRC      = src/validate.c src/authparse.c src/policy.c src/state.c src/proc.c
TEST_SRC = t/main.c t/harness.c t/test_policy.c t/test_state.c
TEST_BIN = build/vu-test

SAN_FLAGS = $(CSTD) $(WARN) -g -O1 -fno-omit-frame-pointer -Iinclude -It

.PHONY: all test clean ubsan asan sanitize

all: $(TEST_BIN)

build:
	mkdir -p build

$(TEST_BIN): $(SRC) $(TEST_SRC) include/vu.h include/vu_state.h | build
	$(CC) $(CFLAGS) -o $@ $(SRC) $(TEST_SRC)

test: $(TEST_BIN)
	./$(TEST_BIN)

# The corpus is mostly malformed input, which is exactly where a buffer or
# overflow bug would hide, so the sanitizer runs matter more here than usual.
#
# ubsan and asan are separate targets on purpose. On macOS 26 the AddressSanitizer
# runtime spins forever inside its own initialiser — a stack sample shows it stuck
# in __asan::AsanInitFromRtl() under __malloc_init, before main() is ever reached —
# so `make asan` cannot run there. UndefinedBehaviorSanitizer does not intercept
# malloc and works on both platforms. CI therefore runs ubsan everywhere and asan
# on Linux only; do not read a macOS asan hang as a finding in this code.
ubsan: $(SRC) $(TEST_SRC) include/vu.h include/vu_state.h | build
	$(CC) $(SAN_FLAGS) -fsanitize=undefined -o build/vu-test-ubsan $(SRC) $(TEST_SRC)
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ./build/vu-test-ubsan

asan: $(SRC) $(TEST_SRC) include/vu.h include/vu_state.h | build
	$(CC) $(SAN_FLAGS) -fsanitize=address -o build/vu-test-asan $(SRC) $(TEST_SRC)
	ASAN_OPTIONS=detect_leaks=1 ./build/vu-test-asan

sanitize: ubsan asan

clean:
	rm -rf build
