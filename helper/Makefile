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

# Feature-test macros, set ONCE here rather than per file.
#
# -std=c99 defines __STRICT_ANSI__, and glibc then hides every POSIX
# declaration behind a feature macro — so on Linux mkdtemp, setenv, symlink and
# friends become implicit declarations, which -Werror turns into a broken build.
# Per-file #define _GNU_SOURCE fixed the sources but was forgotten in the test
# files, which is exactly the failure mode a per-file convention invites.
#
# The macro has to differ by platform. On Darwin, defining _POSIX_C_SOURCE
# RESTRICTS the namespace instead of widening it: it hides flock, setgroups and
# O_NOFOLLOW, and makes <libproc.h> fail to compile. So the portable-looking
# choice would swap a Linux failure for a macOS one.
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  FEATURE = -D_DARWIN_C_SOURCE
else
  FEATURE = -D_GNU_SOURCE
endif
# Warnings are errors: this code will run as root, and "probably fine" is not a
# standard we can apply to it later by remembering to look.
WARN     = -Wall -Wextra -Werror -Wshadow -Wconversion -Wsign-conversion \
           -Wpointer-arith -Wwrite-strings -Wcast-qual -Wmissing-prototypes \
           -Wstrict-prototypes -Wold-style-definition -Wvla
HARDEN   = -D_FORTIFY_SOURCE=2 -fstack-protector-strong
OPT     ?= -O2
CFLAGS  += $(CSTD) $(FEATURE) $(WARN) $(HARDEN) $(OPT) -Iinclude -It

# Shared library sources: linked into the test binary AND into both privileged
# executables. One copy of the validation logic, so the helper and the admin tool
# cannot drift apart in what they consider acceptable.
SRC       = src/validate.c src/authparse.c src/policy.c src/request.c \
            src/state.c src/proc.c src/registry.c src/elf.c src/closure.c \
            src/exec.c
TEST_SRC  = t/main.c t/harness.c t/test_policy.c t/test_state.c t/test_registry.c \
            t/test_exec.c t/test_adversarial.c t/test_closure.c
TEST_BIN  = build/vu-test
ADMIN_BIN  = build/vpn-up-admin
HELPER_BIN = build/vpn-up-helper

SAN_FLAGS = $(CSTD) $(FEATURE) $(WARN) -g -O1 -fno-omit-frame-pointer -Iinclude -It

.PHONY: all test clean ubsan asan sanitize test-elf-closure

all: $(TEST_BIN) $(ADMIN_BIN) $(HELPER_BIN)

build:
	mkdir -p build

$(TEST_BIN): $(SRC) $(TEST_SRC) include/vu.h include/vu_state.h | build
	$(CC) $(CFLAGS) -o $@ $(SRC) $(TEST_SRC)

$(ADMIN_BIN): $(SRC) src/admin_main.c include/vu.h include/vu_state.h include/vu_registry.h | build
	$(CC) $(CFLAGS) -o $@ $(SRC) src/admin_main.c

$(HELPER_BIN): $(SRC) src/helper_main.c include/vu.h include/vu_state.h include/vu_registry.h include/vu_exec.h | build
	$(CC) $(CFLAGS) -o $@ $(SRC) src/helper_main.c

test: $(TEST_BIN) $(ADMIN_BIN) $(HELPER_BIN) test-elf-closure
	./$(TEST_BIN)
	# The admin tool must refuse to run without privilege, and must not need
	# privilege merely to report its own version.
	./$(ADMIN_BIN) version >/dev/null
	@if ./$(ADMIN_BIN) list >/dev/null 2>&1; then \
		echo "FAIL: vpn-up-admin list succeeded without root"; exit 1; \
	else echo "ok: vpn-up-admin refuses to run unprivileged"; fi
	@if ./$(ADMIN_BIN) >/dev/null 2>&1; then \
		echo "FAIL: vpn-up-admin with no command exited 0"; exit 1; \
	else echo "ok: vpn-up-admin with no command reports usage"; fi
	./$(HELPER_BIN) version >/dev/null
	@if ./$(HELPER_BIN) connect --profile-id x >/dev/null 2>&1; then \
		echo "FAIL: vpn-up-helper connect succeeded without root"; exit 1; \
	else echo "ok: vpn-up-helper refuses to connect unprivileged"; fi
	# Privilege separation (§5, §18). The passwordless binary must not be able to
	# grant approvals: a NOPASSWD binary that can approve endpoints is a NOPASSWD
	# binary that can approve anything.
	#
	# Checked at the SOURCE, not by running the commands, because an unprivileged
	# run cannot tell "refused: unknown command" from "refused: must be root" —
	# both exit non-zero. What matters is that no code path exists, and that is a
	# property of the file. This is the check that would catch someone adding a
	# convenient `vpn-up-helper approve` later.
	@for sym in vu_registry_put vu_registry_delete; do \
		if grep -q "$$sym" src/helper_main.c; then \
			echo "FAIL: helper_main.c calls $$sym — the NOPASSWD binary must never write the approval registry"; \
			exit 1; \
		fi; \
	done
	@echo "ok: vpn-up-helper cannot write the approval registry"
	@for cmd in approve revoke list; do \
		if ./$(HELPER_BIN) version | grep -qi "$$cmd"; then \
			echo "FAIL: vpn-up-helper advertises '$$cmd'"; exit 1; \
		fi; \
		if ./$(HELPER_BIN) $$cmd >/dev/null 2>&1; then \
			echo "FAIL: vpn-up-helper accepted '$$cmd'"; exit 1; \
		fi; \
	done
	@echo "ok: vpn-up-helper offers no approval subcommand"
	# The reverse direction: the admin tool must not establish tunnels.
	@for cmd in connect stop; do \
		if ./$(ADMIN_BIN) $$cmd >/dev/null 2>&1; then \
			echo "FAIL: vpn-up-admin accepted '$$cmd'"; exit 1; \
		fi; \
	done
	@echo "ok: vpn-up-admin offers no connect subcommand"

# The ELF/ld.so library closure is compiled in on Linux only, because macOS needs
# dyld and Mach-O instead (design step 13) and until then §11.7 requires helper
# mode to fail CLOSED there. That leaves a gap this target fills: on macOS the
# Linux-only branch would otherwise never be compiled or run before CI, which is
# where three of the four CI failures in steps 5-7 came from.
#
# Forcing it on is safe, and not merely convenient: with a REAL macOS install the
# ELF parse of a Mach-O binary reports "not an ELF binary" and the check still
# refuses. Only the synthetic ELF fixtures in t/test_closure.c get past it.
.PHONY: test-elf-closure
test-elf-closure: $(SRC) $(TEST_SRC) include/vu.h include/vu_state.h include/vu_closure.h | build
	$(CC) $(CFLAGS) -DVU_LIBRARY_CLOSURE_ELF=1 -o build/vu-test-elf $(SRC) $(TEST_SRC)
	./build/vu-test-elf

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
