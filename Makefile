BINARY  := ferrite
VERSION := $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
DIST    := dist

TARGET_MAC_ARM64   := aarch64-apple-darwin
TARGET_MAC_X86_64  := x86_64-apple-darwin
TARGET_LINUX_ARM64  := aarch64-unknown-linux-musl
TARGET_LINUX_X86_64 := x86_64-unknown-linux-musl

.PHONY: all mac mac-arm64 mac-x86_64 linux linux-arm64 linux-x86_64 setup clean dist-clean help

all: mac linux

# ── macOS ─────────────────────────────────────────────────────────────────────

mac: mac-arm64 mac-x86_64

mac-arm64: $(DIST)
	cargo build --release --target $(TARGET_MAC_ARM64)
	cp target/$(TARGET_MAC_ARM64)/release/$(BINARY) \
	   $(DIST)/$(BINARY)-$(VERSION)-macos-arm64

mac-x86_64: $(DIST)
	cargo build --release --target $(TARGET_MAC_X86_64)
	cp target/$(TARGET_MAC_X86_64)/release/$(BINARY) \
	   $(DIST)/$(BINARY)-$(VERSION)-macos-x86_64

# ── Linux (musl, static) ──────────────────────────────────────────────────────
# Requires cargo-zigbuild + zig (no Docker needed, works natively on Apple Silicon).
# Install once: cargo install cargo-zigbuild && brew install zig
#
# `ulimit -n` is raised per recipe: the static musl link opens ~200 .rlib files at
# once and the macOS default soft limit (256) makes the linker fail with
# `ProcessFdQuotaExceeded`. 65536 is well under kern.maxfilesperproc.

define check-zigbuild
	@command -v cargo-zigbuild >/dev/null 2>&1 || { \
		echo "Error: cargo-zigbuild not installed."; \
		echo "Run: cargo install cargo-zigbuild && brew install zig"; \
		exit 1; \
	}
endef

linux: linux-arm64 linux-x86_64

linux-arm64: $(DIST)
	$(check-zigbuild)
	ulimit -n 65536; cargo zigbuild --release --target $(TARGET_LINUX_ARM64)
	cp target/$(TARGET_LINUX_ARM64)/release/$(BINARY) \
	   $(DIST)/$(BINARY)-$(VERSION)-linux-arm64

linux-x86_64: $(DIST)
	$(check-zigbuild)
	ulimit -n 65536; cargo zigbuild --release --target $(TARGET_LINUX_X86_64)
	cp target/$(TARGET_LINUX_X86_64)/release/$(BINARY) \
	   $(DIST)/$(BINARY)-$(VERSION)-linux-x86_64

# ── Utility ───────────────────────────────────────────────────────────────────

$(DIST):
	mkdir -p $@

setup:
	rustup target add \
		$(TARGET_MAC_ARM64) $(TARGET_MAC_X86_64) \
		$(TARGET_LINUX_ARM64) $(TARGET_LINUX_X86_64)

clean:
	cargo clean

dist-clean:
	rm -rf $(DIST)

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@printf "  %-18s %s\n" "all"          "mac + linux"
	@printf "  %-18s %s\n" "mac"          "macOS arm64 + x86_64"
	@printf "  %-18s %s\n" "mac-arm64"    "Apple Silicon (M1/M2/M3)"
	@printf "  %-18s %s\n" "mac-x86_64"   "Intel Mac"
	@printf "  %-18s %s\n" "linux"        "Linux arm64 + x86_64 (musl, static)"
	@printf "  %-18s %s\n" "linux-arm64"  "Linux aarch64-musl (via cargo-zigbuild)"
	@printf "  %-18s %s\n" "linux-x86_64" "Linux x86_64-musl  (via cargo-zigbuild)"
	@printf "  %-18s %s\n" "setup"        "rustup target add (run once)"
	@printf "  %-18s %s\n" "clean"        "cargo clean"
	@printf "  %-18s %s\n" "dist-clean"   "rm -rf dist/"
	@echo ""
	@echo "First-time setup:"
	@echo "  make setup                   # add rustup targets"
	@echo "  brew install zig             # zig cross-linker"
	@echo "  cargo install cargo-zigbuild # musl/cross linking (no Docker needed)"
