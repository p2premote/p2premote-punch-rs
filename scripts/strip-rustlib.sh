#!/usr/bin/env bash
# Strip the rustlib prebuilt members out of a Rust static library.
#
# A rustc `staticlib` bundles the precompiled rlibs from the toolchain's
# rustlib directory: std, core, alloc, compiler_builtins, panic runtimes and
# std's own dependencies (memchr, libc, cfg_if, gimli, ...). When the .a is
# linked into a *Rust* host, the host already links those exact objects, and
# cargo's bundled-static-lib handling whole-archives the .a members, so the
# duplicate strong symbols (__RUST_STD_INTERNAL_VAL, __rust_alloc shim,
# compiler-rt intrinsics, memchr internals, ...) break the link with
# "multiple definition" errors.
#
# Removing those members makes the .a "std-external": its std references
# resolve against the host's own std (built from the same pinned toolchain).
# C hosts must link the unstripped archive (target/<triple>/release/...).
#
# Member naming inside the staticlib:
#   p2premote_punch-<h>.<crate>-<h>.<crate>.<h>[-cgu.N].rcgu.o[.rcgu.o]  deps
#   <crate>-<h>.<crate>.<h>-cgu.NNN.rcgu.o                              deps (no prefix)
#   p2premote_punch.<h>-cgu.NN.rcgu.o                                   the crate itself (keep)
#   p2premote_punch-<h>.<base36>.rcgu.o                                 allocator shim (strip)
#   <h>-<fn>.o                                                          raw C/asm objects
#
# Primary rule: any member whose "<crate>-<hash>" prefix matches a file in
# the target's rustlib dir (exact hash match — crates the punch build itself
# compiled carry different hashes and are kept). Fallback name-based rules
# cover the well-known rustlib set when no rustlib dir is given. Raw objects
# are kept only when they are ring's (globals carry the ring_core_ prefix);
# compiler-rt objects from libcompiler_builtins expose bare __-symbols and go.
#
# Usage: strip-rustlib.sh <archive.a> [rust-target-triple]
set -euo pipefail

ARCHIVE="${1:?usage: strip-rustlib.sh <archive.a> [rust-target-triple]}"
STRIP_TARGET="${2:-}"

RUSTLIB_CRATES='std|core|alloc|panic_unwind|panic_abort|compiler_builtins|unwind|std_detect|hashbrown|gimli|addr2line|miniz_oxide|rustc_demangle|adler2|adler|object|rustc_std_workspace_alloc|rustc_std_workspace_core|test|proc_macro'

BEFORE=$(ar t "$ARCHIVE" | wc -l)

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
KEEP="$WORKDIR/keep"
mkdir -p "$KEEP"
ar t "$ARCHIVE" > "$WORKDIR/members.txt"
(cd "$KEEP" && ar x "$ARCHIVE")

{
    # primary rule: exact <crate>-<hash> match against the rustlib dir
    if [ -n "$STRIP_TARGET" ] && command -v rustc >/dev/null 2>&1; then
        RUSTLIB_DIR=$(rustc --print target-libdir --target "$STRIP_TARGET" 2>/dev/null || true)
        if [ -n "$RUSTLIB_DIR" ] && [ -d "$RUSTLIB_DIR" ]; then
            for rlib in "$RUSTLIB_DIR"/lib*-*.rlib; do
                [ -e "$rlib" ] || continue
                base=$(basename "$rlib" .rlib)
                base=${base#lib}
                grep -E "^(p2premote_punch-[0-9a-f]+[.])?${base}[.]" "$WORKDIR/members.txt" || true
            done
        fi
    fi
    # fallback: rustlib crate names, with or without the punch-crate prefix
    grep -E "^p2premote_punch-[0-9a-f]+[.](${RUSTLIB_CRATES})-[0-9a-f]+[.]" "$WORKDIR/members.txt" || true
    grep -E "^(${RUSTLIB_CRATES})-[0-9a-f]+[.]" "$WORKDIR/members.txt" || true
    # the allocator shim (__rust_alloc etc.): no crate-name component; the
    # disambiguator is base-36-ish, not hex
    grep -E "^p2premote_punch-[0-9a-f]+[.][0-9a-z]+[.]rcgu[.]o$" "$WORKDIR/members.txt" || true
    # all raw C/asm objects go: compiler-rt intrinsics are provided by the
    # host's compiler_builtins, and ring's C symbols (ring_core_ prefix, same
    # crate version on both sides) are provided by the host's own ring rlib.
    # NB: never contain "rcgu" — "aead" is all-hex and would otherwise match.
    grep -E "^[0-9a-f]+-[A-Za-z0-9_.-]+[.]o$" "$WORKDIR/members.txt" | grep -v rcgu || true
} | sort -u > "$WORKDIR/remove.txt"

if [ ! -s "$WORKDIR/remove.txt" ]; then
    echo "strip-rustlib: nothing to strip (already stripped?)" >&2
    exit 0
fi

while read -r member; do
    rm -f "$KEEP/$member"
done < "$WORKDIR/remove.txt"

NEW="$WORKDIR/rebuilt.a"
(cd "$KEEP" && ar rcs "$NEW" ./*.o)
mv "$NEW" "$ARCHIVE"

AFTER=$(ar t "$ARCHIVE" | wc -l)
echo "strip-rustlib: removed $((BEFORE - AFTER)) of $BEFORE members from $ARCHIVE"
