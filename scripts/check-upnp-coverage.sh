#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
report_dir="${UPNP_COVERAGE_DIR:-target/upnp-coverage}"
mkdir -p "$report_dir"

# Branch instrumentation is unstable in Rust 1.94.1. This opt-in is restricted
# to the coverage process; release builds and persistent toolchain settings are
# unaffected. A compatible nightly may be selected with UPNP_TEST_TOOLCHAIN.
RUSTC_BOOTSTRAP=1 cargo +"${UPNP_TEST_TOOLCHAIN:-1.94.1}" llvm-cov test \
    --branch --lib --no-default-features --features port-mapping --locked --offline \
    --ignore-filename-regex '(_tests\.rs|coverage_tests\.rs)' \
    --json --output-path "$report_dir/coverage.json" -- portmap
python scripts/check_upnp_coverage.py "$report_dir/coverage.json" "$report_dir/summary.json"
cargo +"${UPNP_TEST_TOOLCHAIN:-1.94.1}" test --lib --no-default-features --locked --offline portmap
