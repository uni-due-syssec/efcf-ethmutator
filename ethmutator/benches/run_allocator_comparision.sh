#!/usr/bin/env bash

set -e

CARGO=cargo
if command -v rustup >/dev/null; then
    CARGO="rustup run nightly cargo"
fi

cat /proc/cpuinfo | grep "model name" | head -n 1
cat /proc/cpuinfo | grep "MHz" | head -n 1

(/lib64/libc.so.6 || /lib/libc.so.6 || /usr/lib/libc.so.6) | head -n 1

export RUST_BACKTRACE=1
export RUSTFLAGS="-A warnings"

echo ""
echo "### Default Allocator"
echo ""
echo '```'
$CARGO bench --quiet -p ethmutator --no-default-features
echo '```'
echo ""
echo "### jemalloc"
echo ""
echo '```'
$CARGO bench --quiet -p ethmutator --no-default-features --features use_jemalloc
echo '```'
echo ""
echo "### mimalloc"
echo ""
echo '```'
$CARGO bench --quiet -p ethmutator --no-default-features --features use_mimalloc
echo '```'
echo ""
echo "### snmalloc"
echo ""
echo '```'
$CARGO bench --quiet -p ethmutator --no-default-features --features use_snmalloc
echo '```'
echo ""

echo "### malloc stats"
echo ""
echo '```'
echo 'export MIMALLOC_SHOW_STATS=1'
export MIMALLOC_SHOW_STATS=1
$CARGO bench --quiet -p ethmutator --no-default-features --features use_mimalloc >/dev/null
echo '```'
echo ""
