#!/bin/sh
# ==============================================================================
# Script Name:   run.sh
# Description:   Universal cross-platform launcher for netlog.
# Author:        Mai Tan Duc <ducmai.network@gmail.com>
# Created:       2026-10-23
# Version:       1.0.0
# License:       MIT
# ==============================================================================
# Usage:         ./scripts/run.sh [options] [arguments]
# Notes:         Auto-detects OS & architecture and executes the appropriate binary.
# ==============================================================================
set -e

OS=""
ARCH=""

case "$(uname -s)" in
    Linux*)               OS="linux";;
    Darwin*)              OS="darwin";;
    CYGWIN*|MINGW*|MSYS*) OS="windows";;
    *)                    echo "Error: Unsupported OS $(uname -s)"; exit 1;;
esac

case "$(uname -m)" in
    x86_64|amd64)         ARCH="amd64";;
    arm64|aarch64)        ARCH="arm64";;
    *)                    echo "Error: Unsupported Architecture $(uname -m)"; exit 1;;
esac

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

BINARY="$ROOT_DIR/bin/netlog"
[ "$OS" = "windows" ] && BINARY="$ROOT_DIR/bin/netlog.exe"

ARCH_BINARY="$ROOT_DIR/bin/netlog-${OS}-${ARCH}"
[ "$OS" = "windows" ] && ARCH_BINARY="${ARCH_BINARY}.exe"

ROOT_BIN="$ROOT_DIR/netlog"
[ "$OS" = "windows" ] && ROOT_BIN="$ROOT_DIR/netlog.exe"

ROOT_ARCH_BIN="$ROOT_DIR/netlog-${OS}-${ARCH}"
[ "$OS" = "windows" ] && ROOT_ARCH_BIN="${ROOT_ARCH_BIN}.exe"

if [ -f "$BINARY" ]; then
    :
elif [ -f "$ARCH_BINARY" ]; then
    BINARY="$ARCH_BINARY"
elif [ -f "$ROOT_BIN" ]; then
    BINARY="$ROOT_BIN"
elif [ -f "$ROOT_ARCH_BIN" ]; then
    BINARY="$ROOT_ARCH_BIN"
else
    echo "Binary $BINARY not found. Building..."

    if ! command -v go >/dev/null 2>&1; then
        echo "Error: 'go' is not installed but is required to build the binary."
        echo "Please install Go or download a pre-built release binary."
        exit 1
    fi

    if [ ! -d "$ROOT_DIR/vendor" ]; then
        echo "Checking and installing required dependencies..."
        (cd "$ROOT_DIR" && go mod tidy && go mod vendor)
    fi

    if command -v make >/dev/null 2>&1; then
        (cd "$ROOT_DIR" && make build)
        BINARY="$ROOT_DIR/bin/netlog"
    else
        echo "make is unavailable, building directly with go..."
        (cd "$ROOT_DIR" && CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags '-s -w' -o bin/netlog ./cmd/netlog)
        BINARY="$ROOT_DIR/bin/netlog"
    fi
fi

# If no arguments are passed, default to 'collect'.
# If the first argument is --dry-run / -dry-run (without a subcommand),
# prepend 'collect' so "./run --dry-run" works like the other shorthands.
if [ $# -eq 0 ]; then
    set -- collect
elif [ "$1" = "--dry-run" ] || [ "$1" = "-dry-run" ]; then
    set -- collect "$@"
fi

exec "$BINARY" "$@"
