#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

missing=()
command -v cmake >/dev/null || missing+=(cmake)
command -v g++ >/dev/null || missing+=(g++)
pkg-config --exists Qt6Widgets 2>/dev/null || missing+=(Qt6Widgets)
pkg-config --exists yaml-cpp 2>/dev/null || missing+=(yaml-cpp)

if ((${#missing[@]})); then
  echo "Missing build deps: ${missing[*]}"
  echo "Fedora: sudo dnf install cmake gcc-c++ qt6-qtbase-devel openssl-devel yaml-cpp-devel"
  echo "Debian: sudo apt install cmake g++ qt6-base-dev libssl-dev libyaml-cpp-dev nlohmann-json3-dev"
  exit 1
fi

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DOREON_BUILD_TESTS=ON
cmake --build build -j"$(nproc)"
echo "Built:"
echo "  $ROOT/build/oreon-defense-daemon"
echo "  $ROOT/build/oreon-defense"
