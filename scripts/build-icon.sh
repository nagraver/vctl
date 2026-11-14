#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p dist/Whale.iconset
xcrun swift -module-cache-path /private/tmp/whale-swift-cache scripts/render-icon.swift macos/Whale/Assets/whale.svg dist/whale-icon.png
for size in 16 32 128 256 512; do
  sips -z "$size" "$size" dist/whale-icon.png --out "dist/Whale.iconset/icon_${size}x${size}.png" >/dev/null
  double=$((size * 2))
  sips -z "$double" "$double" dist/whale-icon.png --out "dist/Whale.iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns dist/Whale.iconset -o dist/Whale.icns
