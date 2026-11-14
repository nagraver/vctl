#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
xcrun swiftc -module-cache-path /private/tmp/whale-swift-cache macos/Whale/Models.swift macos/Tests/ModelsCheck.swift -o dist/models-check
profile=$(mktemp -d /private/tmp/whale-native-check.XXXXXX)
trap 'rm -rf "$profile"' EXIT
./dist/whale-helper --home "$profile" snapshot | ./dist/models-check
cp tests/fixtures/native-state.json "$profile/state.json"
chmod 600 "$profile/state.json"
./dist/whale-helper --home "$profile" snapshot | ./dist/models-check
