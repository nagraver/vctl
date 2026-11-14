#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
app=dist/Whale.app
version=$(cat VERSION)
app_version=${version%%-*}
arch=$(uname -m)
core=${WHALE_BUILD_CORE:-.tools/xray}
expected_core=$(cat XRAY_VERSION)
actual_core=$("$core" version)
case "$actual_core" in
  "Xray $expected_core "*) ;;
  *) echo "Expected Xray $expected_core; configure WHALE_BUILD_CORE." >&2; exit 1 ;;
esac
expected_sha=${WHALE_BUILD_CORE_SHA256:-$(awk -v arch="$arch" '$2 == arch {print $1}' XRAY_SHA256)}
if [ -z "$expected_sha" ]; then
  echo "No reviewed engine checksum for $arch. Set WHALE_BUILD_CORE_SHA256 after verifying the engine." >&2
  exit 1
fi
actual_sha=$(shasum -a 256 "$core" | awk '{print $1}')
if [ "$actual_sha" != "$expected_sha" ]; then
  echo "Bundled engine checksum does not match the reviewed build." >&2
  exit 1
fi
case "$(./dist/whale --version)" in
  "whale $version") ;;
  *) echo "Cargo.toml and VERSION must match." >&2; exit 1 ;;
esac
previous_build=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$app/Contents/Info.plist" 2>/dev/null || true)
case "$previous_build" in ''|*[!0-9]*) previous_build=0 ;; esac
build_number=$((previous_build + 1))
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources" "$app/Contents/Helpers"
xcrun swiftc -parse-as-library -O -module-cache-path /private/tmp/whale-swift-cache -target "$arch-apple-macos13.0" -framework SwiftUI -framework AppKit macos/Whale/*.swift -o "$app/Contents/MacOS/Whale"
cp dist/whale-helper "$app/Contents/MacOS/"
cp dist/whale "$app/Contents/Helpers/whale"
cp "$core" "$app/Contents/MacOS/xray"
sh scripts/build-icon.sh
cp dist/Whale.icns "$app/Contents/Resources/AppIcon.icns"
chmod 755 "$app/Contents/MacOS/"*
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>io.github.nagraver.whale</string>
<key>CFBundleName</key><string>Whale</string>
<key>CFBundleDisplayName</key><string>Whale</string>
<key>CFBundleExecutable</key><string>Whale</string>
<key>CFBundleIconFile</key><string>AppIcon.icns</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$app_version</string>
<key>CFBundleVersion</key><string>$build_number</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>NSHighResolutionCapable</key><true/>
<key>NSPrincipalClass</key><string>NSApplication</string>
</dict></plist>
PLIST
codesign --force --deep --sign - "$app"
