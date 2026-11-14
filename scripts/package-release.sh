#!/bin/sh
# Package an already built app; never installs or starts a service.
set -eu
cd "$(dirname "$0")/.."
version=$(cat VERSION)
core_version=$(cat XRAY_VERSION)
case "$version" in
  *[!0-9.]*|""|.*|*.) echo "Release packaging requires a stable numeric VERSION." >&2; exit 1 ;;
esac
if [ "$(uname -m)" != arm64 ]; then
  echo "Only the tested macOS arm64 release is currently supported." >&2
  exit 1
fi
app=dist/Whale.app
core=${WHALE_BUILD_CORE:-.tools/xray}
cargo=${CARGO:-"$HOME/.cargo/bin/cargo"}
command -v python3 >/dev/null
command -v go >/dev/null # Packaging only: collects licenses of Xray dependencies.
test -x "$cargo"
test "$(dist/whale --version)" = "whale $version"
test "$(dist/whale-helper --version)" = "whale-helper $version"
test "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app/Contents/Info.plist")" = "$version"
test "$(/usr/libexec/PlistBuddy -c 'Print :LSMinimumSystemVersion' "$app/Contents/Info.plist")" = 13.0
test "$("$app/Contents/Helpers/whale" --version)" = "whale $version"
test "$("$app/Contents/MacOS/whale-helper" --version)" = "whale-helper $version"
codesign --verify --deep --strict "$app"
for binary in dist/whale dist/whale-helper "$app/Contents/MacOS/Whale" "$app/Contents/MacOS/xray"; do
  test "$(lipo -archs "$binary")" = arm64
done
expected_sha=$(awk '$2 == "arm64" {print $1}' XRAY_SHA256)
test -n "$expected_sha"
test "$(shasum -a 256 "$core" | awk '{print $1}')" = "$expected_sha"
case "$("$app/Contents/MacOS/xray" version)" in
  "Xray $core_version "*) ;;
  *) echo "Unexpected bundled Xray version." >&2; exit 1 ;;
esac

name="whale-$version-macos-arm64"
staging=$(mktemp -d "$PWD/dist/.release-package.XXXXXX")
trap 'rm -rf "$staging"' EXIT HUP INT TERM
# Deep app signing replaces the engine's linker signature. Reproduce that
# transformation on the checksum-verified original and compare the whole file.
cp -p "$core" "$staging/xray"
codesign --force --sign - "$staging/xray"
cmp "$staging/xray" "$app/Contents/MacOS/xray"
package="$staging/$name"
mkdir -p "$package/bin" "$package/libexec" "$package/completions" "$package/licenses/xray"
cp -p "$app/Contents/Helpers/whale" "$package/bin/whale"
cp -p "$app/Contents/MacOS/whale-helper" "$package/libexec/whale-helper"
cp -p "$app/Contents/MacOS/xray" "$package/libexec/xray"
ditto --noextattr --noqtn "$app" "$package/Whale.app"
cmp "$package/bin/whale" "$package/Whale.app/Contents/Helpers/whale"
cmp "$package/libexec/whale-helper" "$package/Whale.app/Contents/MacOS/whale-helper"
cp completions/_whale completions/whale.bash completions/whale.fish "$package/completions/"
cp VERSION XRAY_VERSION README.md "$package/"
cp docs/DEVELOPMENT.md "$package/DEVELOPMENT.md"
curl --fail --location --silent --show-error --connect-timeout 10 --max-time 60 \
  --proto '=https' --proto-redir '=https' \
  "https://raw.githubusercontent.com/XTLS/Xray-core/v$core_version/LICENSE" \
  --output "$package/licenses/xray/LICENSE"
test "$core_version" = 26.9.9
test "$(shasum -a 256 "$package/licenses/xray/LICENSE" | awk '{print $1}')" = 1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5
"$cargo" metadata --locked --offline --format-version 1 --filter-platform aarch64-apple-darwin > "$staging/cargo-metadata.json"

rust_sysroot=$("$(dirname "$cargo")/rustc" --print sysroot)
python3 - "$package" "$staging/cargo-metadata.json" "$version" "$core_version" "$rust_sysroot" <<'PY'
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

package = Path(sys.argv[1])
metadata = json.loads(Path(sys.argv[2]).read_text())
version, core_version = sys.argv[3:5]
license_prefixes = ("license", "licence", "copying", "notice", "copyright")

def copy_notices(source, destination):
    source, destination = Path(source), Path(destination)
    files = sorted(p for p in source.rglob("*")
                   if p.is_file() and not p.is_symlink()
                   and p.name.lower().startswith(license_prefixes))
    if not files:
        raise RuntimeError(f"Missing redistribution notices for {source.name}")
    for path in files:
        target = destination / path.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)

resolved = {node["id"] for node in metadata["resolve"]["nodes"]}
rust_packages = []
for item in sorted(metadata["packages"], key=lambda p: (p["name"], p["version"])):
    if item["id"] not in resolved or not item["source"]:
        continue
    copy_notices(Path(item["manifest_path"]).parent,
                 package / "licenses/rust" / f'{item["name"]}-{item["version"]}')
    rust_packages.append({key: item.get(key) for key in ("name", "version", "license", "repository", "source")})

rust_notices = Path(sys.argv[5]) / "share/doc/rust"
shutil.copytree(rust_notices / "licenses", package / "licenses/rust-standard-library")
shutil.copy2(rust_notices / "COPYRIGHT-library.html", package / "licenses/rust-standard-library/COPYRIGHT-library.html")

# Inspect the distributed binary, not Whale's retained legacy go.mod.
core = package / "libexec/xray"
build_info = subprocess.check_output(["go", "version", "-m", str(core)], text=True)
go_version = build_info.splitlines()[0].rsplit(": ", 1)[1]
go_modules = []
for line in build_info.splitlines()[1:]:
    fields = line.strip().split("\t")
    if fields[0] == "=>":
        raise RuntimeError("Review Xray module replacements before packaging")
    if fields[0] == "dep":
        go_modules.append(dict(zip(("path", "version", "sum"), fields[1:4])))

def collect_go_module(module):
    env = os.environ.copy()
    env["GOTOOLCHAIN"] = "local"
    env["GO111MODULE"] = "on"
    env["GOWORK"] = "off"
    # Run outside the checkout so Go cannot update the retained legacy go.sum.
    with tempfile.TemporaryDirectory(prefix="whale-license-module-", dir="/private/tmp") as module_work:
        result = subprocess.run(["go", "mod", "download", "-json", f'{module["path"]}@{module["version"]}'],
                                cwd=module_work, env=env, text=True, capture_output=True, timeout=180)
    downloaded = json.loads(result.stdout)
    if result.returncode or downloaded.get("Error") or downloaded.get("Sum") != module["sum"]:
        raise RuntimeError(f'Could not verify source notices for {module["path"]}')
    slug = module["path"].replace("/", "_") + "@" + module["version"]
    copy_notices(downloaded["Dir"], package / "licenses/xray-dependencies" / slug)
    return {**module, "source": f'https://pkg.go.dev/{module["path"]}@{module["version"]}'}

with concurrent.futures.ThreadPoolExecutor(max_workers=6) as workers:
    go_modules = list(workers.map(collect_go_module, go_modules))

go_license = package / "licenses/go/LICENSE"
go_license.parent.mkdir(parents=True)
if go_version != "go1.27.1":
    raise RuntimeError("Review the embedded Go toolchain license before packaging")
subprocess.run([
    "curl", "--fail", "--location", "--silent", "--show-error",
    "--connect-timeout", "10", "--max-time", "60",
    "--proto", "=https", "--proto-redir", "=https",
    f"https://raw.githubusercontent.com/golang/go/{go_version}/LICENSE",
    "--output", str(go_license),
], check=True)
if hashlib.sha256(go_license.read_bytes()).hexdigest() != "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad":
    raise RuntimeError("Go runtime license checksum does not match the reviewed version")
notices = {
    "xray": {"version": core_version, "license": "MPL-2.0",
             "source": f"https://github.com/XTLS/Xray-core/tree/v{core_version}",
             "source_archive": f"https://github.com/XTLS/Xray-core/archive/refs/tags/v{core_version}.tar.gz"},
    "go_runtime": {"version": go_version, "license": "BSD-3-Clause", "source": f"https://go.googlesource.com/go/+/refs/tags/{go_version}"},
    "rust_dependencies": rust_packages,
    "xray_dependencies": go_modules,
}
(package / "licenses/DEPENDENCIES.json").write_text(json.dumps(notices, indent=2) + "\n")
(package / "THIRD-PARTY-NOTICES.txt").write_text(
    "Whale includes the separately distributed Xray-core engine under MPL 2.0.\n"
    f"Corresponding Xray source: https://github.com/XTLS/Xray-core/tree/v{core_version}\n"
    "The license text is in licenses/xray/LICENSE. Individual dependency license\n"
    "and attribution notices are retained under licenses/. The dependency index\n"
    "contains exact versions and source locations. These notices do not change\n"
    "the licenses of the individual components.\n"
)
manifest = {
    "version": version, "platform": "macos", "architecture": "arm64", "minimum_macos": "13.0",
    "xray_version": core_version, "signature": "ad-hoc", "notarized": False,
    "files": {str(path.relative_to(package)): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in sorted(package.rglob("*")) if path.is_file()},
}
(package / "RELEASE.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(f'Collected notices for {len(rust_packages)} Rust and {len(go_modules)} Xray dependencies.')
PY

codesign --verify --deep --strict "$package/Whale.app"
COPYFILE_DISABLE=1 tar -czf "$staging/$name.tar.gz" -C "$staging" "$name"
mv "$staging/$name.tar.gz" "dist/$name.tar.gz"
(cd dist && shasum -a 256 "$name.tar.gz" > "$name.tar.gz.sha256")
cat "dist/$name.tar.gz.sha256"
