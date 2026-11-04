#!/usr/bin/env bash
# Build the benchmark targets. Run through `vm.sh build-benchmarks`, which opens the network first
# and closes it afterwards. Compilers land in the VM, so `vm.sh restore tools` removes them again.
set -euo pipefail

ROOT="$1"
ANDROID_JAR=/usr/lib/android-sdk/platforms/android-23/android.jar
STORE_PASSWORD=benchmark

step() { echo "==> $*"; }

install_compilers() {
  step 'Compilers'
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    gcc-mingw-w64-x86-64-win32 aapt apksigner zipalign dalvik-exchange android-sdk-platform-23 \
    zip >/dev/null
}

build_crackmes() {
  step 'Benchmarks 1 and 2: crackme, then the same crackme stripped and packed'
  local source="$ROOT/01-crackme-xor/src/crackme.c" plain="$ROOT/01-crackme-xor/build/crackme"
  mkdir -p "$ROOT/01-crackme-xor/build" "$ROOT/02-crackme-upx/build"
  gcc -O1 -o "$plain" "$source"
  "$plain" RK26-XOR7-ROL3-A >/dev/null
  if "$plain" RK26-XOR7-ROL3-B >/dev/null; then
    echo 'failed: the crackme accepted a wrong serial' >&2
    return 1
  fi
  local stripped=/tmp/crackme-stripped packed="$ROOT/02-crackme-upx/build/crackme-packed"
  gcc -O1 -static -s -o "$stripped" "$source"
  rm -f "$packed"
  upx -q --best -o "$packed" "$stripped" >/dev/null
  "$packed" RK26-XOR7-ROL3-A >/dev/null
}

build_telemetry() {
  step 'Benchmark 3: Windows telemetry agent'
  mkdir -p "$ROOT/03-telemetry-pe/build"
  x86_64-w64-mingw32-gcc -O1 -s -o "$ROOT/03-telemetry-pe/build/agent.exe" \
    "$ROOT/03-telemetry-pe/src/agent.c" -ladvapi32 -lws2_32
}

build_protocol() {
  step 'Benchmark 4: two captures of the toy protocol'
  python3 "$ROOT/04-toy-tcp-protocol/src/make_pcaps.py" "$ROOT/04-toy-tcp-protocol/build"
  python3 "$ROOT/04-toy-tcp-protocol/src/decoder.py" \
    "$ROOT/04-toy-tcp-protocol/build/session-holdout.pcap" >/dev/null
}

build_android() {
  step 'Benchmark 5: Android app with hidden endpoints'
  local project="$ROOT/05-android-hidden-api" work=/var/tmp/apk-build
  rm -rf "$work"
  mkdir -p "$work/classes" "$work/generated" "$project/build"
  aapt package -f -m -J "$work/generated" -M "$project/src/AndroidManifest.xml" \
    -S "$project/src/res" -I "$ANDROID_JAR"
  # shellcheck disable=SC2046
  javac -nowarn -Xlint:-options --release 8 -cp "$ANDROID_JAR" -d "$work/classes" \
    $(find "$project/src/java" "$work/generated" -name '*.java')
  dalvik-exchange --dex --output="$work/classes.dex" "$work/classes"
  aapt package -f -M "$project/src/AndroidManifest.xml" -S "$project/src/res" -I "$ANDROID_JAR" \
    -F "$work/unsigned.apk"
  (cd "$work" && zip -q unsigned.apk classes.dex)
  zipalign -f 4 "$work/unsigned.apk" "$work/aligned.apk"
  keytool -genkeypair -keystore "$work/debug.keystore" -storepass "$STORE_PASSWORD" \
    -keypass "$STORE_PASSWORD" -alias benchmark -keyalg RSA -keysize 2048 -validity 3650 \
    -dname 'CN=Benchmark Only' 2>/dev/null
  apksigner sign --ks "$work/debug.keystore" --ks-pass "pass:$STORE_PASSWORD" \
    --out "$project/build/fieldnotes.apk" "$work/aligned.apk"
  apksigner verify "$project/build/fieldnotes.apk"
  rm -f "$project/build/fieldnotes.apk.idsig"
}

build_webpack() {
  step 'Benchmark 6: webpack bundle without a source map'
  local project="$ROOT/06-webpack-bundle"
  (cd "$project/src" && npm ci --ignore-scripts --no-audit --no-fund >/dev/null)
  (cd "$project/src" && node_modules/.bin/webpack --output-path "$project/build" >/dev/null)
  rm -rf "$project/src/node_modules"
  if grep -q sourceMappingURL "$project/build/main.js"; then
    echo 'failed: the bundle points at a source map' >&2
    return 1
  fi
}

build_electron() {
  step 'Benchmark 7: Electron app packed with asar'
  local project="$ROOT/07-electron-asar"
  mkdir -p "$project/build/resources"
  asar pack "$project/src/app" "$project/build/resources/app.asar"
}

build_antidebug() {
  step 'Benchmark 8: binary with anti-debug checks'
  local binary="$ROOT/08-anti-debug/build/antidebug"
  mkdir -p "$ROOT/08-anti-debug/build"
  gcc -O1 -o "$binary" "$ROOT/08-anti-debug/src/antidebug.c"
  "$binary" | grep -q 'ORCHID-42'
}

build_file_format() {
  step 'Benchmark 9: custom file format, proved against its Kaitai spec'
  local project="$ROOT/09-custom-file-format" parser=/var/tmp/rkf-parser
  python3 "$project/src/make_samples.py" "$project/build"
  rm -rf "$parser"
  mkdir -p "$parser"
  kaitai-struct-compiler -t python --outdir "$parser" "$project/src/format.ksy" >/dev/null
  (cd "$parser" && /opt/re-kit/venv/bin/python -c '
import sys
from pathlib import Path
import rkf
files = sorted(Path(sys.argv[1]).glob("*.rkf"))
assert len(files) == 3
for path in files:
    parsed = rkf.Rkf.from_file(str(path))
    assert len(parsed.records) == parsed.num_records
' "$project/build")
}

build_obfuscated() {
  step 'Benchmark 10: obfuscated JavaScript'
  local project="$ROOT/10-obfuscated-js"
  mkdir -p "$project/build"
  (cd "$project/src" && npm ci --ignore-scripts --no-audit --no-fund >/dev/null)
  (cd "$project/src" && node obfuscate.js app.js "$project/build/app.obfuscated.js")
  rm -rf "$project/src/node_modules"
  # The obfuscated copy must still do what the original does.
  diff <(node "$project/src/app.js") <(node "$project/build/app.obfuscated.js")
  # The original has no switch, so one here means the control flow really was flattened.
  grep -q 'switch(' "$project/build/app.obfuscated.js"
}

install_compilers
build_crackmes
build_telemetry
build_protocol
build_android
build_webpack
build_electron
build_antidebug
build_file_format
build_obfuscated
step 'All benchmarks built'
