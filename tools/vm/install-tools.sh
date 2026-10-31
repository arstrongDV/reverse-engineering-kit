#!/usr/bin/env bash
# Install the pinned analysis tools in the test VM, then prove each one works. Run through
# `vm.sh install-tools`, which opens the network first and closes it again afterwards.
# Safe to rerun after a failure: finished tools are skipped. With --check-only, it just runs the
# working tests, which need no network.
set -euo pipefail

PREFIX=/opt/re-kit
BIN=/usr/local/bin

GHIDRA_TAG=Ghidra_12.2_build
GHIDRA_ZIP=ghidra_12.2_PUBLIC_20261016.zip
GHIDRA_SHA256=2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67
JADX_VERSION=1.5.6
JADX_SHA256=545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974
APKTOOL_VERSION=3.0.3
APKTOOL_SHA256=dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423
RIZIN_VERSION=0.9.1
RIZIN_SHA256=7ac1cd7daca7afdda742e15478b1f747fc1f813e496fee71839d1e109e543dca
FRIDA_VERSION=17.25.0
FRIDA_TOOLS_VERSION=14.11.0

# /tmp is held in RAM here and is too small to unpack Ghidra.
WORK="$(mktemp -d -p /var/tmp)"
trap 'rm -rf "$WORK"' EXIT

step() { echo "==> $*"; }

fetch() {
  local url="$1" sha256="$2" name
  name="$(basename "$url")"
  curl -fsSL --retry 3 -o "$WORK/$name" "$url"
  echo "$sha256  $WORK/$name" | sha256sum --check --quiet
  echo "$WORK/$name"
}

# Build logs are thousands of lines, so show them only when something fails.
quietly() {
  local log="$WORK/build.log"
  if ! "$@" >"$log" 2>&1; then
    tail -n 40 "$log" >&2
    echo "failed: $*" >&2
    return 1
  fi
}

install_packages() {
  step 'Ubuntu packages'
  # Ubuntu's daily updater takes the apt lock at random and would change a baseline meant to stay fixed.
  sudo systemctl disable --now apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service
  sudo systemctl stop apt-daily.service apt-daily-upgrade.service
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    openjdk-25-jdk-headless nodejs npm unzip xz-utils gcc g++ make meson ninja-build pkg-config \
    >/dev/null
  sudo install -d -o "$(id -un)" "$PREFIX"
}

install_frida() {
  if [[ -x "$PREFIX/venv/bin/frida" ]]; then return; fi
  step "Frida $FRIDA_VERSION"
  python3 -m venv "$PREFIX/venv"
  "$PREFIX/venv/bin/pip" install -q "frida==$FRIDA_VERSION" "frida-tools==$FRIDA_TOOLS_VERSION"
  sudo ln -sf "$PREFIX/venv/bin/frida" "$PREFIX/venv/bin/frida-ps" "$PREFIX/venv/bin/frida-trace" "$BIN/"
}

install_jadx() {
  if [[ -x "$PREFIX/jadx/bin/jadx" ]]; then return; fi
  step "jadx $JADX_VERSION"
  local zip
  zip="$(fetch "https://github.com/skylot/jadx/releases/download/v$JADX_VERSION/jadx-$JADX_VERSION.zip" "$JADX_SHA256")"
  unzip -q "$zip" -d "$PREFIX/jadx"
  sudo ln -sf "$PREFIX/jadx/bin/jadx" "$BIN/jadx"
}

install_apktool() {
  if [[ -f "$PREFIX/apktool/apktool.jar" ]]; then return; fi
  step "apktool $APKTOOL_VERSION"
  local jar
  jar="$(fetch "https://github.com/iBotPeaches/Apktool/releases/download/v$APKTOOL_VERSION/apktool_$APKTOOL_VERSION.jar" "$APKTOOL_SHA256")"
  install -d "$PREFIX/apktool"
  install -m 644 "$jar" "$PREFIX/apktool/apktool.jar"
  printf '#!/bin/sh\nexec java -jar %s/apktool/apktool.jar "$@"\n' "$PREFIX" | sudo tee "$BIN/apktool" >/dev/null
  sudo chmod 755 "$BIN/apktool"
}

install_ghidra() {
  # Ghidra starts without this file, but it cannot decompile, so it marks a finished install.
  local decompiler="$PREFIX/ghidra/Ghidra/Features/Decompiler/build/os/linux_arm_64/decompile"
  if [[ -x "$decompiler" ]]; then return; fi
  step 'Ghidra 12.2 (the release has no arm64 Linux natives, so they are built here)'
  rm -rf "$PREFIX/ghidra"
  local zip
  zip="$(fetch "https://github.com/NationalSecurityAgency/ghidra/releases/download/$GHIDRA_TAG/$GHIDRA_ZIP" "$GHIDRA_SHA256")"
  unzip -q "$zip" -d "$WORK/ghidra-unpacked"
  rm -f "$zip"
  mv "$WORK"/ghidra-unpacked/ghidra_* "$PREFIX/ghidra"
  (cd "$PREFIX/ghidra/support/gradle" && quietly ./gradlew --no-daemon buildNatives)
  rm -rf "$HOME/.gradle"
  test -x "$decompiler"
  sudo ln -sf "$PREFIX/ghidra/support/analyzeHeadless" "$BIN/analyzeHeadless"
}

install_rizin() {
  if command -v rizin >/dev/null; then return; fi
  step "rizin $RIZIN_VERSION (no arm64 Linux package exists, so it is built from source)"
  local archive src
  archive="$(fetch "https://github.com/rizinorg/rizin/releases/download/v$RIZIN_VERSION/rizin-src-v$RIZIN_VERSION.tar.xz" "$RIZIN_SHA256")"
  tar -xJf "$archive" -C "$WORK"
  rm -f "$archive"
  src="$(find "$WORK" -maxdepth 1 -type d -name 'rizin*')"
  quietly meson setup "$WORK/rizin-build" "$src" --prefix=/usr/local --buildtype=release
  quietly meson compile -C "$WORK/rizin-build" -j 2
  sudo meson install -C "$WORK/rizin-build" --quiet
  sudo ldconfig
  # The install step runs as root and leaves root-owned logs in the build folder.
  sudo rm -rf "$WORK/rizin-build" "$src"
}

# A version number proves little: Ghidra reports one even when it cannot decompile.
verify() {
  step 'Working tests'
  local sample="$WORK/verify"
  mkdir -p "$sample"
  cat >"$sample/sample.c" <<'EOF'
__attribute__((noinline)) int add_two(int value) { return value + 2; }
int main(int argc, char **argv) { (void)argv; return add_two(argc) == 0; }
EOF
  gcc -O1 -o "$sample/sample" "$sample/sample.c"

  cat >"$sample/DecompileCheck.java" <<'EOF'
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;

public class DecompileCheck extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        var function = getGlobalFunctions("add_two").get(0);
        println(decompiler.decompileFunction(function, 60, monitor).getDecompiledFunction().getC());
    }
}
EOF
  analyzeHeadless "$sample" check -import "$sample/sample" -scriptPath "$sample" \
    -postScript DecompileCheck.java -deleteProject >"$sample/ghidra.log" 2>&1 || true
  if ! grep -q 'param_1 + 2' "$sample/ghidra.log"; then
    tail -n 30 "$sample/ghidra.log" >&2
    echo 'failed: Ghidra did not decompile add_two' >&2
    return 1
  fi
  echo 'ghidra: decompiled add_two'

  rizin -qc 'aa; afl' "$sample/sample" >"$sample/rizin.log" 2>&1
  grep -q add_two "$sample/rizin.log"
  echo 'rizin: analyzed the sample and found add_two'

  mkdir -p "$sample/java"
  cat >"$sample/java/Check.java" <<'EOF'
public class Check { public static String marker() { return "re-kit-check"; } }
EOF
  javac -d "$sample/java" "$sample/java/Check.java"
  jar cf "$sample/check.jar" -C "$sample/java" Check.class
  jadx -q -d "$sample/jadx" "$sample/check.jar"
  grep -rq 're-kit-check' "$sample/jadx/sources"
  echo 'jadx: decompiled a jar and recovered the marker string'

  cat >"$sample/frida_check.py" <<'EOF'
import sys
import threading

import frida

messages = []
detached = threading.Event()
pid = frida.spawn([sys.argv[1]])
session = frida.attach(pid)
session.on("detached", lambda *args: detached.set())
script = session.create_script("""
const symbol = Process.mainModule.enumerateSymbols().find((item) => item.name === "add_two");
Interceptor.attach(symbol.address, {
  onEnter(args) { send(args[0].toInt32()); },
  onLeave(result) { send(result.toInt32()); },
});
""")
script.on("message", lambda message, data: messages.append(message.get("payload")))
script.load()
frida.resume(pid)
# Exiting while the target is shutting down crashes the Python binding, so wait for the detach.
detached.wait(30)
sys.exit(0 if messages == [1, 3] else 1)
EOF
  "$PREFIX/venv/bin/python" "$sample/frida_check.py" "$sample/sample"
  echo 'frida: hooked add_two and read its argument and return value'

  echo "apktool $(apktool --version) (version check only: there is no sample APK yet)"
  echo "java $(java -version 2>&1 | head -n 1)"
  echo "node $(node --version), npm $(npm --version), $(python3 --version)"
}

if [[ "${1:-}" == --check-only ]]; then
  verify
  exit
fi

install_packages
install_frida
install_jadx
install_apktool
install_ghidra
install_rizin
verify
sudo apt-get clean
step 'All tools installed'
