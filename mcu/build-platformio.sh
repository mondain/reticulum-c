#!/usr/bin/env bash
# Builds the PlatformIO/Arduino firmware (mcu/platformio) for ESP32, ESP32-S3 and
# nRF52840 boards with a pinned PlatformIO, the same way in CI and on a developer machine.
#
#   mcu/build-platformio.sh [ENV...] [OUTDIR]
#
# ENV is one or more environment names from mcu/platformio/platformio.ini (default:
# all of them); an argument that is not an environment name is the output directory
# (default mcu/out/platformio). PlatformIO is installed into a virtual environment
# ($RNC_PIO_VENV, default mcu/out/.pio-venv) when it is missing or not the pinned
# version; platforms, toolchains and frameworks are downloaded into PlatformIO's core
# directory ($PLATFORMIO_CORE_DIR, default ~/.platformio) at the versions pinned in
# platformio.ini. Needs python3 (with venv) and network access on the first run.
#
# OUTDIR/<env>/ receives the board's flashable files, flash.txt, size.txt (section sizes
# and, on nRF52, the heap), build-info.txt and build.log. OUTDIR/size-report.txt
# has the RAM and flash lines PlatformIO printed for every environment.
set -eu

PIO_VERSION=6.1.19 # keep in sync with the cache key in the workflows (they hash this file)
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
PROJECT=$HERE/platformio
VENV=${RNC_PIO_VENV:-$HERE/out/.pio-venv}

# the single version source
VERSION=$(sed -n 's/^project(reticulum_c VERSION \([0-9][0-9.]*\).*/\1/p' "$ROOT/CMakeLists.txt")
[ -n "$VERSION" ] || { echo "cannot read the version from $ROOT/CMakeLists.txt" >&2; exit 1; }
COMMIT=${RNC_COMMIT:-$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)}

ALL_ENVS=$(sed -n 's/^\[env:\([^]]*\)\].*/\1/p' "$PROJECT/platformio.ini")
ENVS=""
OUT=""
for arg in "$@"; do
  if echo "$ALL_ENVS" | grep -qx -- "$arg"; then
    ENVS="$ENVS $arg"
  elif [ -z "$OUT" ]; then
    OUT=$arg
  else
    echo "unknown environment or extra argument: $arg" >&2
    echo "environments: $(echo $ALL_ENVS)" >&2
    exit 2
  fi
done
[ -n "$ENVS" ] || ENVS=$ALL_ENVS
OUT=${OUT:-$HERE/out/platformio}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)

# ---- the pinned PlatformIO ---------------------------------------------------
if [ ! -x "$VENV/bin/pio" ] || ! "$VENV/bin/pio" --version 2>/dev/null | grep -q "version $PIO_VERSION\$"; then
  command -v python3 >/dev/null || { echo "python3 not found" >&2; exit 1; }
  echo "installing platformio==$PIO_VERSION into $VENV"
  rm -rf "$VENV"
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install --quiet --disable-pip-version-check "platformio==$PIO_VERSION"
fi
PIO=$VENV/bin/pio
export PLATFORMIO_CORE_DIR=${PLATFORMIO_CORE_DIR:-$HOME/.platformio}
export PLATFORMIO_NO_ANSI=true PLATFORMIO_DISABLE_PROGRESSBAR=true PLATFORMIO_CHECK_PLATFORMS_INTERVAL=0
# RELEASE BUILDS MUST NOT CONTAIN Wi-Fi CREDENTIALS. Developers can compile defaults in
# with PLATFORMIO_BUILD_FLAGS (-DRNC_MCU_DEV_WIFI_SSID=... see mcu/platformio/README.txt);
# such a build is marked "dev-wifi-defaults: yes" in build-info.txt (the release packaging
# refuses it) and this script fails when RNC_RELEASE=1 is set.
DEV_WIFI=no
case "${PLATFORMIO_BUILD_FLAGS:-}" in
  *RNC_MCU_DEV_WIFI*)
    DEV_WIFI=yes
    echo "WARNING: Wi-Fi credentials are compiled in (RNC_MCU_DEV_WIFI_*): developer build, do not distribute" >&2
    if [ "${RNC_RELEASE:-0}" = 1 ]; then
      echo "refusing: RNC_RELEASE=1 and credentials are compiled in" >&2
      exit 1
    fi ;;
esac
# one build epoch for every environment (the clock policy in mcu/app/rnc_mcu_app.h);
# SOURCE_DATE_EPOCH makes it reproducible
RNC_MCU_BUILD_EPOCH=${RNC_MCU_BUILD_EPOCH:-${SOURCE_DATE_EPOCH:-$(date +%s)}}
export RNC_MCU_BUILD_EPOCH

: > "$OUT/size-report.txt"
failed=""
for env in $ENVS; do
  echo "=== $env (reticulum-c $VERSION) ==="
  DEST=$OUT/$env
  rm -rf "$DEST" "$PROJECT/.pio/build/$env"
  mkdir -p "$DEST"
  if ! (cd "$PROJECT" && "$PIO" run -e "$env") > "$DEST/build.log" 2>&1; then
    echo "BUILD FAILED: $env (last lines of $DEST/build.log)" >&2
    tail -25 "$DEST/build.log" >&2
    failed="$failed $env"
    continue
  fi
  cp "$PROJECT/.pio/build/$env/artifacts/"* "$DEST/"
  {
    echo "== $env =="
    grep -E '^(RAM|Flash):' "$DEST/build.log"
  } | tee -a "$OUT/size-report.txt"
  {
    echo "version:   $VERSION"
    echo "commit:    $COMMIT"
    echo "firmware:  platformio-$env"
    echo "platformio: $PIO_VERSION"
    echo "epoch:     $RNC_MCU_BUILD_EPOCH"
    echo "dev-wifi-defaults: $DEV_WIFI"
    echo "built:     $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "packages:"
    (cd "$PROJECT" && "$PIO" pkg list -e "$env" 2>/dev/null) | grep -v '^Resolving' | sed 's/^/  /' || true
  } > "$DEST/build-info.txt"
done

if [ -n "$failed" ]; then
  echo "failed environments:$failed" >&2
  exit 1
fi
echo "built (reticulum-c $VERSION): $OUT"
ls -l "$OUT"/*/merged.bin "$OUT"/*/*.uf2 2>/dev/null || true
