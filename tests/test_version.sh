#!/bin/sh
# Tests .github/scripts/check-version.sh: the real tree must agree, and a copy with one
# file out of step, or a tag that does not match, must fail with a message naming it.
#   test_version.sh SOURCE_DIR
set -u
src=${1:?usage: test_version.sh SOURCE_DIR}
script=$src/.github/scripts/check-version.sh
tmp=$(mktemp -d "${TMPDIR:-/tmp}/rnc-version.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
failures=0
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

version=$(sed -n 's/^project(reticulum_c VERSION \([0-9][0-9.]*\).*/\1/p' "$src/CMakeLists.txt")
[ -n "$version" ] || { echo "no project version in CMakeLists.txt"; exit 1; }

# 1. the repository itself
sh "$script" --root "$src" >"$tmp/out" 2>&1 || fail "the repository's own versions disagree: $(cat "$tmp/out")"
sh "$script" --root "$src" "v$version" >"$tmp/out" 2>&1 || fail "tag v$version rejected: $(cat "$tmp/out")"
sh "$script" --root "$src" "v$version-rc1" >"$tmp/out" 2>&1 || fail "tag v$version-rc1 rejected: $(cat "$tmp/out")"

# 2. wrong tags
for t in v9.9.9 "v$version.1" "$version-x" v ""; do
  [ -n "$t" ] || continue
  if sh "$script" --root "$src" "$t" >"$tmp/out" 2>&1; then fail "tag '$t' accepted"; fi
done
sh "$script" --root "$src" v9.9.9 2>&1 | grep -q "9.9.9" || fail "the tag mismatch message does not name the tag"

# 3. a copy where one file is bumped but not the others
copy() {
  rm -rf "$tmp/tree"
  mkdir -p "$tmp/tree/mcu/app" "$tmp/tree/mcu/esp-idf/components/reticulum_c" "$tmp/tree/mcu/esp-idf/components/reticulum_c_mcu_app"
  cp "$src/CMakeLists.txt" "$src/library.json" "$src/idf_component.yml" "$tmp/tree/"
  cp "$src/mcu/app/rnc_mcu_app.h" "$tmp/tree/mcu/app/"
  cp "$src"/mcu/esp-idf/components/reticulum_c/idf_component.yml "$tmp/tree/mcu/esp-idf/components/reticulum_c/"
}
copy
sh "$script" --root "$tmp/tree" >"$tmp/out" 2>&1 || fail "the copy should pass: $(cat "$tmp/out")"
for f in library.json idf_component.yml mcu/esp-idf/components/reticulum_c/idf_component.yml mcu/app/rnc_mcu_app.h CMakeLists.txt; do
  copy
  sed "s/$version/99.0.0/" "$tmp/tree/$f" >"$tmp/edited" && cp "$tmp/edited" "$tmp/tree/$f"
  if sh "$script" --root "$tmp/tree" >"$tmp/out" 2>&1; then
    fail "a bumped $f was not detected"
  else
    case $f in
      CMakeLists.txt) grep -q "has version" "$tmp/out" || fail "CMakeLists.txt bump: no mismatch message" ;;
      *) grep -q "$f has version 99.0.0" "$tmp/out" || fail "$f bump: message does not name the file: $(cat "$tmp/out")" ;;
    esac
  fi
done

# 4. a component file with the version removed
copy
grep -v '^version:' "$src/idf_component.yml" >"$tmp/tree/idf_component.yml"
if sh "$script" --root "$tmp/tree" >"$tmp/out" 2>&1; then fail "a missing version line was not detected"; fi

if [ "$failures" -ne 0 ]; then echo "$failures check(s) failed"; exit 1; fi
echo "version consistency check: ok"
