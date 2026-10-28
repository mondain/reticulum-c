#!/bin/sh
# Checks that every file that repeats the project version agrees with CMakeLists.txt
# (project(reticulum_c VERSION x.y.z), the single source), and, when a release tag is
# given, that the tag names that version.
#
#   check-version.sh [TAG]       TAG such as v0.3.0 or v0.3.0-rc1 (leading v and any
#                                -suffix are dropped before comparing)
#   check-version.sh --root DIR  check another checkout (used by the test)
#
# Files checked: CMakeLists.txt, library.json, idf_component.yml, every
# mcu/esp-idf/components/*/idf_component.yml, and the fallback RNC_MCU_VERSION in
# mcu/app/rnc_mcu_app.h. Exit 0 when all agree, 1 otherwise, 2 for usage errors.
set -eu

root=
tag=
while [ $# -gt 0 ]; do
  case $1 in
    --root) root=${2:?--root needs a directory}; shift 2 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    -*) echo "check-version: unknown option $1" >&2; exit 2 ;;
    *) [ -z "$tag" ] || { echo "check-version: more than one tag given" >&2; exit 2; }
       tag=$1; shift ;;
  esac
done
[ -n "$root" ] || root=$(cd "$(dirname "$0")/../.." && pwd)

fail=0
bad() { echo "check-version: $*" >&2; fail=1; }

# version_of FILE SED_EXPRESSION: prints the first captured version or nothing
version_of() { sed -n "$2" "$1" | head -n 1; }

cmake=$root/CMakeLists.txt
[ -f "$cmake" ] || { echo "check-version: $cmake not found" >&2; exit 2; }
project=$(version_of "$cmake" 's/^project(reticulum_c VERSION \([0-9][0-9.]*\).*/\1/p')
[ -n "$project" ] || { echo "check-version: no project(reticulum_c VERSION ...) line in $cmake" >&2; exit 1; }

report="CMakeLists.txt: $project"
compare() { # file, found
  rel=${1#"$root"/}
  if [ -z "$2" ]; then
    bad "$rel: no version found"
  else
    report="$report
$rel: $2"
    [ "$2" = "$project" ] || bad "$rel has version $2 but CMakeLists.txt has $project"
  fi
}

for f in "$root/library.json"; do
  if [ -f "$f" ]; then compare "$f" "$(version_of "$f" 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  else bad "library.json is missing"; fi
done
yml_found=0
for f in "$root/idf_component.yml" "$root"/mcu/esp-idf/components/*/idf_component.yml; do
  [ -f "$f" ] || continue
  yml_found=$((yml_found + 1))
  compare "$f" "$(version_of "$f" 's/^version:[[:space:]]*"\{0,1\}\([^"[:space:]]*\)"\{0,1\}[[:space:]]*$/\1/p')"
done
[ "$yml_found" -ge 2 ] || bad "expected idf_component.yml at the root and in the components, found $yml_found"
app=$root/mcu/app/rnc_mcu_app.h
if [ -f "$app" ]; then
  compare "$app" "$(version_of "$app" 's/^#define RNC_MCU_VERSION "\([^"]*\)".*/\1/p')"
else
  bad "mcu/app/rnc_mcu_app.h is missing"
fi

if [ -n "$tag" ]; then
  tagged=${tag#v}
  tagged=${tagged%%-*}
  case $tag in
    v[0-9]*) ;;
    *) bad "tag '$tag' does not look like v<major>.<minor>.<patch>[-suffix]" ;;
  esac
  report="$report
tag $tag: $tagged"
  [ "$tagged" = "$project" ] || bad "tag $tag names version $tagged but the project version in CMakeLists.txt is $project"
fi

if [ "$fail" -ne 0 ]; then
  echo "$report" >&2
  echo "check-version: FAILED. Set the version in CMakeLists.txt, then update every file listed above." >&2
  exit 1
fi
echo "check-version: all agree on $project${tag:+ (tag $tag)}"
