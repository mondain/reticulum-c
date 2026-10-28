#!/bin/sh
# Builds a self-contained release archive inside an Alpine container (musl, fully
# static, OpenSSL and bzip2 linked in), natively or under qemu for another CPU.
#   release-build.sh TARGET VERSION OUTDIR [SKIP_TEST_LABELS]
# TARGET names the archive (x86_64, aarch64, armv7, armv6); the container's own
# architecture decides what is built. The source tree is mounted at /src.
set -eu
target=$1 version=$2 out=$3 skip=${4:-network|pty}
name=reticulum-c-$version-linux-$target-musl
stage=/tmp/$name
apk add --no-cache build-base cmake bash git linux-headers \
  openssl-dev openssl-libs-static bzip2-dev bzip2-static >/dev/null
cd /src
cmake -S . -B /tmp/build -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
  -DRNC_BUILD_EXAMPLES=ON -DOPENSSL_USE_STATIC_LIBS=ON \
  -DBZIP2_LIBRARY_RELEASE=/usr/lib/libbz2.a -DBZIP2_INCLUDE_DIR=/usr/include \
  -DCMAKE_EXE_LINKER_FLAGS=-static
cmake --build /tmp/build -j"$(nproc)"
# the tests that need no sockets or ptys prove the binaries run on this CPU
ctest --test-dir /tmp/build -j"$(nproc)" --output-on-failure -LE "$skip"
cmake --install /tmp/build --prefix "$stage"
# what a consumer needs to link statically: OpenSSL and bzip2 beside the SDK
mkdir -p "$stage/include" "$stage/lib"
cp -a /usr/include/openssl "$stage/include/"
cp /usr/include/bzlib.h "$stage/include/"
cp /usr/lib/libcrypto.a /usr/lib/libbz2.a "$stage/lib/"
# the archive must be consumable as shipped: link the installed SDK statically
cmake -S tests/consumer -B /tmp/consumer -DCMAKE_PREFIX_PATH="$stage" \
  -DOPENSSL_ROOT_DIR="$stage" -DOPENSSL_USE_STATIC_LIBS=ON \
  -DBZIP2_LIBRARY_RELEASE="$stage/lib/libbz2.a" -DBZIP2_INCLUDE_DIR="$stage/include" \
  -DCMAKE_EXE_LINKER_FLAGS=-static
cmake --build /tmp/consumer
/tmp/consumer/consumer
strip "$stage"/bin/* 2>/dev/null || true
cp LICENSE README.md COMPATIBILITY.md "$stage/"
{
  echo "release:  $version"
  echo "target:   linux-$target-musl ($(uname -m))"
  echo "commit:   ${GITHUB_SHA:-$(git -C /src rev-parse HEAD 2>/dev/null || echo unknown)}"
  echo "openssl:  $(apk list --installed openssl-dev 2>/dev/null | head -1 | cut -d" " -f1)"
  echo "alpine:   $(cat /etc/alpine-release)"
} > "$stage/BUILDINFO"
mkdir -p "$out"
tar -C /tmp -czf "$out/$name.tar.gz" "$name"
ls -l "$out/$name.tar.gz"
