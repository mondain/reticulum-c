# Releasing reticulum-c


## Where the version lives

The version is the VERSION in the project() line of CMakeLists.txt (today
0.8.0); the library and package version, the shared library version and the CMake
package compatibility all read it, and so do the firmware build scripts. SOVERSION
(the ABI number) is separate, also in CMakeLists.txt; raise it only for an
incompatible ABI change.

Five more files repeat the version because their tools read them directly:

```text
library.json                                        (PlatformIO library)
idf_component.yml                                   (ESP-IDF, repository root)
mcu/esp-idf/components/reticulum_c/idf_component.yml
mcu/app/rnc_mcu_app.h                               (fallback RNC_MCU_VERSION)
include/reticulum_c/rnc.h                           (RNC_VERSION_STRING)
```

When bumping, change all of them in the same pull request.
.github/scripts/check-version.sh reads every one and fails, naming the file and
both values, unless they agree; it also runs as the ctest
reticulum_version_consistency and as the first step of the CI mcu job and of the
Release workflow, so a bump that misses a file cannot get through. Run it by hand
with `sh .github/scripts/check-version.sh [vTAG]`.

## The tag

A release is a git tag named `v<VERSION>`, for example v0.2.1, on a commit that
is on main. A suffix after a hyphen makes a pre-release: v0.3.0-rc1. The suffix
is ignored when the tag is compared with the project version, so v0.3.0-rc1
needs `project(reticulum_c VERSION 0.3.0 ...)`.

Tags record what was released; the GitHub release page carries the archives,
SHA256SUMS and generated notes. Main-branch firmware on the browser installer
is a separate publication and can include changes not yet in a tagged release.

## How a release happens

1. Raise the version in a pull request, merge it, and let CI go green on main. The
   version is in six places (CMakeLists.txt, library.json, idf_component.yml, the
   component copy under mcu/esp-idf/components/reticulum_c/idf_component.yml,
   mcu/app/rnc_mcu_app.h and the "today" note at the top of this file); `sh .github/scripts/check-version.sh vX.Y.Z`
   checks that they agree.
2. Tag that commit and push only the tag:

   ```sh
   git tag v0.2.1
   git push origin v0.2.1
   ```

3. The tag push also runs the reference Python RNS and Leviculum interoperability
   workflows (rns-interop.yml, leviculum-interop.yml). They run on tags and on demand,
   not on every push or pull request, so a release is the normal point to see them.
   The Release workflow (.github/workflows/release.yml) runs on the tag push
   and on nothing else that creates a release. Its first job, `version`, runs
   check-version.sh with the tag and stops the whole workflow unless the tag and
   every version file agree. Then it builds and tests the Linux archives, builds
   the firmware for the ESP32 and nRF52 boards, packages it, and only then
   publishes the release.
   The release is created by the workflow's own token, which does not start other
   workflows, so the last step of the release job dispatches the browser installer
   workflow (pages.yml) at the new tag. Nothing further is needed by hand; check
   that the Firmware flasher Pages run succeeded.
4. A tag that was pushed by mistake: delete the GitHub release, then the tag
   (git push origin :refs/tags/v0.2.1 and git tag -d v0.2.1).

## What a release contains

```text
Linux (musl, static):  reticulum-c-<version>-linux-<x86_64|aarch64|armv7|armv6>-musl.tar.gz
Firmware per board:    reticulum-c-<version>-mcu-<board>.zip (flashable files,
                       flash instructions, BUILDINFO), for esp32 and esp32s3
                       (ESP-IDF) and the PlatformIO boards heltec_wifi_lora_32_v3,
                       heltec_wifi_lora_32_v2, ttgo_t_beam, lilygo_t3_s3,
                       lilygo_t_beam_supreme (SX1262 variant),
                       wiscore_rak4631, heltec_t114, seeed_xiao_nrf52840_wio,
                       lilygo_t_echo
Sources for firmware:  reticulum-c-<version>-esp-idf-component.tar.gz and
                       reticulum-c-<version>-platformio-library.tar.gz
Checksums:             SHA256SUMS covers every archive.
```

Toolchain pins that change the firmware builds: the ESP-IDF Docker image
(espressif/idf:v5.4.4, in mcu/build-esp-idf.sh), PlatformIO 6.1.19 (in
mcu/build-platformio.sh, whose hash is also the CI cache key) and the platform
versions in mcu/platformio/platformio.ini. The Linux archives use alpine:3.20.
Hardware bench coverage is a T-Echo leaf and Supreme SX1262 gateway using
PlatformIO firmware, including routed /echo and /info at 915 MHz. Other boards,
range, sustained load and stock RNode interoperability remain unverified.
ESP-IDF archives are generic (no LoRa board selected, so no radio); only the
PlatformIO board archives carry a selected board's radio pin table. Radio and
Wi-Fi settings are provisioned at run time, so no archive
contains credentials or transmit defaults; package-mcu.sh refuses images built
with compiled-in credentials.

## Browser installer publication

.github/workflows/pages.yml builds all nine PlatformIO board environments and
deploys https://mondain.github.io/reticulum-c/ independently of the Release
workflow. It runs for relevant main-branch pushes, externally published release
events or manual dispatch. Main and manually dispatched builds use
`main-<12-character-commit>`; release-event builds use the release tag.

The Release workflow publishes with GITHUB_TOKEN, so its release event does not
trigger another workflow. Its last step therefore dispatches Firmware flasher
Pages with release_tag set to the tag, which labels the installer entry with the
tag. A release published directly by a user or an external token triggers the
tagged path through the release event. To publish a tag by hand (for example to
repeat a failed run), with the GitHub CLI: gh workflow run pages.yml -f release_tag=v0.2.1
See https://docs.github.com/en/actions/concepts/security/github_token for the
event restrictions. Pages publication does not add archives to an older release.

The staging script (.github/scripts/build-web-flasher.py) checks build provenance,
rejects compiled-in Wi-Fi credentials, verifies hashes, chip headers, flash
offsets and application-only nRF52 packages, and publishes an allowlisted catalog.
It retains up to five catalog versions, prioritizing tagged releases in history.
Logs, ELF files, merged images and identity/settings images are not published.
The browser verifies SHA-256 before writing; ESP32 updates use separate parts
and MD5 flash verification. A factory erase is an explicit user choice. nRF52
uses acknowledged serial DFU or downloadable UF2, preserving its internal file
system. Browser setup uses the rnc-config console, not RNode EEPROM provisioning.

Validate publication rules with python3 tests/test_web_firmware.py. In web/ run
npm ci, npm test, npm run build and npm run test:ui (install Playwright Chromium
with npx playwright install --with-deps chromium first). Pages success verifies
this pipeline; check the C SDK CI workflow, and the interoperability workflows (tags and on demand),
for the full SDK result.

## Trial builds

Run the Release workflow by hand (Actions, Release, Run workflow) to build and
package everything without publishing; the archives are kept as workflow
artifacts. The release job is skipped unless the run was started by a tag. The
CI workflow's mcu job also builds all firmware on every push and pull request.

## Withdrawing a firmware build

When a published build for a board turns out to be harmful: release the fix, delete that board's archive from the
earlier releases, add a warning to their notes, and list the board in `WITHDRAWN_BEFORE` in
`.github/scripts/build-web-flasher.py`, so the browser installer stops carrying the old builds forward (it keeps its
own copies). The tags stay.
