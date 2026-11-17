# Source and compatibility provenance

The implementation and C tests were developed as an independent C11 protocol
library. Protocol source files use the C standard library, with OpenSSL 3 C APIs
by default or the optional portable backend described below. Optional
Buffer/Resource compression uses BZip2. POSIX I/O is a separate target.
No Python, Go or Rust stack is linked into the runtime library or installed SDK.

| Reference | Exact snapshot | Use |
| --- | --- | --- |
| Reticulum/RNS 1.5.5 | e40191b3d193b46b7f2d8a44424a594cd758839b | Protocol behavior/byte layouts, optional unmodified Channel.py direct/routed live oracle, Resource/service/security differential fixtures and shared-instance RPC process check. |
| Supplied Reticulum Manual, Release 1.5.5, September 29 2026 | PDF SHA-256 33ad80f0f831c7eab91ee31c4ad21fc1cd573656d23de7c882bcfed1d4534584 | Link/channel/API documentation, reviewed as extracted text. The PDF and extracted manual are not bundled here. |
| Leviculum | 395edd42fbbffcdfb438fcd80afa17668459d331 | Specification prose/vector snapshot and optional unmodified C-API live oracle. |
| Vector generator's recorded RNS 1.3.5 | d5e62d4e15c5fe2e170f7bd9e120551671f21a27 | Source identified by the external frozen-vector generator. Older vectors support only the implemented constructions. |

The unit tests embed selected expected cryptographic/packet/announce byte values
from the Leviculum specification vectors, with deterministic inputs reproducing
the documented RNG stream. They do not bundle the external generator or stack.
Passing a frozen vector is not live interoperability certification.

Reference sources:

- [RNS pinned source](https://github.com/markqvist/Reticulum/tree/e40191b3d193b46b7f2d8a44424a594cd758839b)
- [Leviculum pinned source](https://codeberg.org/Lew_Palm/leviculum/src/commit/395edd42fbbffcdfb438fcd80afa17668459d331)
- [Leviculum vector dataset](https://codeberg.org/Lew_Palm/leviculum/src/commit/395edd42fbbffcdfb438fcd80afa17668459d331/docs/src/appendix/reticulum/vectors/vectors.json)

External oracle checkouts/libraries retain their own licenses and are not
redistributed by this repository. OpenSSL and BZip2 retain their own licenses. The MIT
license in this repository covers this project's source; it does not relicense
any external reference project or dependency.

## Vendored third-party code

`src/third_party/monocypher/` holds Monocypher 4.0.2
(https://github.com/LoupVaillant/Monocypher, tag 4.0.2), unmodified:
`monocypher.c/.h` and the optional `monocypher-ed25519.c/.h`. It is dual licensed
(2-clause BSD or CC-0); the full text is in `src/third_party/monocypher/LICENSE`.
It is compiled only into the optional `-DRNC_CRYPTO=portable` backend, which uses it
for X25519 and Ed25519 (including its SHA-512). SHA-256, HMAC, HKDF and AES-256-CBC
for that backend are original code in `src/crypto_portable.c`.

## Browser firmware installer (`web/`)

The browser application is separate from the C runtime and installed SDK. Its
nRF52840 uploader in `web/src/nrf-dfu.js` adapts the legacy serial DFU protocol
and timing described by Adafruit's `Adafruit_nRF52_nrfutil`
`nordicsemi/dfu/dfu_transport_serial.py`, and uses Liam Cottle's browser
implementation as a reference. The inspected browser reference was
[`liamcottle/rnode-flasher` at `678b1e3aa7ec0f9f4cd8bdb206e1b9d1cd9761c1`](https://github.com/liamcottle/rnode-flasher/tree/678b1e3aa7ec0f9f4cd8bdb206e1b9d1cd9761c1),
specifically `js/nrf52_dfu_flasher.js` (MIT, copyright 2024 Liam Cottle).
Nordic Semiconductor's copyright 2015 BSD 3-clause notice for the protocol
reference and Cottle's MIT notice are retained in
[`web/public/nrf-dfu-license.txt`](web/public/nrf-dfu-license.txt).

This uploader implements application-only legacy DFU for Adafruit nRF52
bootloaders, including HCI/SLIP framing, CRC16 and acknowledgement checks. It
does not implement Nordic Secure DFU or install a bootloader or SoftDevice.
The reference browser application's other bundled libraries are not copied
into this application; the dependencies below are installed through npm.

| Dependency | Pinned version | Use and license |
| --- | --- | --- |
| Espressif esptool-js | 0.5.7 | ESP32/ESP32-S3 serial bootloader and flash verification; Apache-2.0. The application wraps serial cleanup and reset behavior in `web/src/flash.js`. |
| JSZip | 3.10.1 | Read application-only nRF52 DFU ZIP packages; dual licensed MIT or GPL-3.0-or-later, usable under the MIT option. |
| SparkMD5 | 3.0.2 | Compute the MD5 values esptool-js uses to verify flash contents; package declares WTFPL or MIT, with the WTFPL v2 text retained in the notices. |

Exact npm versions, transitive dependencies and archive integrity hashes are
recorded in [`web/package-lock.json`](web/package-lock.json). Direct dependency
license texts and the DFU reference notices are retained in
[`web/public/THIRD_PARTY_NOTICES.txt`](web/public/THIRD_PARTY_NOTICES.txt), which
Vite copies into the published site along with `nrf-dfu-license.txt`. These
dependencies and reference notices retain their own license terms; this
repository's MIT license does not replace them.

## LoRa radio support (`mcu/radio/`): what was taken from the RNode firmware

The over-the-air format of the LoRa interface, the modem settings and the board pin maps
were established by reading the RNode firmware (https://github.com/markqvist/RNode_Firmware,
GPL-3.0, shallow clone of the default branch taken on 2026-10-28 into a scratch directory
outside this repository) AS A SOURCE OF FACTS. Taken, as facts
only: the header byte layout (random sequence nibble in bits 7..4, split flag in bit 0,
other bits zero); the frame limits (255 bytes per frame, MTU 508, split at 254 packet
bytes) and the receiver's rule for pending halves; the sync words (SX127x 0x12, SX126x
0x1424 in registers 0x0740/0x0741); explicit header, CRC on, standard IQ; the preamble
targets (24 ms, 6 ms above 30 kbit/s, floor 18 symbols; the SX127x register holds the count
minus 4); the integer low data rate rule; the bit rate formula; the CSMA slot (12 symbols,
24 to 100 ms, 6 ms minimum above 30 kbit/s) and DIFS (two slots); the airtime accounting
period (one hour) and the unit of the airtime limit commands (hundredths of a percent);
register addresses and values that the datasheet erratas call for (0x0736 bit 2, 0x0889
bit 2, 0x08D8, 0x08AC, 0x08E7 setting 0x28); the TCXO voltage code per board; whether DIO2
drives the antenna switch per board; board pin numbers and chip variants; the AXP192 LDO2
use on the original T-Beam. No source code, no comments and no identifiers were copied or
translated from that firmware, and no file of it is in this repository or its releases.
The radio drivers were written independently from those facts and from the public
Semtech documents (SX1261/2 and SX1276/77/78/79 data sheets, AN1200.13); the later
AXP2101 helper has the additional source of facts described below. Facts that could
not be established from the source are listed under "Not established" in
`mcu/radio/README.md`. The RNode firmware keeps its own licence.

RNode firmware commit read: 56775c51b60a6190242e324c210997dcc7637e53.

The unmodified reference `RNodeInterface.updateBitrate` (RNS 1.5.5, the snapshot above) is
called by `mcu/tests/ref_rnode_bitrate.py` for a comparison test (only with
`RNC_INTEROP_TESTS`); it is not redistributed.

The T-Beam Supreme SX1262 addition uses AXP2101 register-layout and voltage
encoding facts from XPowersLib's AXP2101 definitions for the independent
`mcu/radio/rnc_axp2101.h` helper: chip ID 0x4a, ALDO3 voltage register 0x94,
500 mV plus 100 mV per step, and enable bit 2 in register 0x90. The helper sets
only the radio's ALDO3 rail to 3.3 V and checks the writes. This attribution is
separate from the earlier RNode firmware snapshot; XPowersLib is not linked or
vendored by this implementation.
