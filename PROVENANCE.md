# Source and compatibility provenance

The implementation and C tests were developed as an independent C11 protocol
library. Protocol source files use the C standard library and OpenSSL 3 C APIs;
optional Buffer/Resource compression uses BZip2. POSIX I/O is a separate target.
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
