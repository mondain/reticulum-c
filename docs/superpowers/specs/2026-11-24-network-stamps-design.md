# Network stamps and the RNS 1.6.x re-pin: design

Status: draft for approval. Nothing in this document has been built.

## Intent and why

reticulum-c is pinned to Reticulum (RNS) 1.5.5 (`e40191b3d193b46b7f2d8a44424a594cd758839b`).
Upstream is at 1.6.1 (`cff4d03fdbd6bfb63b765280cd944756ac5cce8d`, released 2026-11-18). RNS 1.6.0
added proof-of-work "network stamps" to three wire primitives, 1.6.1 turned stamp emission on by
default, and 1.6.2 will turn enforcement on: announces, path requests and link requests that do
not carry a sufficient stamp will be dropped by enforcing nodes.

Nodes still on 1.5.x are carried through by stamp-aware nodes, but cannot be reached by, or get
paths from, nodes that enforce. `reticulum-c-node` and every MCU board in this repository would
fall in that group. The goal is to be a full participant in a 1.6.x network before 1.6.2 ships,
and to keep the oracle that all interop claims rest on current.

The user also wants the microcontroller boards to do as little proof-of-work as possible:
stamps for a board are computed elsewhere and loaded onto it through the flasher or console.

## Goals

1. Re-pin the reference oracle, provenance and gap list to RNS 1.6.1, and make every existing
   interop test pass against it.
2. Verify stamps on announces, path requests and link requests, with the reference's three
   independent enforcement switches and its default (verify, do not enforce).
3. Emit stamps from the host node: destination (announce) stamps, path-request stamps and
   link-request stamps, so that a host node reaches an enforcing network.
4. Let a board announce with a destination stamp that was computed off-board and loaded through
   the console, the web flasher or `reticulum-c-flash`, with a board doing no stamp search itself.
5. Bit-exact agreement with the reference: cost encoding, fractional cost arithmetic, material,
   wire layout, checked by differential tests against the unmodified reference.

## Non-goals

- Identity stamps (`Identity(value=n)`, a stamp carried inside the keyset). They add no wire
  bytes and nothing verifies them on the network yet. Follow-up.
- Flipping enforcement on by default. The defaults track the pinned reference: 1.6.1 verifies
  and emits, and does not enforce. When the pin moves to a version that enforces by default, a
  separate change moves ours.
- Reference 1.6.x changes with no wire effect: the SQLite storage backend, path-table sharding
  and culling, filtering and hop-limiter options, `rnstatus` additions, `client_limit`,
  `blocked_ips`. They are inventoried in the re-pin step; any that change what is sent or
  accepted on the wire are fixed, the rest are listed in the gap list as open.
- On-board stamp generation, on-board path-request or link-request stamping (a board does not
  initiate links or path requests of its own today).
- Windows and Android specifics of stamp worker pools.

## Anti-goals (failure even if it technically works)

- Interop with 1.5.x peers gets worse. A stamped announce must still be accepted and relayed by
  1.5.5 and by this code with stamps switched off.
- A node starts emitting and then stalls: announces must not be held indefinitely waiting for a
  stamp search, and a slow stamp must not block the event loop.
- A board's announces become invalid after a reflash: a stamp is bound to the identity, so a
  board whose identity changed must notice and not emit a stamp that fails verification.

## Reference behavior being matched (read from 1.6.1)

Constants and costs. Costs are fractional, carried as 8-bit fixed point (`COST_FP_BITS` 8). The
256-entry mantissa table `TAB`, `MANTISSA_BITS` 33 and its digests are copied from
`RNS/Stamps.py` and verified by the same digest assertions. A cost is capped at 100
(`STAMP_COST_CAP`), link cost at 40 (`LINK_COST_CAP`). Stamp size is 14 bytes.

Validity of a stamp: `SHA-256(workblock || stamp)`, as a 256-bit integer, must not exceed a
target derived from the fixed-point cost (`target_from_fp`). For announces and path requests the
workblock is the material itself, with no expansion (`expand_rounds=0`). Stamp value is the
fixed-point leading-zero measure in `stamp_value`.

| Primitive | Material | Cost | Where carried |
| --- | --- | --- | --- |
| Destination (announce) | `destination_hash \|\| public_key \|\| name_hash` | `DESTINATION_COST` default 23.5 required of others; emitted at `DESTINATION_VALUE` 25.0 | last 18 bytes of the announce app data: `0xC1`, flags byte, 14 byte stamp, 2 cost bytes |
| Path request | `destination_hash \|\| tag` | `PR_COST` 15.8, emitted at `PR_VALUE` 15.8 | after the 3 x 16 byte request: `0xC1`, flags, 14 byte stamp (64 bytes total; 48 and the legacy 32 still accepted) |
| Link request | `destination_hash \|\| peer_signature_public_key` | the cost the destination announced (default `LR_COST` 12.5, cap 40) | the X25519 public key in the link request is itself the stamp: the initiator grinds ephemeral X25519 keys until `SHA-256(material \|\| public_key)` meets the cost |

The announce extension sits inside the signed app data, is removed before the application sees
app data when it validates, and the trailing two bytes carry the destination's link request cost
(integer in the last byte, its MSB reserved, fraction in the byte before). A stamp-unaware node
simply sees 18 more bytes of app data.

Switches (all in `[stamps]` of the reference config, plus two constructor flags):
`enforce_stamps` (announces and link requests together), `stamp_destinations`, `stamp_prs`,
`always_stamp_lrs`, `destination_cost`, `destination_value`, `pr_cost`, `pr_value`, `lr_cost`,
`lr_stamp_timeout`, `pr_stamp_timeout`, worker count and niceness. The interface-level
`destination_cost` and `pr_cost` override the global values per interface. Defaults in 1.6.1:
verify on, enforcement off, emission on, link request stamps off unless the destination
announced a cost.

Behavior to keep: a destination stamp is generated once, persisted, and reused; an announce that
needs a stamp that does not exist yet is queued and emitted when ready; a path request stamp is
cached (256 entries) and generation has a 15 s timeout, after which the request is cancelled;
a link whose stamp generation fails or times out is torn down with reason `STAMP_FAILURE`
(0x04).

## Constraints

- The library already has integer-cost stamp primitives (`src/stamp.c`, used by interface
  discovery, 32 byte stamps over an expanded workblock). The new stamps differ (fractional cost,
  14 byte stamps, unexpanded workblock, stamped keys), so they are new functions beside the old
  ones. The discovery behavior must not change.
- Two crypto backends (OpenSSL and the portable Monocypher build used by the firmware) both need
  the stamped X25519 key search.
- MCU memory: the board build has a small RAM budget (`tests/footprint.c`, limit 96 KB). The
  verification code and the 256-entry table (about 2 KB) are acceptable. No board may do a
  stamp search.
- Code must stay C11, within the existing style and test harness; host-only code (threads) stays
  out of the library core.

## Approaches considered

1. Verify only, emit later. Smallest. Leaves the host unreachable once enforcement is on.
2. Host first, boards verify only. Full parity on the host, boards verify and relay.
   Chosen as the base. Extended per the decision below.
3. Everything at once, boards generating stamps themselves. An nRF52840 would grind about 2^25
   hashes for the destination stamp; I have not measured it and expect it to be minutes to
   tens of minutes. Rejected in favor of precomputation, which is cheaper on the board and gets
   to the same wire result.

Chosen: approach 2, with board stamps precomputed off-board and loaded (this document's
decision), delivered in the steps below.

## Design

### Step 1: re-pin to 1.6.1

Update `PROVENANCE.md`, `.github/workflows/rns-interop.yml` (the oracle checkout hash),
`docs/spec-gap-list.md` baseline and the README claims to 1.6.1. Run the whole interop suite
against 1.6.1 and fix what changed. Produce an inventory of 1.6.0 and 1.6.1 differences from the
diff of `Transport.py`, `Identity.py`, `Destination.py`, `Link.py`, `Packet.py`, `Resource.py`
and the interfaces, each classified as wire-relevant (fix now), local behavior (list as a gap)
or irrelevant. Bidirectional tunnel synthesis with stamp cost and version signalling is
wire-relevant and is the likeliest place for surprises.

### Step 2: stamp primitives (library)

New public header `rnc_netstamp.h` and `src/netstamp.c`:

- cost encoding: `cost_to_fp`, `cost_to_bytes`, `cost_from_bytes`, `quantize_cost`;
- `target_from_fp`, `stamp_valid`, `stamp_value` over the table, as the reference does it,
  using 256-bit integer helpers in the library (no bignum dependency);
- stamp search for a given material and cost (host and test use);
- stamped X25519 key search for a given material and cost, in both crypto backends;
- stamped-announce extension builder and parser.

Tests: the reference computes vectors (costs, material, stamps, values, ext payloads) in CI; the
tests check that this code returns identical values and accepts and rejects the same stamps,
including boundary and fractional costs. Mutation cases flip bits in each field.

### Step 3: verification in the node

- Announces: parse the extension after the signature check, validate against the receiving
  interface's `destination_cost`, strip it from the delivered app data when valid, record the
  announced link request cost with the destination (recall), cache invalid announces by packet
  hash as the reference does. Enforcement off: unstamped and insufficiently stamped announces
  are still accepted. Enforcement on: they are dropped and counted as filtered on the interface.
- Path requests: accept the stamped (64), unstamped (48) and legacy (32) lengths; validate
  against the interface `pr_cost`; with enforcement on, drop failures. Reject longer than 64 as
  a protocol violation, as the reference does.
- Link requests: validate the stamp in the initiator's key against the cost this destination
  announces; with link request enforcement on, refuse.
- Configuration in `reticulum-c-node` (`[stamps]` section with the reference's option names, and
  `destination_cost`/`pr_cost` on interfaces), also in `--exampleconfig`, `--check`, and the
  management RPC where interface fields are reported.

### Step 4: emission from the host node

- Destination stamps: a worker pool (count and niceness configurable) searches in the
  background; the result is persisted beside the destination's state and reused; an announce
  waits in a bounded queue and is sent when the stamp is ready, with the reference's priority
  (path responses before ordinary announces) and drop-with-log when the queue is full.
- Path-request stamps: generated per request with a 256 entry cache and a timeout; on failure
  the request is cancelled and logged.
- Link request stamps: when the destination's announced cost is non-zero (or
  `always_stamp_lrs`), the initiator searches for a stamped ephemeral key before sending, with a
  timeout; failure ends the link with `STAMP_FAILURE`. Our own destinations announce the
  default link cost and verify inbound link requests when link request enforcement is on.
- Emission switches as in the reference. Workers live in `examples/` or a host-side module, not
  in the library core.

### Step 5: precomputed stamps for boards

A board does no stamp search. The destination stamp depends only on public data
(destination hash, public key, name hash), not on the private key, so any machine can compute it.

- Console: a read command prints the stamp material for the board's destination as hex, and the
  board's current stamp status (none, loaded and valid, loaded and stale). A set command takes a
  28 hex digit stamp, checks it with one hash against the board's own material and the
  configured destination value, and stores it in the same place as the identity (survives
  reboot; erased with the identity).
- Tool: `reticulum-c-flash` and the browser flasher gain a "stamp this board" action: read the
  material from the console, compute the stamp on the host at the configured value, set it. The
  web flasher computes in workers with its own SHA-256 (see "Decided: where stamps are computed").
- Board behavior: with a valid stamp, announces carry the extension (adding 18 bytes) and the
  announced link request cost; without one, announces are unstamped as today. If the identity is
  regenerated, the stored stamp no longer verifies and is dropped on boot with a console notice.
- Boards verify announces, path requests and link requests with the Step 3 code, subject to the
  RAM check. They never search.
- Ship: the board's emitted destination value defaults to the reference's value (25.0). The
  host-side cost of computing it is a few seconds to a minute on a PC; the tool shows progress.

### Step 6: evidence

- Differential vector tests (Step 2) run in the existing interop workflows against the 1.6.1
  oracle.
- Process tests: `reticulum-c-node` against an unmodified 1.6.1 `rnsd` with enforcement on:
  announce passes, path request passes, link opens, and the negative cases (no stamp, stamp too
  low, wrong material) are dropped, each in both directions.
- Hardware: a board with a loaded stamp announced over LoRa and accepted by an enforcing 1.6.1
  node; the same board without a stamp is rejected by the enforcing node and accepted by a
  non-enforcing one.
- Update `docs/spec-gap-list.md`, `COMPATIBILITY.md`, `README.md` and the MCU README, and the
  manual's configuration reference.

## Decisions made by the user

- Approach 2 (host first), re-pin first, as above.
- The browser flasher also computes stamps (workers, JavaScript SHA-256), not only the CLI; stamps cannot be precomputed because they are bound to each board's public key.
- Board stamps are precomputed and loaded through the flasher or console, so a board does
  minimal processing.

## Calls made by the author (for review)

- Defaults follow the pinned reference at each pin: verify on, enforcement off, emission on.
- New functions live beside the discovery stamp code, not replacing it.
- The 1.6.x re-pin inventories non-wire changes and lists them, rather than implementing them.
- Identity stamps are a follow-up.
- The board console stores one stamp: a board announces a single destination
  (`rnc_node_add_destination` once, no app data). A stamp that no longer verifies against the
  board's current identity is erased on boot with a console notice, and the status then reads
  "none".
- Library announce API: the core never waits and never searches. A host module fills a stamp
  store with `rnc_node_set_destination_stamp`. `rnc_node_announce` sends the stamp when the store
  has one. When stamping is required and none is stored it returns `RNC_AGAIN` and the host
  daemon queues and retries; when stamping is not required (the board default) it sends
  unstamped, as today.
- App data limit: destination app data is limited to 316 bytes today, and the 18 byte extension
  counts against it. If app data plus extension would exceed it, the announce is sent without
  the extension and a warning is logged, so existing announces (including interface discovery
  data) keep working.
- Step 1 is its own merge and is gated on the existing interop suite passing against 1.6.1,
  with known non-wire failures allowed if recorded in the gap list. Wire-relevant 1.6.x changes
  found there (tunnel synthesis with stamp cost and version signalling) stay in this project.
- Board verification: boards verify and accept and relay as today, with enforcement off. There
  is no console enforcement option yet. The 96 KB footprint baseline is rechecked after Step 3
  and updated if the table and verifier need it.

## Decided: where stamps are computed

Revised after approval, at the user's request. Board stamps are computed in two places, with
the same result: `reticulum-c-flash` (native, the reference implementation for testing) and the
browser flasher. A stamp cannot be shipped precomputed, because it is bound to the board's own
public key (each board generates its identity on first boot); pre-generated identities would
mean the distributor knows the private keys, so that approach is rejected.

The browser flasher runs the search in Web Workers (one per available core, capped at 8) with a
hand-written JavaScript SHA-256 over typed arrays (Web Crypto's per-call async digest is far too
slow for about 2^25 trials). It needs no new toolchain; a WASM build is a later optimization.
The flow is one action, "Stamp this board": read `stamp.material` from the console, search at
the board's destination value (25.0 by default) with progress shown, set the stamp, and display
`stamp.status`. The search is cancellable. The cost arithmetic (fixed-point costs and the
256-entry table, with 256-bit comparison via BigInt) is ported to JavaScript and must agree
with the C library, checked by test: the table is compared with `src/netstamp_tab.h`, and
stamps are cross-validated in both directions (C-found stamps pass the JavaScript check and
the reverse). Speed is unmeasured; if a search proves impractically slow on common hardware,
the page shows the CLI command instead of failing silently.

## Left to the builder

- Internal data structures (stamp queue, caches), thread pool implementation, file format for
  the persisted destination stamp (a small versioned record is expected).
- The exact console command names and flasher button wording.
- Test vector formats.
- Performance tuning of the 256-bit comparison and the stamped key search.
