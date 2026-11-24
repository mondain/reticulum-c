# Network stamps and RNS 1.6.x re-pin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make reticulum-c a full participant in an RNS 1.6.x network: verify and emit network stamps on announces, path requests and link requests, with board stamps computed off-board and loaded through the console.

**Architecture:** A new library module `netstamp` (fixed-point cost arithmetic, stamp and stamped-key search, announce extension codec) beside the untouched discovery stamps. The node verifies stamps in its existing announce, path-request and link-request paths and holds a per-destination stamp store that a host module fills. `reticulum-c-node` owns the workers that search; boards only verify and carry one loaded stamp.

**Tech Stack:** C11, CMake/CTest, OpenSSL and portable (Monocypher) crypto backends, PlatformIO firmware, Python 3 for the reference oracle, JavaScript for the web flasher.

**Spec:** `docs/superpowers/specs/2026-11-24-network-stamps-design.md` (approved). Read it first.

## Global Constraints

- Reference oracle: RNS 1.6.1, `cff4d03fdbd6bfb63b765280cd944756ac5cce8d` (replaces 1.5.5 `e40191b3d193b46b7f2d8a44424a594cd758839b`).
- Stamp size 14 bytes; `STAMP_COST_CAP` 100; `LINK_COST_CAP` 40; costs are 8-bit fixed point (`COST_FP_BITS` 8, `MANTISSA_BITS` 33, 256-entry `TAB`, digests asserted as in `RNS/Stamps.py`).
- Defaults follow 1.6.1: verify on, enforcement off, emission on. `DESTINATION_COST` 23.5, `DESTINATION_VALUE` 25.0, `PR_COST` 15.8, `PR_VALUE` 15.8, `LR_COST` 12.5, `LINK_STAMP_TIMEOUT` 15 s, `PR_STAMP_TIMEOUT` 15 s, path request stamp cache 256 entries.
- Announce extension: last 18 bytes of app data: `0xC1`, flags `0x00`, 14 stamp bytes, two cost bytes (fraction byte, then integer byte with MSB reserved). Material: `destination_hash || public_key || name_hash`; no workblock expansion.
- Path request: 48 bytes unstamped, 64 stamped (`0xC1`, flags, 14 bytes), legacy 32 still accepted, longer than 64 is a protocol violation. Material `destination_hash || tag`.
- Link request: the 32-byte X25519 public key is the stamp; material `destination_hash || peer_signature_public_key`; failure tears down with `STAMP_FAILURE` (0x04).
- Destination app data limit 316 bytes counts the 18-byte extension; if it does not fit, send without the extension and log a warning.
- Discovery stamps (`src/stamp.c`, `rnc_stamp.h`) must not change behavior.
- Boards never search for stamps; one stored stamp, erased at boot if it no longer verifies; web flasher shows material and accepts a stamp but does not compute.
- C11, existing style, no new dependencies. Library core has no threads. Never commit with the Claude tagline, no emoji in commit messages. Docs are Markdown.
- A merge needs the user's explicit approval; code PRs need all CI green. Never `pkill -f`.

## Review Focus

- A 1.5.5-style peer receives a stamped announce: it must still accept and relay it (the extension is just app data).
- An announce whose app data plus 18 bytes would exceed 316 bytes: sent unstamped with a warning, never truncated or dropped.
- A stamp that is valid at cost 15.8 but checked at 15.9: fractional boundaries accept and reject exactly as the reference does.
- A board whose identity was regenerated still holds a stamp: it is erased at boot, the board announces unstamped, and nothing crashes.
- A path request of an unexpected length (33 to 47, 49 to 63, over 64): handled as the reference does (protocol violation or ignore), never a read past the buffer.

---

## File map

- Create: `include/reticulum_c/rnc_netstamp.h`, `src/netstamp.c`, `src/netstamp_tab.h`, `tests/test_netstamp.c`, `tests/netstamp_reference.py`, `docs/superpowers/notes/rns-1.6-inventory.md`
- Create (host): `examples/node_stamper.h` (worker pool, persistence, queues)
- Modify: `src/node.c`, `src/link.c`, `include/reticulum_c/rnc_node.h`, `CMakeLists.txt`, `examples/node_daemon.c`, `examples/reticulum_flash.c`, `mcu/app/rnc_mcu_net.h`, `mcu/app/rnc_mcu_app.c`, `web/src/*` (stamp field), `PROVENANCE.md`, `.github/workflows/rns-interop.yml`, `docs/spec-gap-list.md`, `COMPATIBILITY.md`, `README.md`

---

### Task 1: Re-pin the oracle to 1.6.1 and baseline the suite

**Files:**
- Modify: `PROVENANCE.md`, `.github/workflows/rns-interop.yml:19-22`, `docs/spec-gap-list.md` (baseline lines), `README.md` (any "1.5.5" claim)
- Create: `docs/superpowers/notes/rns-1.6-inventory.md`

**Interfaces:**
- Produces: a list of failing interop tests and a classified 1.6.0/1.6.1 difference inventory that Task 2 consumes.

- [ ] **Step 1:** Check out RNS `cff4d03fdbd6bfb63b765280cd944756ac5cce8d` into a scratch directory and point `RNC_INTEROP_PYTHONPATH` at it (the `rns-interop.yml` steps show how).
- [ ] **Step 2:** Run the full suite against it: `ctest --test-dir build -R "rns|interop" -j4 --output-on-failure`. Record every failure verbatim in the inventory file.
- [ ] **Step 3:** Diff `Transport.py`, `Identity.py`, `Destination.py`, `Link.py`, `Packet.py`, `Resource.py`, `Interfaces/` between `e40191b3` and `cff4d03f`. In the inventory, classify each change as wire-relevant, local behavior, or irrelevant. Bidirectional tunnel synthesis with stamp cost and version signalling is expected to be wire-relevant.
- [ ] **Step 4:** Update `PROVENANCE.md`, `rns-interop.yml` (name and hash), the gap list baseline and README claims to 1.6.1.
- [ ] **Step 5:** Commit: `git commit -m "Re-pin the RNS oracle to 1.6.1 and inventory the changes"`.

### Task 2: Fix wire-relevant 1.6.x breakage (its own PR)

**Files:** as the Task 1 inventory dictates (expected: `src/node.c` tunnel synthesis, `src/host_posix.c`); tests beside each fix.

**Interfaces:**
- Consumes: Task 1 inventory.
- Produces: the existing interop suite green against 1.6.1, except failures recorded in `docs/spec-gap-list.md` as non-wire.

- [ ] **Step 1:** For each wire-relevant item, write a failing test that reproduces the reference behavior (process test against the 1.6.1 oracle where one exists). Name it `reticulum_<area>_rns161_<case>`.
- [ ] **Step 2:** Run it, confirm it fails for the stated reason.
- [ ] **Step 3:** Implement the fix. Tunnel synthesis must send and accept the 1.6.1 stamp-cost and version fields.
- [ ] **Step 4:** Run the whole suite against 1.6.1; green except recorded non-wire gaps.
- [ ] **Step 5:** Open the PR for Tasks 1-2 and wait for the user's merge approval. Steps below build on this merge.

### Task 3: Fixed-point cost arithmetic

**Files:**
- Create: `include/reticulum_c/rnc_netstamp.h`, `src/netstamp.c`, `src/netstamp_tab.h`, `tests/test_netstamp.c`
- Modify: `CMakeLists.txt` (add `src/netstamp.c` to the library sources near line 62; add `test_netstamp` beside `test_stamp` at line 210, cases registered like `reticulum_stamp_${case}`)

**Interfaces:**
- Produces (all in `rnc_netstamp.h`):
  - `#define RNC_NETSTAMP_SIZE 14u`, `RNC_NETSTAMP_COST_CAP 100`, `RNC_NETSTAMP_LINK_COST_CAP 40`
  - `uint16_t rnc_netstamp_cost_to_fp(double cost)`; `double rnc_netstamp_cost_from_fp(uint16_t fp)`
  - `void rnc_netstamp_cost_to_bytes(double cost, uint8_t out[2])` (integer byte, then fraction byte); `double rnc_netstamp_cost_from_bytes(const uint8_t in[2])`
  - `double rnc_netstamp_quantize(double cost)`
  - `int rnc_netstamp_valid(const void *material, size_t material_size, const void *stamp, size_t stamp_size, double cost)`: 1 when SHA-256(material || stamp) is not above `target_from_fp(cost_to_fp(cost))`
  - `double rnc_netstamp_value(const void *material, size_t material_size, const void *stamp, size_t stamp_size)`

- [ ] **Step 1: Failing test** `test_netstamp.c` case `cost_encoding`: `cost_to_fp(23.5)==6016`, `cost_to_fp(0)==0`, `cost_to_fp(500)==100*256` (capped), `cost_to_bytes(12.5)` is `{12,128}`, `from_bytes` inverts it, `quantize(15.84)==15.84375`. Add case `table`: `src/netstamp_tab.h` digests match the reference's `TAB_DIGEST` `55ba3ce1df224895b0dfdc102eb4359fc2f5a7efefee68df0cc90c8a8ac24f48` and `PRM_DIGEST` check.
- [ ] **Step 2:** Run `ctest --test-dir build -R reticulum_netstamp -V`; expect link/compile failure.
- [ ] **Step 3:** Copy `TAB` (256 values, `MANTISSA_BITS` 33) exactly from `RNS/Stamps.py` into `src/netstamp_tab.h` as `static const uint64_t rnc_netstamp_tab[256]`. Implement `target_from_fp` as a 256-bit shift of `TAB[f] << i >> 33` using a small `uint8_t[32]` big-endian helper (no bignum dependency); implement `valid` and `value` on top, with `value` using the bisect-right mantissa rule from `stamp_value`.
- [ ] **Step 4:** Run the tests; expect PASS. Commit: `Add network stamp cost arithmetic`.

### Task 4: Stamp and stamped-key search

**Files:** Modify `include/reticulum_c/rnc_netstamp.h`, `src/netstamp.c`, `tests/test_netstamp.c`.

**Interfaces:**
- Consumes: Task 3.
- Produces:
  - `rnc_result rnc_netstamp_find(const void *material, size_t material_size, double cost, rnc_random_fn random, void *random_context, uint64_t max_attempts, uint8_t stamp[RNC_NETSTAMP_SIZE], uint64_t *attempts)` (RNC_TIMEOUT when exhausted)
  - `rnc_result rnc_netstamp_find_key(const void *material, size_t material_size, double cost, rnc_random_fn random, void *random_context, uint64_t max_attempts, uint8_t private_key[32], uint8_t public_key[32], uint64_t *attempts)` (X25519 pairs via `rnc_x25519_public`)
  - no cancel callback: callers bound work with `max_attempts` and call repeatedly in slices.

- [ ] **Step 1: Failing tests** `find_low_cost`: find at cost 8.0 with a fixed-seed RNG, `rnc_netstamp_valid` accepts; `find_key_low_cost`: the returned public key validates and equals `rnc_x25519_public(private)`; `find_exhausted`: `max_attempts=1` at cost 40 returns RNC_TIMEOUT and leaves outputs untouched.
- [ ] **Step 2:** Run, expect failure.
- [ ] **Step 3:** Implement both. The stamp search starts at a random 14-byte value and counts up (as `rnc_stamp_generate` does); the key search draws fresh 32-byte private keys. Hash with `rnc_sha256_init/update/final`, copying the material context once (`rnc_sha256_copy`) so each trial hashes only the stamp.
- [ ] **Step 4:** Run under both backends (`-DRNC_CRYPTO=portable` build too); PASS. Commit: `Add network stamp and stamped key search`.

### Task 5: Announce extension codec and material

**Files:** Modify `include/reticulum_c/rnc_netstamp.h`, `src/netstamp.c`, `tests/test_netstamp.c`.

**Interfaces:**
- Produces:
  - `#define RNC_NETSTAMP_EXT_SIZE 18u`
  - `void rnc_netstamp_announce_material(const uint8_t destination[16], const uint8_t public_key[64], const uint8_t name_hash[10], uint8_t out[90])`
  - `rnc_result rnc_netstamp_ext_build(const uint8_t stamp[RNC_NETSTAMP_SIZE], double link_cost, uint8_t out[RNC_NETSTAMP_EXT_SIZE])`
  - `typedef struct { uint8_t stamp[14]; double link_cost; size_t app_size; } rnc_netstamp_ext;` and `int rnc_netstamp_ext_parse(const uint8_t *app_data, size_t size, rnc_netstamp_ext *ext)` (1 and `app_size = size - 18` when marker `0xC1`, reserved MSB clear and `link_cost <= 100`; 0 otherwise, `ext` untouched)

- [ ] **Step 1: Failing tests:** `ext_roundtrip` (build with cost 12.5 then parse returns the stamp, 12.5, `app_size` unchanged); `ext_rejects` (wrong marker, reserved MSB set, cost above cap, size under 18, all return 0); `ext_with_app_data` (10 bytes of app data plus extension parse back to `app_size==10`).
- [ ] **Step 2:** Run, expect failure. **Step 3:** Implement; cost bytes are written fraction first then integer (`bytes([cost_bytes[1], cost_bytes[0]])` in `Destination._announce`). **Step 4:** PASS. Commit: `Add the stamped announce extension codec`.

### Task 6: Differential vectors against the 1.6.1 reference

**Files:** Create `tests/netstamp_reference.py`; Modify `tests/test_netstamp.c`, `CMakeLists.txt` (register `reticulum_netstamp_reference` only when the oracle is configured, like the other `*_rns` tests).

**Interfaces:**
- Consumes: Tasks 3-5. The Python script prints JSON lines: `{cost, material_hex, stamp_hex, valid, value, ext_hex}` computed with `RNS.Stamps`.

- [ ] **Step 1:** Write the script: for 40 cost values including 0, 0.5, 12.5, 15.8, 15.84375, 23.5, 25, 99.99, 100 and for each a stamp the reference generates (low costs for speed) plus mutated stamps (one flipped bit in each byte), emit the reference's `stamp_valid` and `stamp_value`.
- [ ] **Step 2:** Add C test `reference_vectors` that reads the lines on stdin (script piped through the test runner as other `*_rns` tests do) and asserts identical `valid` and `value` (value compared as double to 1e-9) and identical `ext` bytes.
- [ ] **Step 3:** Run with the oracle; expect PASS. Any mismatch is a bug in Task 3: fix there. Commit: `Check network stamp arithmetic against the reference`.

### Task 7: Verify stamps on announces

**Files:** Modify `src/node.c` (`announced()` at ~line 1440, the stored route and recall record), `include/reticulum_c/rnc_node.h`, `tests/test_node.c`.

**Interfaces:**
- Consumes: `rnc_netstamp_ext_parse`, `rnc_netstamp_announce_material`, `rnc_netstamp_valid`.
- Produces in `rnc_node.h`:
  - `typedef struct rnc_stamp_policy { int enabled; int enforce_announces; int enforce_link_requests; double destination_cost; double pr_cost; } rnc_stamp_policy;` (defaults: enabled 1, enforce 0, 23.5, 15.8)
  - `void rnc_node_set_stamp_policy(rnc_node *node, const rnc_stamp_policy *policy)`; `rnc_result rnc_node_set_interface_stamp_costs(rnc_node *node, uint32_t interface_id, double destination_cost, double pr_cost)` (negative means "use global")
  - the recalled destination record gains `double link_cost` (negative when the announce had no valid stamp); `rnc_node_recall` returns it.
  - a counter `filtered_announces` per interface, exposed where interface statistics already are.

- [ ] **Step 1: Failing tests** in `tests/test_node.c`: `stamp_announce_accept_unenforced` (unstamped and badly stamped announces are accepted, relayed, `link_cost<0`); `stamp_announce_valid` (valid stamp at cost 8 with `destination_cost=8`: app data delivered without the 18 bytes, `link_cost==12.5` recalled); `stamp_announce_enforced_drop` (enforce on: no stamp and low stamp both dropped, `filtered_announces` counts 2, nothing relayed); `stamp_announce_per_interface` (interface cost overrides global).
- [ ] **Step 2:** Run; expect failure.
- [ ] **Step 3:** In `announced()` after `rnc_announce_verify`: when `policy.enabled`, call `ext_parse` on `a.app_data`; validate against the ingress interface's effective `destination_cost`; strip the extension from `a.app_data`/`a.app_size` when valid; apply the enforcement switch. Relay the original packet bytes unchanged. Cache invalid outcomes by packet hash, bounded to the existing small caches.
- [ ] **Step 4:** Run `ctest -R reticulum_node`; PASS. Commit: `Verify network stamps on announces`.

### Task 8: Path request stamps, verify and build

**Files:** Modify `src/node.c` (`rnc_path_request_create`, `rnc_path_request_decode`, request handling near line 1604), `include/reticulum_c/rnc_node.h`, `tests/test_node.c`.

**Interfaces:**
- Produces: `rnc_result rnc_path_request_create_stamped(const uint8_t destination[16], const uint8_t transport_id[16], const uint8_t *tag, size_t tag_size, const uint8_t stamp[RNC_NETSTAMP_SIZE], rnc_packet *packet)`; `rnc_path_request` gains `int has_stamp` and `uint8_t stamp[14]`; the material is `destination || tag`.

- [ ] **Step 1: Failing tests:** `pr_lengths` (48, 64 and legacy 32 accepted; 33, 47, 49, 63 and 65 handled per reference: protocol violation for over 64, ignored-as-unstamped otherwise, never read past the end); `pr_stamp_valid`; `pr_enforced_drop` (no stamp and low stamp dropped when `enforce_announces`, counted); `pr_unenforced_answers_anyway`.
- [ ] **Step 2:** Run, expect failure. **Step 3:** Implement decode of the 2 + 14 byte extension and validation against `pr_cost`; extend creation. **Step 4:** PASS. Commit: `Verify and build stamped path requests`.

### Task 9: Verify link request stamps

**Files:** Modify `src/link.c` (responder side where the request public key is read), `src/node.c`, `tests/test_link.c`.

**Interfaces:**
- Consumes: node policy `enforce_link_requests`; the owning destination's `link_cost` (new `rnc_node_set_destination_link_cost(rnc_node*, const uint8_t destination[16], double cost)`, default 12.5, 0 disables).

- [ ] **Step 1: Failing tests:** `lr_unstamped_accepted_when_not_enforced`; `lr_stamped_valid` (key found with `rnc_netstamp_find_key` at cost 8 over `destination || sig_pub` accepted at `link_cost=8`); `lr_enforced_refuses_unstamped`; `lr_cost_zero_accepts_all`.
- [ ] **Step 2-4:** Run to fail; implement the check on the 32-byte encryption public key before creating the responder link; PASS. Commit: `Verify link request stamps`.

### Task 10: Daemon configuration and reporting

**Files:** Modify `examples/node_daemon.c` (config parser near line 1036, `example_config` at ~2025, `--check`), `examples/node_rpc.h`, `tests/test_node_process.c`.

**Interfaces:**
- Consumes: Tasks 7-9 APIs.
- Produces: a `[stamps]` section with the reference's names: `enforce_stamps`, `stamp_destinations`, `stamp_prs`, `always_stamp_lrs`, `destination_cost`, `destination_value`, `pr_cost`, `pr_value`, `lr_cost`, `lr_stamp_timeout`, `pr_stamp_timeout`, `max_workers`, `worker_niceness`; interface keys `destination_cost` and `pr_cost`. Interface statistics report filtered announces and the effective costs.

- [ ] **Step 1: Failing test** in `test_node_process.c`: the sample config printed by `--exampleconfig` contains a `[stamps]` section, passes `--check`; `--check` rejects `destination_cost = 500` and a non-numeric cost.
- [ ] **Step 2-4:** Run to fail; implement parse, validation and clamping (costs 0..100, `lr_cost` 0..40, timeouts at least 0.02); add the section to `example_config` with defaults commented; PASS. Commit: `Add the [stamps] configuration to the node daemon`.

### Task 11: Destination stamp store and announce behavior

**Files:** Modify `src/node.c`, `include/reticulum_c/rnc_node.h`, `tests/test_node.c`.

**Interfaces:**
- Produces:
  - `rnc_result rnc_node_set_destination_stamp(rnc_node *node, const uint8_t destination[16], const uint8_t stamp[RNC_NETSTAMP_SIZE])` (verifies against the destination's material at the `destination_value` given to `rnc_node_set_stamp_emission`; RNC_AUTH if it does not verify)
  - `rnc_result rnc_node_set_stamp_emission(rnc_node *node, int required, double destination_value)`
  - `rnc_result rnc_node_destination_stamp_material(const rnc_node *node, const uint8_t destination[16], uint8_t out[90])`
  - `rnc_node_announce` returns `RNC_AGAIN` when `required` and no stamp is stored; sends the extension (with the destination's `link_cost`) when a stamp is stored; if `app_size + 18 > 316`, sends without it and logs once.

- [ ] **Step 1: Failing tests:** `announce_with_stamp_carries_extension` (parse the emitted packet: extension valid, signature still verifies over app data including it); `announce_required_without_stamp_again`; `announce_not_required_sends_unstamped`; `announce_overlong_app_data_unstamped` (app data 300 bytes: sent, no extension, one warning); `set_stamp_rejects_invalid` (RNC_AUTH).
- [ ] **Step 2-4:** Run to fail; implement; PASS. Commit: `Add the destination stamp store and stamped announces`.

### Task 12: Host stamp workers and persistence

**Files:** Create `examples/node_stamper.h`; Modify `examples/node_daemon.c`, `tests/test_node_process.c`.

**Interfaces:**
- Produces in `node_stamper.h`: `stamper_start(config *c, rnc_node *n, const char *state_path)`, `stamper_request_destination(const uint8_t destination[16])`, `stamper_stop()`. Persistence: `<state>.stamps`, a versioned record per destination (magic, version, destination hash, 14-byte stamp, value, CRC); a stored stamp that no longer verifies is ignored.
- Behavior: a bounded queue (32), path-response announces first; a worker pool (`max_workers`, `worker_niceness`) searches in `rnc_netstamp_find` slices of 1<<20 attempts so shutdown and SIGHUP stay responsive; when found, `rnc_node_set_destination_stamp` then announce; persisted so restarts do not search again.

- [ ] **Step 1: Failing process tests:** `stamper_emits_announce` (daemon at `destination_value = 12`, reference `rnsd` peer receives an announce carrying a valid extension); `stamper_persists` (restart reuses the stamp without searching: log line `stamp loaded`); `stamper_shutdown_interrupts` (SIGTERM during a cost-30 search exits within 3 s).
- [ ] **Step 2-4:** Run to fail; implement; PASS. Commit: `Search and persist destination stamps in the node daemon`.

### Task 13: Path request stamp emission

**Files:** Modify `examples/node_daemon.c` / `examples/node_stamper.h`, `src/node.c`, `tests/test_node_process.c`.

**Interfaces:**
- Consumes: `rnc_path_request_create_stamped`. `rnc_node_request_path_ex` gains behavior only through a node hook: `rnc_node_set_stamp_provider(rnc_node *node, int (*fn)(void *ctx, const uint8_t material[32], uint8_t stamp[14]), void *ctx)`; when set and emission is on, requests call it (cached, 256 entries) and are cancelled with a log line if it returns 0 within `pr_stamp_timeout`.

- [ ] **Step 1: Failing tests:** `pr_emitted_stamped` (an enforcing 1.6.1 `rnsd` answers a path request from the daemon); `pr_stamp_timeout_cancels`.
- [ ] **Step 2-4:** Run to fail; implement; PASS. Commit: `Stamp outgoing path requests`.

### Task 14: Link request stamp emission

**Files:** Modify `src/link.c`, `include/reticulum_c/rnc_link.h`, `examples/node_stamper.h`, `tests/test_link.c`, `tests/test_node_process.c`.

**Interfaces:**
- Produces: `rnc_result rnc_link_set_stamped_key(rnc_link *link, const uint8_t private_key[32], const uint8_t public_key[32])`, called before the existing request-creation function in `src/link.c` (around line 235); when set, that function uses the pair as the ephemeral encryption key instead of the one from `rnc_identity_generate`, keeping the generated signature key (the stamp material uses its public half). Teardown reason `RNC_LINK_STAMP_FAILURE` (0x04) when the search times out.
- Host: when the recalled `link_cost > 0` (or `always_stamp_lrs`), search with `rnc_netstamp_find_key` over `destination || sig_pub` up to `lr_stamp_timeout`.

- [ ] **Step 1: Failing tests:** `lr_stamped_established_with_enforcing_reference` (daemon to enforcing 1.6.1 peer opens a link); `lr_stamp_timeout_teardown` (cost 40 with 0.1 s timeout ends with reason 0x04); `lr_unstamped_when_cost_zero`.
- [ ] **Step 2-4:** Run to fail; implement; PASS. Commit: `Stamp outgoing link requests`.

### Task 15: Enforcing-network process tests (both directions)

**Files:** Create `tests/test_netstamp_network.sh` or a case set in `tests/test_node_process.c`; Modify `CMakeLists.txt`.

- [ ] **Step 1:** Write tests `reticulum_node_process_stamps_rns161_*`: 1.6.1 `rnsd` with `enforce_stamps = yes` and this daemon (stamping on) exchange announce, path request and link; negative cases with this daemon's emission off are dropped by the enforcing peer; this daemon with `enforce_stamps = yes` drops unstamped announces from a 1.6.1 peer started with stamping disabled.
- [ ] **Step 2:** Run; expect PASS for the positive cases and the listed drops. Commit: `Test network stamps against an enforcing 1.6.1 node`.

### Task 16: Board verification and the stamp slot

**Files:** Modify `mcu/app/rnc_mcu_app.c` (after `rnc_node_add_destination` at line 346; announce at 450), `mcu/app/rnc_mcu_net.h` (config keys near line 147), `mcu/platformio/src/*.cpp` persistence for the config, `mcu/tests/test_net.c`, `mcu/tests/test_link.c`, `tests/footprint.c` budget.

**Interfaces:**
- Produces config keys: `stamp` (28 hex digits, shown by `get` as `(set)` or `(empty)`), console commands `stamp.material` (prints the 90 hex-byte material, plus the destination value, as hex) and `stamp.status` (`none`, `valid`, `stale`). `set stamp <hex>` verifies with one hash via `rnc_node_set_destination_stamp`; RNC_AUTH prints `error: stamp does not verify`. At boot the stored stamp is checked; if it fails it is erased and the console prints `stamp erased: identity changed`.

- [ ] **Step 1: Failing host tests** in `mcu/tests/test_net.c`: `stamp_set_valid`, `stamp_set_invalid_rejected`, `stamp_stale_erased_at_boot`, `stamp_material_matches_library`, `announce_unstamped_without_stamp`, `announce_stamped_with_stamp` (extension verifies at 25.0 with a host-computed stamp).
- [ ] **Step 2:** `mcu/tests/mcu_unit.sh`; expect failure. **Step 3:** Implement; boards call `rnc_node_set_stamp_emission(node, 0, 25.0)` so an absent stamp never blocks announcing. **Step 4:** PASS; run `tests/footprint` with its budget and the PlatformIO builds for nrf52 and esp32; record any footprint change and update the baseline only if the 96 KB limit still holds. Commit: `Boards carry and verify a precomputed destination stamp`.

### Task 17: Stamp the board from the flash tool and the web flasher

**Files:** Modify `examples/reticulum_flash.c`, `tests/test_flash.c`, `web/src/*` (the console view), `web/tests/ui.spec.js`.

**Interfaces:**
- Produces: `reticulum-c-flash stamp --port PORT [--value 25]`: reads `stamp.material` over the setup console, finds a stamp with `rnc_netstamp_find` (progress to stderr), sets it, confirms with `stamp.status`. Web flasher console panel shows `stamp.status` and the material, with a field to paste a stamp and a Set button; it does not compute.

- [ ] **Step 1: Failing tests:** `test_flash.c` case `stamp_command_flow` against the existing pty console fake (material read, stamp set, status valid); UI test `stamp panel shows status and accepts a stamp` with the simulated serial device.
- [ ] **Step 2-4:** Run to fail; implement; PASS. Commit: `Stamp boards from reticulum-c-flash and show the status in the web flasher`.

### Task 18: Hardware validation and documentation

**Files:** Modify `docs/spec-gap-list.md`, `COMPATIBILITY.md`, `README.md`, `mcu/README.md`, `docs/superpowers/plans` (this plan, ticked).

- [ ] **Step 1:** On the Supreme and the T-Echo (user approval to flash first, preserving identity): flash the new build, run `reticulum-c-flash stamp`, confirm over LoRa that an enforcing 1.6.1 node accepts the board's announce and that an unstamped board is dropped by an enforcing node and accepted by a non-enforcing one. Record RSSI, timings and the stamp search time on the host.
- [ ] **Step 2:** Update the gap list (baseline 1.6.1, stamps IMPL, identity stamps open, non-wire 1.6.x items listed), `COMPATIBILITY.md` evidence, `README.md`, the MCU README console commands, and the manual's configuration reference.
- [ ] **Step 3:** Open the PR(s); merge only with the user's approval and green CI. Commit: `Document network stamps and the 1.6.1 baseline`.

---

## Self-review

- **Spec coverage:** re-pin and inventory (Tasks 1-2); primitives (3-6); verification of announces, path requests, link requests (7-9); configuration (10); host emission of all three (11-14); enforcing-network evidence (15); board precompute, status and staleness (16-17); docs and hardware (18). Identity stamps and in-browser computation are non-goals and have no task.
- **Interfaces:** `rnc_netstamp_*` names are used identically in Tasks 3-6, 7-9, 11-17. `rnc_node_set_stamp_emission`, `rnc_node_set_destination_stamp`, `rnc_node_destination_stamp_material` are defined in Task 11 and used in 12 and 16. Task 14 adds `rnc_link_set_stamped_key`, which Task 14's host code calls.
- **Review Focus coverage:** 1.5.5 peer acceptance (Task 15 negative cases and Task 7 relay of original bytes), overlong app data (Task 11), fractional boundary (Task 6), stale board stamp (Task 16), odd path-request lengths (Task 8).
