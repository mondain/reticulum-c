# RNS 1.5.5 to 1.6.1: inventory and baseline

Oracle moved from `e40191b3d193b46b7f2d8a44424a594cd758839b` (1.5.5) to
`cff4d03fdbd6bfb63b765280cd944756ac5cce8d` (tag 1.6.1). The diff below was taken against the 1.5.5
tag (`7f2b3b9b524c9386316379af1313b43a5e4f7a5d`), which is not the pinned commit but is close
enough to classify the changes; 45 files in `RNS/` changed (5455 insertions, 911 deletions).

## Baseline: existing suite against 1.6.1 (2026-11-24)

`cmake -DRNC_INTEROP_TESTS=ON -DRNC_REFERENCE_DIR=<1.6.1 checkout>`; 356 tests, 343 pass, 13 fail:

| Test | Symptom | First guess |
| --- | --- | --- |
| `reticulum_mesh_client/server/loss/large` (4) | `rnc_node_input(...) == RNC_OK` fails at once (`tests/test_interop.c:124`) | a 1.6.1 TCP peer's first packet, the tunnel synthesis packet with `ext_payload`, is refused by this node |
| `reticulum_node_process_tunnel_ref` | timeout; reply lacks `tunnel id=` and `paths=1` | tunnel synthesis format (see below) |
| `reticulum_node_process_remote` | timeout while the reference `rnpath` is "establishing link with remote transport instance" | to investigate (link to the remote management destination) |
| `reticulum_node_process_live_rns` | path response hops differ: reference and this daemon at `test_node_process.c:2032` (`ref_hops == c_hops`) | path response handling changed in 1.6 |
| `reticulum_node_process_disc_list_rns` | the reference prints stamp values as `24.000`, this tool as `24` | display only |
| `reticulum_node_process_disc_listen_ref` | daemon never lists the reference's interface | discovery announce changes, to investigate |
| `reticulum_weave_reference` | `test_weave.c:513` the reference's Weave handshake produces no first send | to investigate (WeaveInterface changed, 19 lines) |
| `reticulum_mcu_radio_reference` | reference bitrate computed as 0 for sf=5 (and likely all) | the test driver, `updateBitrate` or its inputs changed |
| `reticulum_mcu_tcp_reference` | the reference client fails | likely tunnel synthesis or a TCP client change |
| `reticulum_git_manage_ref_client` | timeout (400 s) | to investigate |

These are the work of the next task; none is classified as fixed here.

## Classification of the 1.5.5 to 1.6.1 changes

Wire-relevant (this project must follow):

- **Network stamps** (new `Stamps.py`; `Identity`, `Destination`, `Link`, `Transport`): announce
  extension, path request extension, link request stamped keys. The subject of the rest of the
  plan.
- **Tunnel synthesis** (`Transport.synthesize_tunnel(interface, reverse=False)`): the signed data now
  includes an `ext_payload` (msgpack map with implementation, version, transport status,
  destination cost and path request cost), minimum and maximum lengths are enforced with
  protocol violations, a second synthesis packet on an established tunnel is a violation,
  blackholed remote transports are torn down, and a reverse (bidirectional) synthesis exists.
- **Resource**: `app_flag` bit in the advertisement flags, an advertisement with an empty
  hashmap (`HASHMAP_IS_EMPTY` 0xFE, answered with an initial hashmap update), and
  `ResourceAdvertisement(self, mdu=self.link.mdu)`.
- **Link**: `STAMP_FAILURE` teardown reason 0x04; link request key derivation with stamped
  X25519 keys.
- **Known destinations** record the announced link request cost (`recall_link_cost`).
- **Interface discovery**: `DST_COST`, `PR_COST`, `TRANSPORT_IMPL`, `TRANSPORT_VERS` keys.

Local behavior (listed as gaps, not implemented here):

- SQLite storage backend (`Storage.py`) and path table culling, path usage tracking, sharding.
- Announce ingress pre-filtering, hop limiter options, filtered-traffic and link statistics in
  `rnstatus`, `client_limit` on `BackboneInterface`, `blocked_ips`, worker and niceness options.
- `rnpath`, `rnstatus`, `rnsd` display and option changes.

Irrelevant: copyright years, version string, logging text, `AES128_BLOCKSIZE` to
`AES256_BLOCKSIZE` in MDU formulas (both 16 bytes).
