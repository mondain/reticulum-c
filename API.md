# C API and host contract

Include `<reticulum_c/rnc.h>` for values/crypto/framing and
`<reticulum_c/rnc_link.h>` for the opaque link/channel state machine. Both headers
support C++ inclusion. Serialize calls to an instance; no internal I/O loop,
thread, socket or random-device access is owned by the protocol library.
OpenSSL and instance creation allocate; Resources/services also allocate bounded
transfer/event storage during use. All APIs require serialized access per instance.

## Identity, packet and framing

An identity is caller-owned sensitive storage. Import/generate it, keep private
bytes private, and finish with `rnc_identity_clear()`. Public identities cannot
sign or decrypt. Supply a cryptographically secure RNG callback that fills every
requested byte; deterministic RNGs are only for tests.

Packet encode/decode/hashes use explicit fields and byte order, never a native
struct layout on the wire. Header size/MTU/hops/IFAC validation is enforced.
Raw packet codecs reject IFAC-protected bytes; verify/remove IFAC with
`rnc_ifac_verify()` first. For output: packet encode, `rnc_ifac_apply()`, framing.

Initialize each stream with `rnc_hdlc framing = {0}`. Feed each byte through
`rnc_hdlc_feed()`. RNC_OK yields one whole frame; malformed/overlong input is
discarded through a fresh delimiter. Zero the whole framing state when replacing
a transport. Encode outgoing packets, then HDLC-frame them in the host.

Announces require caller-supplied Unix seconds and randomness. Verification
checks identity/name/destination/signature binding, including an optional
ratchet. It does not establish freshness, a usable route or application trust.

## Link event pump

1. Create a link with `rnc_link_new(rng, context)`; the callback/context must
   outlive the instance. One instance represents one transport association.
2. An initiator passes a verified announce to `rnc_link_open()`. A responder
   applies admission policy before `rnc_link_accept()` with its local identity.
3. Feed decoded packets with `rnc_link_input()`. Supply monotonic milliseconds
   for every operation and call `rnc_link_tick()` regularly, including while idle.
4. Drain copied events with `rnc_link_poll()`. SEND belongs to the host's output
   queue; ACTIVE signals usable keys; IDENTIFIED signals a proved identity.
5. A responder has no principal until it verifies LINKIDENTIFY. The initiator
   learns the destination identity from its proof. Call `rnc_link_identify()`
   to prove the initiator's identity, and `rnc_link_remote_identity()` to obtain
   public-only remote material. Authentication does not grant app permissions.
6. `rnc_link_send()` queues a typed message up to `rnc_link_channel_mdu()` bytes
   (425 at default MTU). Configure the MTU before opening a link; negotiation
   caps it to the peer's limit, at most 4096. Keep input on RNC_AGAIN, drain events
   and retry. Types >=0xf000 are reserved; the Buffer API uses system type 0xff00.
   The default TX window is two messages; `rnc_link_configure_channel()` can
   enable bounded adaptive growth to 48. The RX reorder window is 48 slots.
7. MESSAGE arrives in order with its type/sequence/payload. DELIVERED identifies
   an outgoing sequence proved received; it does not mean persisted or read.
8. CLOSED discards pending application events/data and clears session secrets.
   `rnc_link_close()` queues an encrypted close where possible. The host must
   flush SEND bytes; free/new to reconnect, resetting host framing and queues.

The event queue has 64 entries. Channel input conservatively reserves 50 slots
so a complete reorder window can be released atomically. Drain frequently.
RNC_AGAIN does not commit the rejected operation. A crypto failure requires
closing/recreating the instance. Treat malformed app framing according to the
application protocol; unknown or forged receipts must not count as delivery.

Handshake timeout is 30 seconds, active silence timeout 180 seconds. Initiators
send keepalives every 30 seconds; correctly directed keepalive bytes extend
liveness but are unauthenticated. Channel retry delay starts at three RTTs,
clamped to 250–4000 ms, doubles per attempt and caps at 30 seconds. Up to five
attempts retain their packet hashes; retries re-encrypt with fresh IVs.

Input/output buffers and objects must not overlap. Functions document output
commit behavior and required initialization in their public headers. Use the
[POSIX text host](examples/text_peer.c) and [installed consumer](tests/consumer/main.c)
as C integration examples. They are separate from protocol authority and do not
make application privilege decisions for the caller.

## Transfers, services and routing

`rnc_buffer.h` provides standard Buffer stream codecs and bounded receive rings.
Feed type 0xff00 Channel events to `rnc_stream_input()`. Retain input on AGAIN,
drain the ring, and retry. Transmit and receive EOF are independent.

`rnc_resource.h` provides explicit advertisement admission, segmented transfers,
integrity proofs, bounded decompression, progress/cancellation and retries. Feed
Resource events to each candidate transfer, pump output and tick regularly.
Read completed application data and metadata separately. Failed preparation of
a replacement transfer preserves completed data. A successful replacement owns
the instance's new data and receipt state.

`rnc_service.h` sends complete MessagePack values inline or via Resources.
Register paths with admission policy and service requests from polled events.
Each instance permits one incoming and one outgoing Resource, eight pending
requests and eight queued events. Completed malformed envelopes release their
receive slot; event-queue backpressure retains completed input until drained.
Late responses are discarded; request deadlines and the bounded replay cache
do not guarantee durable exactly-once application effects.

`rnc_responder.h` and `rnc_requester.h` compose links and services into the
`Destination.register_request_handler` and `Link.request` patterns. A responder
accepts links for registered destinations and calls a handler per admitted
request with the caller's identity hash; `rnc_responder_request_identity()` and
`rnc_responder_request_link_id()` give the full public key and link inside a
handler. A handler normally answers by writing a MessagePack value, but it may
(a) register with `rnc_responder_register_file()` to answer with raw data plus
one MessagePack metadata value as a single Resource (the reference's file
response; `rnc_requester_poll_file()` returns both), (b) keep the node serviced
while it works by feeding `rnc_responder_input()` and ticking the responder from
inside the handler (no second handler starts; a link that closes meanwhile is
released afterwards), or (c) call `rnc_responder_defer()`, return RNC_AGAIN and
answer later with `rnc_responder_reply()` using the ticket, within the lifetime
it requested (the service otherwise keeps a request for 30 seconds). A requester
runs one request per link: start, tick, poll. Both borrow the node and are
thread-confined.

`rnc_security.h` supplies IFAC, GROUP keys, signed ratcheted announces and
caller-owned ratchet storage. Persist private ratchets securely and clear keys
when done. IFAC network membership and encryption do not grant app privileges.

`rnc_node.h` owns bounded routes, signed announce freshness, path requests,
forwarding and transit-link state. Supply interface IDs, incoming packets and
both clocks; drain SEND/local-delivery events. Explicitly bind local links to
the selected route/admitted ingress with `rnc_node_bind_link_on()`. Checkpoints
are owner-signed public route records and remain configuration-bound.

`rnc_host.h` belongs to the separate `reticulum_c::host` target. It owns POSIX
descriptors, framing/IFAC, bounded outgoing queues and reconnects. Feed host
steps/events into the application's loop; protocol objects remain caller-owned.
`rnc_ipc.h` supplies authenticated framed RPC, bounded GET-only MessagePack
queries and response writers; socket and private-state ownership stays in the
host. See `examples/node_daemon.c` for composition, reload and persistence.
