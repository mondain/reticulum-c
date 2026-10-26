# C API and host contract

Include `<reticulum_c/rnc.h>` for values/crypto/framing and
`<reticulum_c/rnc_link.h>` for the opaque link/channel state machine. Both headers
support C++ inclusion. Serialize calls to an instance; no internal I/O loop,
thread, socket or random-device access is owned by the protocol library.
OpenSSL and link creation allocate; link queues/storage are bounded thereafter.

## Identity, packet and framing

An identity is caller-owned sensitive storage. Import/generate it, keep private
bytes private, and finish with `rnc_identity_clear()`. Public identities cannot
sign or decrypt. Supply a cryptographically secure RNG callback that fills every
requested byte; deterministic RNGs are only for tests.

Packet encode/decode/hashes use explicit fields and byte order, never a native
struct layout on the wire. Header size/MTU/hops/IFAC validation is enforced.
Unsupported IFAC is an error, not silently ignored encryption/access control.

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
6. `rnc_link_send()` queues a typed message of at most 425 bytes. Keep input on
   RNC_AGAIN, drain events and retry. Types >=0xf000 are reserved. A fixed two-
   message TX window and 48-slot RX reorder window bound storage.
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
add routing or application privilege decisions to the library.
