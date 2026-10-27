# Reticulum network functionality implementation plan

User authorization: proceed with implementations to eliminate the audited gaps.
C11, MIT, Linux first, macOS second, Windows last. RNS 1.5.5 at
`e40191b3d193b46b7f2d8a44424a594cd758839b` is the protocol baseline. Read the
Reticulum Manual 1.5.5 in text form before the reference source. External
implementations are test oracles only. No implementation is copied from them.

## Design and boundaries

Keep protocol state machines sans I/O. Input, monotonic time, Unix time,
randomness, packet delivery and persistence are supplied by the caller. New
protocol modules are independently usable; hosts compose them with links.
Bound all queues, tables and transfers; invalid/authentication-failing input
must not commit output/state. RNC_AGAIN is retryable without partial consumption.
Preserve existing default link behavior and public API compatibility.

The node engine owns interface IDs, destinations, announcement/path management,
packet duplicate/reverse/link routing and caller-drained events. Host adapters
own actual descriptors, configuration, persistence and administrative sockets.
Transfer/service engines own application protocol state and pass context-tagged
plaintext through the link's authenticated raw-packet API. Stream readers/writers
use the standard Channel system message 0xff00 and preserve EOF/backpressure.

## Tasks and verification

- [ ] Establish a clean isolated worktree and baseline; all new tests are C.
- [ ] Security primitives: IFAC derivation/masking/checking, ratchet generation,
  encryption/decryption/rotation/storage records, ratcheted announces, GROUP keys
  and PLAIN destination hashing. Tests: deterministic reference vectors,
  tampering/truncation/wrong secrets, expiry/rotation and bounds; live oracle.
- [ ] Link services: authenticated context-tagged packet input/output, standard
  Buffer streams and adaptive Channel send windows (default bounded behavior
  remains compatible). Tests: two real in-memory links, reserved types, stream
  EOF/compression/fragmentation/backpressure, loss, wrap and window growth.
- [ ] Transfers and services: standard Resources with integrity, flow control,
  retries, cancellation/progress, bounded compression/segmentation; standard Link
  requests/responses and admission/timeouts. Test C pairs and unmodified RNS in
  both roles, loss, malformed control, cancellation and maximum capacities.
- [ ] Mesh node: path request codec, signed announcement caching/freshness,
  bounded routing tables/expiry, request forwarding/duplicate suppression,
  SINGLE and Link packet/proof forwarding, interface removal and reconnect.
  Test a multi-interface multi-hop topology, forged proofs/announces, loops,
  stale routes, clock rollback, saturation and real RNS routing in both roles.
- [ ] Node host: C TCP/UDP/AutoInterface and serial/KISS/RNode adapters; IFAC,
  per-interface announce/airtime queues; a configurable daemon with persistent
  identities/network state and shared-instance/admin tools. Verify processes,
  reload/reconnect, private state permissions, malformed config/IPC and PTYs.
- [ ] Integrate node/transfer APIs in standalone examples without introducing
  runtime dependencies on Python/Rust/other stacks. Verify source integration
  and the relocated installed SDK consumer.
- [ ] Fresh independent review, Linux/macOS/shared/sanitizer CI, RNS/Leviculum
  and reticulum-rs interoperability matrix, exact tested publication refs.

Physical radio and Windows claims require execution on that hardware/platform;
implemented drivers or cross-compilation alone do not establish validation.

## Execution ledger

Ruling: the user's proceed approves the gap list, dependency order and continued
implementation without another design permission gate. Additive APIs will keep
existing callers working; version packaging will reflect actual ABI changes.

2026-10-26 execution update:
- Worktree branch feature/network-stack-parity, base6536fb6. No publication yet.
- SDK0.2.0/SOVERSION1: packet/event ABI enlarged for max4096MTU, defaults500.
- Security APIs/modules+unitandoptionalC-CPythonoracle pass exactRNS IFAC,
  ratchet/GROUPbothdirections, signedratchetannounce, PLAIN/pathdestinationhash.
- Node routing/pathrequests/reverseproof/transitlinks/announcebudget plus
  signedcheckpoint+sharedlocaltransparenthop bridge implemented. SevenCgroups
  pass, including4node2routerencryptedChannel and3messages170sapart.
- Reviewfixed: pathnamehashoffbyone(frozen6b9f66014d9853faab220fba47d02761),
  activeLinkroutingTTL, unauthlocalinterfacepin(nowbind_link_on), sameifaceforward,
  eventcleanupatifaceremoval, oversizedHEADER2, requesttagreplay/queuebudget.
- Resources/services standardwire, boundedBZip2optional, segments>1MiB,
  cancel/proofs/admission/MessagePack/requests/deadlines, adaptiveChannels and
  standardBufferstreams implemented. FifteenC-CPythonpost-handshake differential
  modespassincludingbothroles/compression/largeMTU/bulk; actualnetworknotrefreshed.
- Reviewfixed: Resourcewirequota, duplicateHMU; servicelate/replayedrequests and
  latecompletedbulkresponsekeepingrxslot. Newtest_service_expiry isregistered.
- POSIXhost separatetarget reticulum_c::host, TCP/UDP/AutoIPv6/HDLC/serial/KISS/
  RNode/IFAC+privateidentity APIs; codecsandrealPTYtests pass. DaemonIPCwiring
  andprocessoracle are still inprogress (parity_links owns thosefiles).
- RNS1.5.5RPC uses MessagePack, NOT theolderpickle protocol. PureC ipc.c/auth/
  framing/query/writer native4groupspass; PythonCAPIoracleagreedwithCPython
  challenges/RNSMessagePack (parity_security owns oraclewhilehost integrates).
- Integrated out/parity-rns:62/62 socket-free pass. Sixold/newRNS networktests+
  hostnetwork/textpeer blockedlocallyEPERM; must run hostedCI before claims.
- Freshreview_network_core isreviewing protocolmodules; candidate distantResource
  maphashcollision search-window defect and malformedcompletedservice recovery
  stillunderinvestigation. FixImportant findings before publication.
- Stillrequired: integrateIPC/daemon/tests/CMake; liveRNSlarge-MTUcase; published
  Linux/static/shared/sanitizer/mac/RNS/Lev CI; standalone SDK package/source
  validation; currentdocs/featurematrix; exactrefs.
