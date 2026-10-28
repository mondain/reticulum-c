# Shared registration of the reticulum_c ESP-IDF component. Included by
#   - mcu/esp-idf/components/reticulum_c/CMakeLists.txt  (EXTRA_COMPONENT_DIRS use)
#   - the repository's top-level CMakeLists.txt when built by ESP-IDF (use from the
#     repository root, for example as an IDF Component Manager git dependency).
# RNC_ROOT must be the repository root. The core is built with the mcu capacity
# profile and the portable crypto backend (Monocypher plus built-in SHA-256, HMAC,
# HKDF and AES), so it needs no mbedTLS or OpenSSL and only malloc, snprintf and libm.
if(NOT RNC_ROOT)
    message(FATAL_ERROR "RNC_ROOT must point at the reticulum-c repository root")
endif()
set(RNC_CORE_SRCS
    crypto.c crypto_portable.c packet.c framing.c announce.c link.c channel.c node.c
    ifac.c ratchet.c group.c stream.c resource.c service.c ipc.c responder.c requester.c
    transfer.c stamp.c discovery.c log.c i2p.c)
set(RNC_SRC_LIST "")
foreach(s ${RNC_CORE_SRCS})
    list(APPEND RNC_SRC_LIST "${RNC_ROOT}/src/${s}")
endforeach()
set(RNC_MONOCYPHER
    "${RNC_ROOT}/src/third_party/monocypher/monocypher.c"
    "${RNC_ROOT}/src/third_party/monocypher/monocypher-ed25519.c")
idf_component_register(
    SRCS ${RNC_SRC_LIST} ${RNC_MONOCYPHER}
    INCLUDE_DIRS "${RNC_ROOT}/include"
    PRIV_INCLUDE_DIRS "${RNC_ROOT}/src" "${RNC_ROOT}/src/third_party/monocypher")
# Vendored code is compiled as shipped, without warnings turned on.
set_source_files_properties(${RNC_MONOCYPHER} PROPERTIES COMPILE_OPTIONS "-w")
# Public: the capacity constants size public structs, so every consumer needs them.
target_compile_definitions(${COMPONENT_LIB} PUBLIC RNC_PROFILE_MCU=1)
target_compile_definitions(${COMPONENT_LIB} PRIVATE RNC_CRYPTO_PORTABLE=1
    RNC_PORTABLE_NO_RPC_DIGESTS=1)
