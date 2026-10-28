cmake_minimum_required(VERSION 3.16)
project(reticulum_c VERSION 0.2.0 LANGUAGES C)
set(RNC_TOP_LEVEL OFF)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(RNC_TOP_LEVEL ON)
    include(CTest)
endif()
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
# Crypto backend for the protocol core: "openssl" (default) or "portable" (no OpenSSL,
# Monocypher plus built-in SHA-256/HMAC/HKDF/AES; for microcontrollers).
set(RNC_CRYPTO "openssl" CACHE STRING "Crypto backend: openssl or portable")
set_property(CACHE RNC_CRYPTO PROPERTY STRINGS openssl portable)
if(NOT RNC_CRYPTO STREQUAL "openssl" AND NOT RNC_CRYPTO STREQUAL "portable")
    message(FATAL_ERROR "RNC_CRYPTO must be openssl or portable (got '${RNC_CRYPTO}')")
endif()
# Capacity profile: "" (host defaults) or "mcu" (include/reticulum_c/rnc_profile_mcu.h).
set(RNC_PROFILE "" CACHE STRING "Capacity profile: empty (host) or mcu")
set_property(CACHE RNC_PROFILE PROPERTY STRINGS "" mcu)
if(RNC_CRYPTO STREQUAL "openssl")
    find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
else()
    # The portable library never links OpenSSL. The POSIX host, examples and most
    # tests still use it, so they are built only when OpenSSL happens to be present.
    find_package(OpenSSL 3.0 COMPONENTS Crypto)
endif()
if(OPENSSL_FOUND)
    set(RNC_HAVE_OPENSSL ON)
else()
    set(RNC_HAVE_OPENSSL OFF)
endif()
option(RNC_SANITIZERS "Enable address and undefined-behavior sanitizers" OFF)
option(RNC_BUILD_EXAMPLES "Build the generic POSIX C text peer" ${RNC_TOP_LEVEL})
option(RNC_INTEROP_TESTS "Run against a pinned external RNS 1.5.5 checkout" OFF)
set(RNC_REFERENCE_DIR "" CACHE PATH "Pinned RNS 1.5.5 reference checkout")
set(RNC_INTEROP_PYTHONPATH "" CACHE STRING "Extra Python module paths for the external oracle")
option(RNC_COMPRESSION "Enable bounded BZip2 Resource/Buffer compression" ON)
if(RNC_COMPRESSION)
    find_package(BZip2 REQUIRED)
endif()
add_library(reticulum_c src/crypto.c src/crypto_${RNC_CRYPTO}.c src/packet.c src/framing.c src/announce.c
    src/link.c src/channel.c src/node.c src/ifac.c src/ratchet.c src/group.c
    src/stream.c src/resource.c src/service.c src/ipc.c src/responder.c src/requester.c src/transfer.c src/stamp.c src/discovery.c src/log.c src/i2p.c)
if(RNC_COMPRESSION)
    target_compile_definitions(reticulum_c PRIVATE RNC_HAVE_BZIP2=1)
    target_link_libraries(reticulum_c PRIVATE BZip2::BZip2)
endif()
add_library(reticulum_c::reticulum_c ALIAS reticulum_c)
target_include_directories(reticulum_c PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
if(RNC_CRYPTO STREQUAL "openssl")
    target_link_libraries(reticulum_c PRIVATE OpenSSL::Crypto)
else()
    target_sources(reticulum_c PRIVATE
        src/third_party/monocypher/monocypher.c
        src/third_party/monocypher/monocypher-ed25519.c)
    # Vendored code is compiled as shipped, without this project's -Werror set.
    set_source_files_properties(src/third_party/monocypher/monocypher.c
        src/third_party/monocypher/monocypher-ed25519.c PROPERTIES COMPILE_OPTIONS "-w")
    target_compile_definitions(reticulum_c PRIVATE RNC_CRYPTO_PORTABLE=1)
endif()
if(RNC_PROFILE STREQUAL "mcu")
    # Public: the capacity constants shape public structs, so consumers need them too.
    target_compile_definitions(reticulum_c PUBLIC RNC_PROFILE_MCU=1)
elseif(NOT RNC_PROFILE STREQUAL "")
    message(FATAL_ERROR "RNC_PROFILE must be empty or mcu (got '${RNC_PROFILE}')")
endif()
target_compile_features(reticulum_c PUBLIC c_std_11)
set_target_properties(reticulum_c PROPERTIES C_EXTENSIONS OFF VERSION ${PROJECT_VERSION} SOVERSION 1)
if(MSVC)
    target_compile_options(reticulum_c PRIVATE /W4 /WX)
else()
    target_compile_options(reticulum_c PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
if(RNC_SANITIZERS AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(reticulum_c PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(reticulum_c PUBLIC -fsanitize=address,undefined)
endif()
install(TARGETS reticulum_c EXPORT reticulum_cTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES LICENSE PROVENANCE.md DESTINATION ${CMAKE_INSTALL_DATADIR}/reticulum_c)
install(EXPORT reticulum_cTargets NAMESPACE reticulum_c:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/reticulum_c)
configure_package_config_file(cmake/reticulum_cConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/reticulum_cConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/reticulum_c)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/reticulum_cConfigVersion.cmake
    VERSION ${PROJECT_VERSION} COMPATIBILITY SameMinorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/reticulum_cConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/reticulum_cConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/reticulum_c)
if(BUILD_TESTING)
    add_executable(test_crypto_backend tests/test_crypto_backend.c)
    target_link_libraries(test_crypto_backend PRIVATE reticulum_c)
    add_test(NAME reticulum_crypto_backend_kat COMMAND test_crypto_backend)
    if(RNC_HAVE_OPENSSL)
        # Both backends side by side (distinct symbol prefixes), no reticulum_c library.
        add_executable(test_crypto_differential tests/test_crypto_differential.c
            tests/be_openssl_prefixed.c tests/be_portable_prefixed.c
            src/third_party/monocypher/monocypher.c src/third_party/monocypher/monocypher-ed25519.c)
        target_include_directories(test_crypto_differential PRIVATE src/third_party/monocypher)
        set_source_files_properties(src/third_party/monocypher/monocypher.c
            src/third_party/monocypher/monocypher-ed25519.c PROPERTIES COMPILE_OPTIONS "-w")
        target_link_libraries(test_crypto_differential PRIVATE OpenSSL::Crypto)
        add_test(NAME reticulum_crypto_differential COMMAND test_crypto_differential)
    endif()
    add_executable(test_node tests/test_node.c)
    target_link_libraries(test_node PRIVATE reticulum_c)
    foreach(case paths routing mesh discovery guards state local destinations destination_data request_path_options hops_to accepts_links)
        add_test(NAME reticulum_node_${case} COMMAND test_node ${case})
    endforeach()
    add_executable(test_receipt tests/test_receipt.c)
    target_link_libraries(test_receipt PRIVATE reticulum_c)
    foreach(case prove_all timeout prove_app forged status recycle default_timeout explicit_proof)
        add_test(NAME reticulum_receipt_${case} COMMAND test_receipt ${case})
    endforeach()
    add_executable(test_i2p tests/test_i2p.c)
    target_link_libraries(test_i2p PRIVATE reticulum_c)
    add_test(NAME reticulum_i2p COMMAND test_i2p)
    add_executable(test_policy tests/test_policy.c)
    target_link_libraries(test_policy PRIVATE reticulum_c)
    foreach(case modes expiry cap invalid)
        add_test(NAME reticulum_policy_${case} COMMAND test_policy ${case})
    endforeach()
    add_executable(test_announce tests/test_announce.c)
    target_link_libraries(test_announce PRIVATE reticulum_c)
    foreach(case retry ingress_removed heard_twice heard_once passed_on local_client rate access_point)
        add_test(NAME reticulum_announce_${case} COMMAND test_announce ${case})
    endforeach()
    add_executable(test_ingress tests/test_ingress.c)
    target_link_libraries(test_ingress PRIVATE reticulum_c)
    foreach(case burst_hold disabled known_exempt search_modes pr_burst egress)
        add_test(NAME reticulum_ingress_${case} COMMAND test_ingress ${case})
    endforeach()
    add_executable(test_recall tests/test_recall.c)
    target_link_libraries(test_recall PRIVATE reticulum_c)
    foreach(case recall refresh bounded persistence aspect)
        add_test(NAME reticulum_recall_${case} COMMAND test_recall ${case})
    endforeach()
    add_executable(test_blackhole tests/test_blackhole.c)
    target_link_libraries(test_blackhole PRIVATE reticulum_c)
    foreach(case announces paths bounds expiry persistence reference_file merge)
        add_test(NAME reticulum_blackhole_${case} COMMAND test_blackhole ${case})
    endforeach()
    add_executable(test_responder tests/test_responder.c)
    target_link_libraries(test_responder PRIVATE reticulum_c)
    foreach(case echo quiet allow_list close arguments max_request)
        add_test(NAME reticulum_responder_${case} COMMAND test_responder ${case})
    endforeach()
    add_executable(test_transfer tests/test_transfer.c)
    target_link_libraries(test_transfer PRIVATE reticulum_c)
    foreach(case send large denied fetch refused unavailable arguments large_mtu)
        add_test(NAME reticulum_transfer_${case} COMMAND test_transfer ${case})
    endforeach()
    add_executable(test_requester tests/test_requester.c)
    target_link_libraries(test_requester PRIVATE reticulum_c)
    foreach(case deferred nested file echo no_route silent identify busy arguments progress_inline progress_resource progress_failed mtu_discovery mtu_discovery_off mtu_mixed mtu_default)
        add_test(NAME reticulum_requester_${case} COMMAND test_requester ${case})
    endforeach()
    add_executable(test_stamp tests/test_stamp.c)
    target_link_libraries(test_stamp PRIVATE reticulum_c)
    foreach(case workblock value generate find)
        add_test(NAME reticulum_stamp_${case} COMMAND test_stamp ${case})
    endforeach()
    add_executable(test_discovery tests/test_discovery.c)
    target_link_libraries(test_discovery PRIVATE reticulum_c)
    foreach(case packing parsing encryption helpers seal record_pack record_unpack record_status config_entries)
        add_test(NAME reticulum_discovery_${case} COMMAND test_discovery ${case})
    endforeach()
    add_executable(test_log tests/test_log.c)
    target_link_libraries(test_log PRIVATE reticulum_c)
    foreach(case filtering truncation names node link)
        add_test(NAME reticulum_log_${case} COMMAND test_log ${case})
    endforeach()
    add_executable(test_tunnel tests/test_tunnel.c)
    target_link_libraries(test_tunnel PRIVATE reticulum_c)
    foreach(case establish reject restore newer expire persist)
        add_test(NAME reticulum_tunnel_${case} COMMAND test_tunnel ${case})
    endforeach()
if(RNC_HAVE_OPENSSL)
    add_executable(test_security tests/test_security.c)
    target_link_libraries(test_security PRIVATE reticulum_c OpenSSL::Crypto)
    foreach(case ifac ratchet group ratchet_reference)
        add_test(NAME reticulum_security_${case} COMMAND test_security ${case})
    endforeach()
endif()
    add_executable(test_link_services tests/test_link_services.c)
    target_link_libraries(test_link_services PRIVATE reticulum_c)
    add_test(NAME reticulum_link_services COMMAND test_link_services)
    add_executable(test_stream tests/test_stream.c)
    target_link_libraries(test_stream PRIVATE reticulum_c)
    if(RNC_COMPRESSION)
        target_compile_definitions(test_stream PRIVATE RNC_HAVE_BZIP2=1)
        target_link_libraries(test_stream PRIVATE BZip2::BZip2)
    endif()
    add_test(NAME reticulum_stream COMMAND test_stream)
    add_executable(test_resource tests/test_resource.c)
    target_link_libraries(test_resource PRIVATE reticulum_c)
    foreach(case transfer segments invalid cancel quota window_fast window_slow window_very_slow window_shrinks timeout_rate)
        add_test(NAME reticulum_resource_${case} COMMAND test_resource ${case})
    endforeach()
    if(RNC_COMPRESSION)
        add_test(NAME reticulum_resource_compression COMMAND test_resource compression)
    endif()
    # The fixture includes resource.c to inject allocation failures and inspect
    # private transfer state; all remaining modules come from the SDK.
    add_executable(test_resource_internal tests/test_resource_internal.c)
    target_link_libraries(test_resource_internal PRIVATE reticulum_c)
    if(RNC_COMPRESSION)
        target_compile_definitions(test_resource_internal PRIVATE RNC_HAVE_BZIP2=1)
        target_link_libraries(test_resource_internal PRIVATE BZip2::BZip2)
    endif()
    add_test(NAME reticulum_resource_timeouts COMMAND test_resource_internal)
    add_executable(test_resource_failures tests/test_resource_failures.c)
    target_link_libraries(test_resource_failures PRIVATE reticulum_c)
    if(RNC_COMPRESSION)
        target_compile_definitions(test_resource_failures PRIVATE RNC_HAVE_BZIP2=1)
        target_link_libraries(test_resource_failures PRIVATE BZip2::BZip2)
    endif()
    foreach(case allocation collision)
        add_test(NAME reticulum_resource_${case} COMMAND test_resource_failures ${case})
    endforeach()
    add_executable(test_service tests/test_service.c)
    target_link_libraries(test_service PRIVATE reticulum_c)
    foreach(case inline bulk denial bounds replay recovery backpressure bulk_replay file)
        add_test(NAME reticulum_service_${case} COMMAND test_service ${case})
    endforeach()
    add_executable(test_mtu tests/test_mtu.c)
    target_link_libraries(test_mtu PRIVATE reticulum_c)
    foreach(case negotiation full downgrade bounds framing stream)
        add_test(NAME reticulum_mtu_${case} COMMAND test_mtu ${case})
    endforeach()
    add_executable(test_service_expiry tests/test_service_expiry.c)
    target_link_libraries(test_service_expiry PRIVATE reticulum_c)
    add_test(NAME reticulum_service_expiry COMMAND test_service_expiry)
    add_executable(test_ipc tests/test_ipc.c)
    target_link_libraries(test_ipc PRIVATE reticulum_c)
    foreach(case handshake bounds query blackhole writer)
        add_test(NAME reticulum_ipc_${case} COMMAND test_ipc ${case})
    endforeach()
if(RNC_HAVE_OPENSSL)
    add_executable(test_rnc tests/test_rnc.c)
    target_link_libraries(test_rnc PRIVATE reticulum_c OpenSSL::Crypto)
    foreach(case identity packet framing announce hashes)
        add_test(NAME reticulum_${case} COMMAND test_rnc ${case})
    endforeach()
endif()
    add_executable(test_rnc_link tests/test_link.c)
    target_link_libraries(test_rnc_link PRIVATE reticulum_c)
    foreach(case handshake reliability lifecycle keepalive boundaries keepalive_scale stale reasons establishment getters)
        add_test(NAME reticulum_link_${case} COMMAND test_rnc_link ${case})
    endforeach()
    if(RNC_TOP_LEVEL)
        add_test(NAME installed_consumer COMMAND ${CMAKE_COMMAND}
            -DRNC_BUILD_ROOT=${CMAKE_BINARY_DIR} -DRNC_SOURCE_ROOT=${CMAKE_CURRENT_SOURCE_DIR}
            -DRNC_CONFIG=$<CONFIG> -DRNC_TEST_CC=${CMAKE_C_COMPILER}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/install_consumer.cmake)
    endif()
endif()
if(UNIX AND RNC_BUILD_EXAMPLES AND RNC_HAVE_OPENSSL)
    add_executable(reticulum-c-text examples/text_peer.c)
    target_link_libraries(reticulum-c-text PRIVATE reticulum_c OpenSSL::Crypto)
    target_compile_options(reticulum-c-text PRIVATE -Wall -Wextra -Wpedantic -Werror)
    install(TARGETS reticulum-c-text RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    if(BUILD_TESTING)
        add_executable(test_text_peer tests/test_text_peer.c)
        target_compile_options(test_text_peer PRIVATE -Wall -Wextra -Wpedantic -Werror)
        add_test(NAME text_peer COMMAND test_text_peer $<TARGET_FILE:reticulum-c-text> linked)
        set_tests_properties(text_peer PROPERTIES TIMEOUT 30 LABELS network)
    endif()
endif()
if(RNC_HAVE_OPENSSL)
    include(cmake/Interop.cmake)
endif()

if(RNC_HAVE_OPENSSL)
    include(cmake/Leviculum.cmake)
endif()

option(RNC_BUILD_HOST "Build the optional POSIX interface host and node daemon" ${RNC_TOP_LEVEL})
if(UNIX AND RNC_BUILD_HOST AND RNC_HAVE_OPENSSL)
    add_library(reticulum_c_host src/host_posix.c)
    add_library(reticulum_c::host ALIAS reticulum_c_host)
    set_target_properties(reticulum_c_host PROPERTIES EXPORT_NAME host VERSION ${PROJECT_VERSION} SOVERSION 1 C_EXTENSIONS OFF)
    target_link_libraries(reticulum_c_host PUBLIC reticulum_c PRIVATE OpenSSL::Crypto)
    target_compile_features(reticulum_c_host PUBLIC c_std_11)
    target_compile_options(reticulum_c_host PRIVATE -Wall -Wextra -Wpedantic -Werror)
    install(TARGETS reticulum_c_host EXPORT reticulum_cTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    include(CheckCCompilerFlag)
    check_c_compiler_flag(-Wno-format-truncation RNC_HAVE_NO_FORMAT_TRUNCATION)
    if(RNC_HAVE_NO_FORMAT_TRUNCATION)
        set(RNC_NO_FORMAT_TRUNCATION -Wno-format-truncation)
    endif()
    if(RNC_BUILD_EXAMPLES)
        add_executable(reticulum-c-node examples/node_daemon.c)
        target_link_libraries(reticulum-c-node PRIVATE reticulum_c_host OpenSSL::Crypto)
        target_compile_options(reticulum-c-node PRIVATE -Wall -Wextra -Wpedantic -Werror)
        install(TARGETS reticulum-c-node RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
        add_executable(reticulum-c-ctl examples/reticulum_ctl.c)
        target_link_libraries(reticulum-c-ctl PRIVATE reticulum_c_host OpenSSL::Crypto)
        target_compile_options(reticulum-c-ctl PRIVATE -Wall -Wextra -Wpedantic -Werror)
        install(TARGETS reticulum-c-ctl RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
        add_executable(reticulum-c-cp examples/reticulum_cp.c)
        target_link_libraries(reticulum-c-cp PRIVATE reticulum_c_host OpenSSL::Crypto)
        target_compile_options(reticulum-c-cp PRIVATE -Wall -Wextra -Wpedantic -Werror)
        install(TARGETS reticulum-c-cp RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
        add_executable(reticulum-c-x examples/reticulum_x.c)
        target_link_libraries(reticulum-c-x PRIVATE reticulum_c_host OpenSSL::Crypto)
        target_compile_options(reticulum-c-x PRIVATE -Wall -Wextra -Wpedantic -Werror)
        install(TARGETS reticulum-c-x RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
        add_executable(reticulum-c-git examples/reticulum_git.c)
        target_link_libraries(reticulum-c-git PRIVATE reticulum_c_host OpenSSL::Crypto)
        target_compile_options(reticulum-c-git PRIVATE -Wall -Wextra -Wpedantic -Werror ${RNC_NO_FORMAT_TRUNCATION})
        install(TARGETS reticulum-c-git RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
        add_executable(reticulum-c-git-remote examples/reticulum_git_remote.c)
        target_link_libraries(reticulum-c-git-remote PRIVATE reticulum_c_host OpenSSL::Crypto)
        target_compile_options(reticulum-c-git-remote PRIVATE -Wall -Wextra -Wpedantic -Werror)
        install(TARGETS reticulum-c-git-remote RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
        if(BUILD_TESTING)
            add_executable(test_rngit_san tests/test_rngit_san.c)
            target_link_libraries(test_rngit_san PRIVATE reticulum_c_host OpenSSL::Crypto)
            add_test(NAME reticulum_rngit_san COMMAND test_rngit_san)
            add_executable(test_rngit_server tests/test_rngit_server.c)
            target_link_libraries(test_rngit_server PRIVATE reticulum_c_host OpenSSL::Crypto)
            target_compile_options(test_rngit_server PRIVATE -Wall -Wextra -Wno-unused-function ${RNC_NO_FORMAT_TRUNCATION})
            add_test(NAME reticulum_rngit_server COMMAND test_rngit_server)
            add_executable(test_rngit_pages tests/test_rngit_pages.c)
            target_link_libraries(test_rngit_pages PRIVATE reticulum_c_host OpenSSL::Crypto)
            target_compile_options(test_rngit_pages PRIVATE -Wall -Wextra -Wno-unused-function -Wno-format-truncation)
            add_test(NAME reticulum_rngit_pages COMMAND test_rngit_pages)
            set_tests_properties(reticulum_rngit_pages PROPERTIES TIMEOUT 300)
            find_program(RNC_BASH bash)
            find_program(RNC_GIT git)
            if(RNC_BASH AND RNC_GIT)
                add_test(NAME reticulum_git_roundtrip COMMAND ${RNC_BASH} ${CMAKE_SOURCE_DIR}/tests/git_roundtrip.sh c_client
                    $<TARGET_FILE:reticulum-c-node> $<TARGET_FILE:reticulum-c-git> $<TARGET_FILE:reticulum-c-git-remote>)
                set_tests_properties(reticulum_git_roundtrip PROPERTIES LABELS network TIMEOUT 240)
                add_test(NAME reticulum_git_manage COMMAND ${RNC_BASH} ${CMAKE_SOURCE_DIR}/tests/git_manage.sh c_client
                    $<TARGET_FILE:reticulum-c-node> $<TARGET_FILE:reticulum-c-git> $<TARGET_FILE:reticulum-c-git-remote>)
                set_tests_properties(reticulum_git_manage PROPERTIES LABELS network TIMEOUT 300)
                if(RNC_INTEROP_TESTS)
                    foreach(mode ref_client ref_server)
                        add_test(NAME reticulum_git_${mode} COMMAND ${CMAKE_COMMAND} -E env
                            "PYTHONPATH=${RNC_REFERENCE_DIR}:${RNC_INTEROP_PYTHONPATH}"
                            ${RNC_BASH} ${CMAKE_SOURCE_DIR}/tests/git_roundtrip.sh ${mode}
                            $<TARGET_FILE:reticulum-c-node> $<TARGET_FILE:reticulum-c-git> $<TARGET_FILE:reticulum-c-git-remote>
                            ${Python3_EXECUTABLE} ${RNC_REFERENCE_DIR})
                        set_tests_properties(reticulum_git_${mode} PROPERTIES LABELS "reticulum_interop;network" TIMEOUT 300)
                        add_test(NAME reticulum_git_manage_${mode} COMMAND ${CMAKE_COMMAND} -E env
                            "PYTHONPATH=${RNC_REFERENCE_DIR}:${RNC_INTEROP_PYTHONPATH}"
                            ${RNC_BASH} ${CMAKE_SOURCE_DIR}/tests/git_manage.sh ${mode}
                            $<TARGET_FILE:reticulum-c-node> $<TARGET_FILE:reticulum-c-git> $<TARGET_FILE:reticulum-c-git-remote>
                            ${Python3_EXECUTABLE} ${RNC_REFERENCE_DIR})
                        set_tests_properties(reticulum_git_manage_${mode} PROPERTIES LABELS "reticulum_interop;network" TIMEOUT 400)
                    endforeach()
                    add_test(NAME reticulum_git_pages_diff COMMAND ${CMAKE_COMMAND} -E env
                        "PYTHONPATH=${RNC_REFERENCE_DIR}:${RNC_INTEROP_PYTHONPATH}"
                        ${RNC_BASH} ${CMAKE_SOURCE_DIR}/tests/git_pages.sh
                        $<TARGET_FILE:reticulum-c-node> $<TARGET_FILE:reticulum-c-git>
                        ${Python3_EXECUTABLE} ${RNC_REFERENCE_DIR})
                    set_tests_properties(reticulum_git_pages_diff PROPERTIES LABELS "reticulum_interop;network" TIMEOUT 900)
                endif()
            endif()
        endif()
        add_executable(reticulum-c-git-cs examples/reticulum_gitcs.c)
        target_link_libraries(reticulum-c-git-cs PRIVATE reticulum_c_host OpenSSL::Crypto)
        target_compile_options(reticulum-c-git-cs PRIVATE -Wall -Wextra -Wpedantic -Werror)
        install(TARGETS reticulum-c-git-cs RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
        if(BUILD_TESTING)
            find_program(RNC_BASH bash)
            find_program(RNC_GIT git)
            if(RNC_BASH AND RNC_GIT)
                add_test(NAME reticulum_git_cs COMMAND ${RNC_BASH} ${CMAKE_SOURCE_DIR}/tests/test_git_cs.sh $<TARGET_FILE:reticulum-c-git-cs>)
                set_tests_properties(reticulum_git_cs PROPERTIES TIMEOUT 120)
                if(RNC_INTEROP_TESTS)
                    add_test(NAME reticulum_git_cs_interop COMMAND ${CMAKE_COMMAND} -E env
                        "PYTHONPATH=${RNC_REFERENCE_DIR}:${RNC_INTEROP_PYTHONPATH}"
                        ${RNC_BASH} ${CMAKE_SOURCE_DIR}/tests/test_git_cs.sh $<TARGET_FILE:reticulum-c-git-cs>
                        ${Python3_EXECUTABLE} ${RNC_REFERENCE_DIR})
                    set_tests_properties(reticulum_git_cs_interop PROPERTIES LABELS reticulum_interop TIMEOUT 180)
                endif()
            endif()
        endif()
        add_executable(reticulum-c-git-admin examples/reticulum_git_admin.c)
        target_link_libraries(reticulum-c-git-admin PRIVATE reticulum_c_host OpenSSL::Crypto)
        target_compile_options(reticulum-c-git-admin PRIVATE -Wall -Wextra -Wpedantic -Werror ${RNC_NO_FORMAT_TRUNCATION})
        install(TARGETS reticulum-c-git-admin RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
        add_executable(reticulum-c-sh examples/reticulum_sh.c)
        target_link_libraries(reticulum-c-sh PRIVATE reticulum_c_host OpenSSL::Crypto)
        target_compile_options(reticulum-c-sh PRIVATE -Wall -Wextra -Wpedantic -Werror)
        install(TARGETS reticulum-c-sh RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
        add_executable(reticulum-c-rnodeconf examples/reticulum_rnodeconf.c)
        target_link_libraries(reticulum-c-rnodeconf PRIVATE OpenSSL::Crypto m)
        target_compile_options(reticulum-c-rnodeconf PRIVATE -Wall -Wextra -Wpedantic -Werror)
        install(TARGETS reticulum-c-rnodeconf RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
        if(BUILD_TESTING)
            add_executable(test_rnodeconf tests/test_rnodeconf.c)
            target_link_libraries(test_rnodeconf PRIVATE OpenSSL::Crypto)
            foreach(case info bad settings refusals signature)
                add_test(NAME reticulum_rnodeconf_${case} COMMAND ${CMAKE_COMMAND} -E env TZ=UTC
                    $<TARGET_FILE:test_rnodeconf> $<TARGET_FILE:reticulum-c-rnodeconf> ${case})
                set_tests_properties(reticulum_rnodeconf_${case} PROPERTIES LABELS pty TIMEOUT 60)
            endforeach()
        endif()
    endif()
    if(BUILD_TESTING)
        add_executable(test_host tests/test_host.c)
        target_link_libraries(test_host PRIVATE reticulum_c_host OpenSSL::Crypto)
        foreach(case codecs serial network keys rnode rnode_extras rnode_detect rnode_signal rnode_tcp pipe ax25 fast_flap tcp_options connect_late_clock no_output identity_files await_path serial_params kiss log tunnel pressure udp policy)
            add_test(NAME reticulum_host_${case} COMMAND test_host ${case})
        endforeach()
        set_tests_properties(reticulum_host_serial reticulum_host_kiss reticulum_host_rnode reticulum_host_rnode_extras reticulum_host_rnode_detect reticulum_host_rnode_signal reticulum_host_pipe reticulum_host_ax25 reticulum_host_pressure
            PROPERTIES LABELS pty)
        set_tests_properties(reticulum_host_network reticulum_host_udp reticulum_host_await_path reticulum_host_rnode_tcp
            PROPERTIES LABELS network TIMEOUT 30)
        add_executable(test_rnode_multi tests/test_rnode_multi.c)
        target_link_libraries(test_rnode_multi PRIVATE reticulum_c_host OpenSSL::Crypto)
        foreach(case configure transmit receive refusals)
            add_test(NAME reticulum_rnode_multi_${case} COMMAND test_rnode_multi ${case})
            set_tests_properties(reticulum_rnode_multi_${case} PROPERTIES LABELS pty TIMEOUT 60)
        endforeach()
        if(RNC_BUILD_EXAMPLES)
            add_test(NAME reticulum_rnode_multi_daemon COMMAND test_rnode_multi daemon $<TARGET_FILE:reticulum-c-node>)
            set_tests_properties(reticulum_rnode_multi_daemon PROPERTIES LABELS pty TIMEOUT 60)
        endif()
        add_executable(test_weave tests/test_weave.c)
        target_link_libraries(test_weave PRIVATE reticulum_c_host OpenSSL::Crypto)
        foreach(case handshake silent endpoints receive transmit refusals)
            add_test(NAME reticulum_weave_${case} COMMAND test_weave ${case})
            set_tests_properties(reticulum_weave_${case} PROPERTIES LABELS pty TIMEOUT 60)
        endforeach()
        if(RNC_BUILD_EXAMPLES)
            add_test(NAME reticulum_weave_daemon COMMAND test_weave daemon $<TARGET_FILE:reticulum-c-node>)
            set_tests_properties(reticulum_weave_daemon PROPERTIES LABELS pty TIMEOUT 60)
        endif()
        add_executable(fake_sam tests/fake_sam.c)
        target_link_libraries(fake_sam PRIVATE reticulum_c OpenSSL::Crypto)
        add_executable(test_i2p_host tests/test_i2p_host.c)
        target_link_libraries(test_i2p_host PRIVATE reticulum_c_host OpenSSL::Crypto)
        foreach(case session peers peer_forms retry router_restart bad_key keepalive)
            add_test(NAME reticulum_i2p_host_${case} COMMAND test_i2p_host $<TARGET_FILE:fake_sam> ${case})
            set_tests_properties(reticulum_i2p_host_${case} PROPERTIES LABELS network TIMEOUT 60)
        endforeach()
        add_executable(test_host_internal tests/test_host_internal.c)
        target_link_libraries(test_host_internal PRIVATE reticulum_c OpenSSL::Crypto)
        add_test(NAME reticulum_host_internal COMMAND test_host_internal)
        add_executable(test_node_rpc tests/test_node_rpc.c)
        target_link_libraries(test_node_rpc PRIVATE reticulum_c_host OpenSSL::Crypto)
        add_test(NAME reticulum_node_rpc COMMAND test_node_rpc)
        if(RNC_BUILD_EXAMPLES)
            add_executable(test_node_process tests/test_node_process.c)
            target_link_libraries(test_node_process PRIVATE reticulum_c_host OpenSSL::Crypto)
            foreach(case cli panic mtu network shared blackhole management sources probe netid disc_announce disc_listen disc_autoconnect logging tunnel_persist)
                add_test(NAME reticulum_node_process_${case} COMMAND test_node_process
                    $<TARGET_FILE:reticulum-c-node> ${case})
            endforeach()
            add_test(NAME reticulum_node_process_i2p COMMAND test_node_process
                $<TARGET_FILE:reticulum-c-node> i2p $<TARGET_FILE:fake_sam>)
            set_tests_properties(reticulum_node_process_i2p PROPERTIES LABELS network TIMEOUT 60)
            add_test(NAME reticulum_node_process_sh_tools COMMAND test_node_process
                $<TARGET_FILE:reticulum-c-node> sh_tools $<TARGET_FILE:reticulum-c-sh>)
            set_tests_properties(reticulum_node_process_sh_tools PROPERTIES LABELS network TIMEOUT 120)
            add_test(NAME reticulum_node_process_x_tools COMMAND test_node_process
                $<TARGET_FILE:reticulum-c-node> x_tools $<TARGET_FILE:reticulum-c-x>)
            set_tests_properties(reticulum_node_process_x_tools PROPERTIES LABELS network TIMEOUT 120)
            add_test(NAME reticulum_node_process_cp_tools COMMAND test_node_process
                $<TARGET_FILE:reticulum-c-node> cp_tools $<TARGET_FILE:reticulum-c-cp>)
            set_tests_properties(reticulum_node_process_cp_tools PROPERTIES LABELS network TIMEOUT 120)
            add_test(NAME reticulum_node_process_cli_tools COMMAND test_node_process
                $<TARGET_FILE:reticulum-c-node> cli_tools $<TARGET_FILE:reticulum-c-ctl>)
            set_tests_properties(reticulum_node_process_cli_tools PROPERTIES LABELS network TIMEOUT 60)
            set_tests_properties(reticulum_node_process_cli PROPERTIES TIMEOUT 20)
            set_tests_properties(reticulum_node_process_network reticulum_node_process_shared reticulum_node_process_management
                reticulum_node_process_sources reticulum_node_process_probe reticulum_node_process_netid reticulum_node_process_disc_announce reticulum_node_process_disc_listen reticulum_node_process_disc_autoconnect reticulum_node_process_logging reticulum_node_process_tunnel_persist
                PROPERTIES LABELS network TIMEOUT 60)
            if(RNC_INTEROP_TESTS)
                add_test(NAME reticulum_node_process_rns COMMAND ${CMAKE_COMMAND} -E env
                    "PYTHONPATH=${RNC_REFERENCE_DIR}:${RNC_INTEROP_PYTHONPATH}"
                    $<TARGET_FILE:test_node_process> $<TARGET_FILE:reticulum-c-node> rns
                    "${RNC_REFERENCE_DIR}" ${Python3_EXECUTABLE})
                set_tests_properties(reticulum_node_process_rns
                    PROPERTIES LABELS "reticulum_interop;network" TIMEOUT 60)
                add_test(NAME reticulum_rnodeconf_rns COMMAND ${CMAKE_COMMAND} -E env TZ=UTC
                    "PYTHONPATH=${RNC_REFERENCE_DIR}:${RNC_INTEROP_PYTHONPATH}"
                    $<TARGET_FILE:test_rnodeconf> $<TARGET_FILE:reticulum-c-rnodeconf> ref
                    "${RNC_REFERENCE_DIR}" ${Python3_EXECUTABLE})
                set_tests_properties(reticulum_rnodeconf_rns PROPERTIES LABELS "reticulum_interop;pty" TIMEOUT 300)
                add_test(NAME reticulum_node_process_cp_rns COMMAND ${CMAKE_COMMAND} -E env
                    "PYTHONPATH=${RNC_REFERENCE_DIR}:${RNC_INTEROP_PYTHONPATH}"
                    $<TARGET_FILE:test_node_process> $<TARGET_FILE:reticulum-c-node> cp_ref
                    $<TARGET_FILE:reticulum-c-cp> "${RNC_REFERENCE_DIR}" ${Python3_EXECUTABLE})
                set_tests_properties(reticulum_node_process_cp_rns
                    PROPERTIES LABELS "reticulum_interop;network" TIMEOUT 180)
                add_test(NAME reticulum_node_process_x_rns COMMAND ${CMAKE_COMMAND} -E env
                    "PYTHONPATH=${RNC_REFERENCE_DIR}:${RNC_INTEROP_PYTHONPATH}"
                    $<TARGET_FILE:test_node_process> $<TARGET_FILE:reticulum-c-node> x_ref
                    $<TARGET_FILE:reticulum-c-x> "${RNC_REFERENCE_DIR}" ${Python3_EXECUTABLE})
                set_tests_properties(reticulum_node_process_x_rns
                    PROPERTIES LABELS "reticulum_interop;network" TIMEOUT 180)
                add_test(NAME reticulum_node_process_sh_rns COMMAND ${CMAKE_COMMAND} -E env
                    "PYTHONPATH=${RNC_REFERENCE_DIR}:${RNC_INTEROP_PYTHONPATH}"
                    $<TARGET_FILE:test_node_process> $<TARGET_FILE:reticulum-c-node> sh_ref
                    $<TARGET_FILE:reticulum-c-sh> "${RNC_REFERENCE_DIR}" ${Python3_EXECUTABLE})
                set_tests_properties(reticulum_node_process_sh_rns
                    PROPERTIES LABELS "reticulum_interop;network" TIMEOUT 180)
                add_executable(test_ratchet_reference tests/test_ratchet_reference.c)
                target_link_libraries(test_ratchet_reference PRIVATE reticulum_c OpenSSL::Crypto)
                add_test(NAME reticulum_ratchet_file_rns COMMAND ${CMAKE_COMMAND} -E env
                    "PYTHONPATH=${RNC_REFERENCE_DIR}:${RNC_INTEROP_PYTHONPATH}"
                    $<TARGET_FILE:test_ratchet_reference> ${Python3_EXECUTABLE})
                set_tests_properties(reticulum_ratchet_file_rns PROPERTIES LABELS "reticulum_interop" TIMEOUT 60)
                add_test(NAME reticulum_cli_id_rns COMMAND ${CMAKE_COMMAND} -E env
                    "PYTHONPATH=${RNC_REFERENCE_DIR}:${RNC_INTEROP_PYTHONPATH}"
                    $<TARGET_FILE:test_node_process> $<TARGET_FILE:reticulum-c-ctl> cli_id_ref
                    "${RNC_REFERENCE_DIR}" ${Python3_EXECUTABLE})
                set_tests_properties(reticulum_cli_id_rns
                    PROPERTIES LABELS "reticulum_interop" TIMEOUT 60)
                add_test(NAME reticulum_node_process_backbone COMMAND ${CMAKE_COMMAND} -E env
                    "PYTHONPATH=${RNC_REFERENCE_DIR}:${RNC_INTEROP_PYTHONPATH}"
                    $<TARGET_FILE:test_node_process> $<TARGET_FILE:reticulum-c-node> backbone
                    "${RNC_REFERENCE_DIR}" ${Python3_EXECUTABLE})
                add_test(NAME reticulum_node_process_remote COMMAND ${CMAKE_COMMAND} -E env
                    "PYTHONPATH=${RNC_REFERENCE_DIR}:${RNC_INTEROP_PYTHONPATH}"
                    $<TARGET_FILE:test_node_process> $<TARGET_FILE:reticulum-c-node> remote
                    "${RNC_REFERENCE_DIR}" ${Python3_EXECUTABLE})
                add_test(NAME reticulum_node_process_source_ref COMMAND ${CMAKE_COMMAND} -E env
                    "PYTHONPATH=${RNC_REFERENCE_DIR}:${RNC_INTEROP_PYTHONPATH}"
                    $<TARGET_FILE:test_node_process> $<TARGET_FILE:reticulum-c-node> source_ref
                    "${RNC_REFERENCE_DIR}" ${Python3_EXECUTABLE})
                set_tests_properties(reticulum_node_process_source_ref
                    PROPERTIES LABELS "reticulum_interop;network" TIMEOUT 120)
                add_test(NAME reticulum_node_process_probe_ref COMMAND ${CMAKE_COMMAND} -E env
                    "PYTHONPATH=${RNC_REFERENCE_DIR}:${RNC_INTEROP_PYTHONPATH}"
                    $<TARGET_FILE:test_node_process> $<TARGET_FILE:reticulum-c-node> probe_ref
                    "${RNC_REFERENCE_DIR}" ${Python3_EXECUTABLE})
                set_tests_properties(reticulum_node_process_probe_ref
                    PROPERTIES LABELS "reticulum_interop;network" TIMEOUT 120)
                add_test(NAME reticulum_node_process_netid_ref COMMAND ${CMAKE_COMMAND} -E env
                    "PYTHONPATH=${RNC_REFERENCE_DIR}:${RNC_INTEROP_PYTHONPATH}"
                    $<TARGET_FILE:test_node_process> $<TARGET_FILE:reticulum-c-node> netid_ref
                    "${RNC_REFERENCE_DIR}" ${Python3_EXECUTABLE})
                set_tests_properties(reticulum_node_process_netid_ref
                    PROPERTIES LABELS "reticulum_interop" TIMEOUT 60)
                add_test(NAME reticulum_node_process_disc_ref COMMAND ${CMAKE_COMMAND} -E env
                    "PYTHONPATH=${RNC_REFERENCE_DIR}:${RNC_INTEROP_PYTHONPATH}"
                    $<TARGET_FILE:test_node_process> $<TARGET_FILE:reticulum-c-node> disc_ref
                    "${RNC_REFERENCE_DIR}" ${Python3_EXECUTABLE})
                set_tests_properties(reticulum_node_process_disc_ref
                    PROPERTIES LABELS "reticulum_interop;network" TIMEOUT 120)
                add_test(NAME reticulum_node_process_disc_listen_ref COMMAND ${CMAKE_COMMAND} -E env
                    "PYTHONPATH=${RNC_REFERENCE_DIR}:${RNC_INTEROP_PYTHONPATH}"
                    $<TARGET_FILE:test_node_process> $<TARGET_FILE:reticulum-c-node> disc_listen_ref
                    "${RNC_REFERENCE_DIR}" ${Python3_EXECUTABLE})
                set_tests_properties(reticulum_node_process_disc_listen_ref
                    PROPERTIES LABELS "reticulum_interop;network" TIMEOUT 180)
                add_test(NAME reticulum_node_process_tunnel_ref COMMAND ${CMAKE_COMMAND} -E env
                    "PYTHONPATH=${RNC_REFERENCE_DIR}:${RNC_INTEROP_PYTHONPATH}"
                    $<TARGET_FILE:test_node_process> $<TARGET_FILE:reticulum-c-node> tunnel_ref
                    "${RNC_REFERENCE_DIR}" ${Python3_EXECUTABLE})
                set_tests_properties(reticulum_node_process_tunnel_ref
                    PROPERTIES LABELS "reticulum_interop;network" TIMEOUT 120)
                add_test(NAME reticulum_rnode_multi_reference COMMAND
                    $<TARGET_FILE:test_rnode_multi> reference ${Python3_EXECUTABLE} "${RNC_REFERENCE_DIR}")
                set_tests_properties(reticulum_rnode_multi_reference
                    PROPERTIES LABELS "reticulum_interop;pty" TIMEOUT 120)
                add_test(NAME reticulum_weave_reference COMMAND
                    $<TARGET_FILE:test_weave> reference ${Python3_EXECUTABLE} "${RNC_REFERENCE_DIR}")
                set_tests_properties(reticulum_weave_reference
                    PROPERTIES LABELS "reticulum_interop;pty" TIMEOUT 120)
                add_test(NAME reticulum_node_process_i2p_ref COMMAND ${CMAKE_COMMAND} -E env
                    "PYTHONPATH=${RNC_REFERENCE_DIR}:${RNC_INTEROP_PYTHONPATH}"
                    $<TARGET_FILE:test_node_process> $<TARGET_FILE:reticulum-c-node> i2p_ref
                    $<TARGET_FILE:fake_sam> "${RNC_REFERENCE_DIR}" ${Python3_EXECUTABLE})
                set_tests_properties(reticulum_node_process_i2p_ref
                    PROPERTIES LABELS "reticulum_interop;network" TIMEOUT 400)
                set_tests_properties(reticulum_node_process_remote
                    PROPERTIES LABELS "reticulum_interop;network" TIMEOUT 120)
                set_tests_properties(reticulum_node_process_backbone
                    PROPERTIES LABELS "reticulum_interop;network" TIMEOUT 120)
            endif()
        endif()
    endif()
endif()
