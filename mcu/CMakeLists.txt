# MCU example application and its host build. Included from the top-level
# CMakeLists.txt only with -DRNC_PROFILE=mcu (the profile constants size public
# structs, so the application cannot share a build with the default profile).
#
#   cmake -S . -B build-mcu -DRNC_PROFILE=mcu -DRNC_CRYPTO=portable -DBUILD_TESTING=OFF
#   cmake --build build-mcu --target reticulum-c-mcu-host
#
# The ESP-IDF port compiles mcu/app/rnc_mcu_app.c with the same definitions; see
# mcu/esp-idf.
string(TIMESTAMP RNC_MCU_BUILD_EPOCH "%s" UTC)
# The LoRa radio support (mcu/radio): portable C, no platform headers, no dependency on
# the protocol core. The application uses it for its second interface.
add_library(rnc_lora STATIC radio/rnc_lora_phy.c radio/rnc_lora_air.c radio/rnc_lora_mac.c
    radio/rnc_lora_if.c radio/rnc_sx126x.c radio/rnc_sx127x.c radio/rnc_boards.c radio/rnc_radio.c)
target_include_directories(rnc_lora PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/radio)
if(NOT MSVC)
    target_compile_options(rnc_lora PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
add_library(rnc_mcu_app STATIC app/rnc_mcu_app.c)
target_include_directories(rnc_mcu_app PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/app)
target_link_libraries(rnc_mcu_app PUBLIC reticulum_c rnc_lora)
target_compile_definitions(rnc_mcu_app PUBLIC RNC_MCU_BUILD_EPOCH=${RNC_MCU_BUILD_EPOCH}u
    RNC_MCU_VERSION="${PROJECT_VERSION}")
if(NOT MSVC)
    target_compile_options(rnc_mcu_app PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
# Models of the radio chips and a shared simulated channel: test support, also used by the
# host harness (--lora) for the gateway test.
add_library(rnc_lora_sim STATIC tests/radio/lora_sim.c tests/radio/sx126x_model.c
    tests/radio/sx127x_model.c tests/radio/sim_board.c)
target_link_libraries(rnc_lora_sim PUBLIC rnc_lora m)
target_compile_options(rnc_lora_sim PRIVATE -Wall -Wextra -Wpedantic -Werror)
# The unit tests are built with BUILD_TESTING, or on request (mcu/tests/mcu_unit.sh,
# which the default build's ctest runs, sets RNC_MCU_UNIT_TESTS).
option(RNC_MCU_UNIT_TESTS "Build the MCU application's unit tests" OFF)
if(BUILD_TESTING OR RNC_MCU_UNIT_TESTS)
    add_executable(test_mcu_clock tests/test_clock.c)
    target_link_libraries(test_mcu_clock PRIVATE rnc_mcu_app)
    target_compile_options(test_mcu_clock PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_executable(test_mcu_link tests/test_link.c)
    target_link_libraries(test_mcu_link PRIVATE rnc_mcu_app)
    target_compile_options(test_mcu_link PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_executable(test_mcu_net tests/test_net.c)
    target_link_libraries(test_mcu_net PRIVATE rnc_mcu_app)
    target_compile_options(test_mcu_net PRIVATE -Wall -Wextra -Wpedantic -Werror)
    # LoRa: the tests of the radio core, the drivers, the interface and the application over
    # simulated LoRa (the models are rnc_lora_sim, built below)
    foreach(t radio_core radio_drivers radio_sim radio_app)
        add_executable(test_mcu_${t} tests/test_${t}.c)
        target_link_libraries(test_mcu_${t} PRIVATE rnc_lora_sim rnc_mcu_app)
        target_compile_options(test_mcu_${t} PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endforeach()
    if(BUILD_TESTING)
        foreach(t radio_core radio_drivers radio_sim radio_app)
            add_test(NAME reticulum_mcu_${t} COMMAND test_mcu_${t})
            set_tests_properties(reticulum_mcu_${t} PROPERTIES LABELS mcu TIMEOUT 900)
        endforeach()
    endif()
    if(BUILD_TESTING)
        add_test(NAME reticulum_mcu_net COMMAND test_mcu_net)
        set_tests_properties(reticulum_mcu_net PROPERTIES LABELS mcu)
        add_test(NAME reticulum_mcu_clock COMMAND test_mcu_clock)
        set_tests_properties(reticulum_mcu_clock PROPERTIES LABELS mcu)
        add_test(NAME reticulum_mcu_link COMMAND test_mcu_link)
        set_tests_properties(reticulum_mcu_link PROPERTIES LABELS mcu)
    endif()
endif()
if(UNIX)
    add_executable(reticulum-c-mcu-host host/main.c host/lora_host.c)
    target_link_libraries(reticulum-c-mcu-host PRIVATE rnc_mcu_app rnc_lora_sim)
    target_compile_options(reticulum-c-mcu-host PRIVATE -Wall -Wextra -Wpedantic -Werror)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_link_libraries(reticulum-c-mcu-host PRIVATE m)
    endif()
endif()
