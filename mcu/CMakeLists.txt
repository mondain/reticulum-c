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
add_library(rnc_mcu_app STATIC app/rnc_mcu_app.c)
target_include_directories(rnc_mcu_app PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/app)
target_link_libraries(rnc_mcu_app PUBLIC reticulum_c)
target_compile_definitions(rnc_mcu_app PUBLIC RNC_MCU_BUILD_EPOCH=${RNC_MCU_BUILD_EPOCH}u
    RNC_MCU_VERSION="${PROJECT_VERSION}")
if(NOT MSVC)
    target_compile_options(rnc_mcu_app PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
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
    add_executable(reticulum-c-mcu-host host/main.c)
    target_link_libraries(reticulum-c-mcu-host PRIVATE rnc_mcu_app)
    target_compile_options(reticulum-c-mcu-host PRIVATE -Wall -Wextra -Wpedantic -Werror)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_link_libraries(reticulum-c-mcu-host PRIVATE m)
    endif()
endif()
