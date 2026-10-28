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
if(UNIX)
    add_executable(reticulum-c-mcu-host host/main.c)
    target_link_libraries(reticulum-c-mcu-host PRIVATE rnc_mcu_app)
    target_compile_options(reticulum-c-mcu-host PRIVATE -Wall -Wextra -Wpedantic -Werror)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_link_libraries(reticulum-c-mcu-host PRIVATE m)
    endif()
endif()
