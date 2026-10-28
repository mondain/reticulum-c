# ESP-IDF component: the reticulum_c protocol core, mcu profile, portable crypto.
# Use it with  set(EXTRA_COMPONENT_DIRS <repo>/mcu/esp-idf/components)  in the
# project's top-level CMakeLists.txt, then REQUIRES reticulum_c.
get_filename_component(RNC_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)
include("${RNC_ROOT}/mcu/esp-idf/reticulum_c.cmake")
