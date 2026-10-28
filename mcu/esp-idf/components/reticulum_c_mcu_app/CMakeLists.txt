# ESP-IDF component wrapping the portable example application (mcu/app).
get_filename_component(RNC_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)
file(STRINGS "${RNC_ROOT}/CMakeLists.txt" RNC_PROJECT_LINE REGEX "^project\\(reticulum_c VERSION")
string(REGEX REPLACE ".*VERSION ([0-9.]+).*" "\\1" RNC_VERSION "${RNC_PROJECT_LINE}")
string(TIMESTAMP RNC_MCU_BUILD_EPOCH "%s" UTC)
idf_component_register(
    SRCS "${RNC_ROOT}/mcu/app/rnc_mcu_app.c"
    INCLUDE_DIRS "${RNC_ROOT}/mcu/app"
    REQUIRES reticulum_c)
target_compile_definitions(${COMPONENT_LIB} PUBLIC
    RNC_MCU_BUILD_EPOCH=${RNC_MCU_BUILD_EPOCH}u
    RNC_MCU_VERSION="${RNC_VERSION}")
