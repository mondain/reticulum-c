# ESP-IDF component wrapping the portable example application (mcu/app).
get_filename_component(RNC_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)
file(STRINGS "${RNC_ROOT}/CMakeLists.txt" RNC_PROJECT_LINE REGEX "^project\\(reticulum_c VERSION")
string(REGEX REPLACE ".*VERSION ([0-9.]+).*" "\\1" RNC_VERSION "${RNC_PROJECT_LINE}")
string(TIMESTAMP RNC_MCU_BUILD_EPOCH "%s" UTC)
# The LoRa radio support (mcu/radio) is part of the component: portable C with no platform
# headers; the example's HAL (spi_master, gpio, esp_timer) lives in the example project.
set(RNC_RADIO_SRCS rnc_lora_phy.c rnc_lora_air.c rnc_lora_mac.c rnc_lora_if.c rnc_sx126x.c
    rnc_sx127x.c rnc_boards.c rnc_radio.c)
set(RNC_RADIO_LIST "")
foreach(s ${RNC_RADIO_SRCS})
    list(APPEND RNC_RADIO_LIST "${RNC_ROOT}/mcu/radio/${s}")
endforeach()
idf_component_register(
    SRCS "${RNC_ROOT}/mcu/app/rnc_mcu_app.c" ${RNC_RADIO_LIST}
    INCLUDE_DIRS "${RNC_ROOT}/mcu/app" "${RNC_ROOT}/mcu/radio"
    REQUIRES reticulum_c)
target_compile_definitions(${COMPONENT_LIB} PUBLIC
    RNC_MCU_BUILD_EPOCH=${RNC_MCU_BUILD_EPOCH}u
    RNC_MCU_VERSION="${RNC_VERSION}")
