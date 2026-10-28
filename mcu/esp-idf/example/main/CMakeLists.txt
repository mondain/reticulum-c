if(IDF_TARGET STREQUAL "esp32s3")
    set(rnc_usb_req esp_driver_usb_serial_jtag)
endif()
idf_component_register(
    SRCS main.c
    INCLUDE_DIRS .
    REQUIRES reticulum_c_mcu_app driver nvs_flash esp_timer esp_system esp_hw_support
             bootloader_support ${rnc_usb_req})
