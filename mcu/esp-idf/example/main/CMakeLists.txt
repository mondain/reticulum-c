if(IDF_TARGET STREQUAL "esp32s3")
    set(rnc_usb_req esp_driver_usb_serial_jtag)
endif()
idf_component_register(
    SRCS main.c serial_port.c net_settings.c provision.c wifi_transport.c radio_hal_idf.c
    INCLUDE_DIRS .
    REQUIRES reticulum_c_mcu_app driver esp_driver_gpio nvs_flash esp_timer esp_system
             esp_hw_support bootloader_support esp_wifi esp_netif esp_event lwip
             ${rnc_usb_req})
