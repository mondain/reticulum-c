cmake_minimum_required(VERSION 3.16)
# The reticulum_c core and the portable MCU application are components in
# ../components.
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../components")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(reticulum_c_mcu)
