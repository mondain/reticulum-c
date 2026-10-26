# Install, move, then build/run an external consumer. No source-tree fallback.
set(work "${RNC_BUILD_ROOT}/consumer-test")
file(REMOVE_RECURSE "${work}")
file(MAKE_DIRECTORY "${work}")
execute_process(COMMAND "${CMAKE_COMMAND}" --install "${RNC_BUILD_ROOT}" --prefix "${work}/original"
    --config "${RNC_CONFIG}" RESULT_VARIABLE status)
if(NOT status EQUAL 0)
    message(FATAL_ERROR "SDK installation failed")
endif()
file(RENAME "${work}/original" "${work}/relocated")
execute_process(COMMAND "${CMAKE_COMMAND}" -S "${RNC_SOURCE_ROOT}/tests/consumer" -B "${work}/build"
    "-DCMAKE_C_COMPILER=${RNC_TEST_CC}" "-DCMAKE_PREFIX_PATH=${work}/relocated"
    -DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF -DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF
    RESULT_VARIABLE status)
if(NOT status EQUAL 0)
    message(FATAL_ERROR "Installed SDK consumer configuration failed")
endif()
execute_process(COMMAND "${CMAKE_COMMAND}" --build "${work}/build" --config "${RNC_CONFIG}"
    RESULT_VARIABLE status)
if(NOT status EQUAL 0)
    message(FATAL_ERROR "Installed SDK consumer compilation/linking failed")
endif()
execute_process(COMMAND "${CMAKE_CTEST_COMMAND}" --test-dir "${work}/build" -C "${RNC_CONFIG}"
    --output-on-failure RESULT_VARIABLE status)
if(NOT status EQUAL 0)
    message(FATAL_ERROR "Installed SDK consumer execution failed")
endif()
