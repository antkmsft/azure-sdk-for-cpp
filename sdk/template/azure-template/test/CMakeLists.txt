# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

cmake_minimum_required (VERSION 3.13)

project (azure-template-test LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_compile_definitions(AZURE_TEST_DATA_PATH="${CMAKE_BINARY_DIR}")

include(GoogleTest)

add_executable (
     azure-template-test
     ut/macro_guard.cpp
     ut/template_test.cpp
     )

target_compile_definitions(azure-template-test PRIVATE _azure_BUILDING_TESTS)

create_per_service_target_build(template azure-template-test)
create_map_file(azure-template-test azure-template-test.map)

target_link_libraries(azure-template-test PRIVATE Azure::azure-template gtest_main)

if (MSVC)
    target_compile_options(azure-template-test PUBLIC /wd6326 /wd26495 /wd26812)
endif()

gtest_discover_tests(azure-template-test 
     TEST_PREFIX azure-template.
     DISCOVERY_TIMEOUT 600)
