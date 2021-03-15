# Copyright (c) Microsoft Corporation. All rights reserved.
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.13)
project(custom_managed_identity_credential LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_executable(
     custom_managed_identity_credential
     src/custom_managed_identity_credential.cpp
)

target_link_libraries(custom_managed_identity_credential PRIVATE Azure::azure-core)
#target_link_libraries(custom_managed_identity_credential PRIVATE azure-storage-blobs)
