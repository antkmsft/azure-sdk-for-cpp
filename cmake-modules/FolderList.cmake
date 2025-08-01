macro(GetFolderList project)
    message ("project found ${project}")
    message ("FLAG VALUE : ${FETCH_SOURCE_DEPS}")
    if(${project} STREQUAL CERTIFICATES)
        DownloadDepVersion(sdk/core azure-core 1.5.0)
        DownloadDepVersion(sdk/identity azure-identity 1.1.0)
    elseif(${project} STREQUAL IDENTITY)
        DownloadDepVersion(sdk/core azure-core 1.2.0)
    elseif(${project} STREQUAL SECRETS)
        DownloadDepVersion(sdk/core azure-core 1.5.0)
        DownloadDepVersion(sdk/identity azure-identity 1.1.0)
    elseif(${project} STREQUAL KEYS)
        DownloadDepVersion(sdk/core azure-core 1.5.0)
        DownloadDepVersion(sdk/identity azure-identity 1.1.0)
    elseif(${project} STREQUAL ADMINISTRATION)
        DownloadDepVersion(sdk/core azure-core 1.5.0)
        DownloadDepVersion(sdk/identity azure-identity 1.1.0)
    elseif(${project} STREQUAL STORAGE_COMMON)
        DownloadDepVersion(sdk/core azure-core 1.14.1)
    elseif(${project} STREQUAL STORAGE_BLOBS)
        DownloadDepVersion(sdk/core azure-core 1.14.1)
        DownloadDepVersion(sdk/storage/azure-storage-common azure-storage-common 12.10.0)
    elseif(${project} STREQUAL STORAGE_FILES_DATALAKE)
        DownloadDepVersion(sdk/core azure-core 1.13.0)
        DownloadDepVersion(sdk/storage/azure-storage-common azure-storage-common 12.8.0)
        DownloadDepVersion(sdk/storage/azure-storage-blobs azure-storage-blobs 12.13.0)
    elseif(${project} STREQUAL STORAGE_FILES_SHARES)
        DownloadDepVersion(sdk/core azure-core 1.14.1)
        DownloadDepVersion(sdk/storage/azure-storage-common azure-storage-common 12.10.0)
    elseif(${project} STREQUAL STORAGE_QUEUES)
        DownloadDepVersion(sdk/core azure-core 1.14.1)
        DownloadDepVersion(sdk/storage/azure-storage-common azure-storage-common 12.10.0)
    elseif(${project} STREQUAL DATA_TABLES)
        DownloadDepVersion(sdk/core azure-core 1.11.3)
    elseif(${project} STREQUAL EVENTHUBS)
        DownloadDepVersion(sdk/core azure-core 1.14.1)
        DownloadDepVersion(sdk/core azure-core-amqp 1.0.0-beta.9)
    elseif(${project} STREQUAL EVENTHUBS_CHECKPOINTSTORE_BLOB)
        DownloadDepVersion(sdk/core azure-core 1.10.1)
        DownloadDepVersion(sdk/core azure-core-amqp 1.0.0-beta.1)
        DownloadDepVersion(sdk/eventhubs azure-messaging-eventhubs 1.0.0-beta.3)
        DownloadDepVersion(sdk/storage/azure-storage-common azure-storage-common 12.3.3)
        DownloadDepVersion(sdk/storage/azure-storage-blobs azure-storage-blobs 12.8.0)
    endif()
    list(REMOVE_DUPLICATES BUILD_FOLDERS)
endmacro()

# Note: These CMake options are meant for contributors to the repo, and not end users.
macro(SetGlobalOptions)
    option(WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)
    option(BUILD_TRANSPORT_CURL "Build an HTTP transport implementation with CURL" OFF)
    option(BUILD_TRANSPORT_WINHTTP "Build an HTTP transport implementation with WIN HTTP" OFF)
    option(BUILD_TRANSPORT_CUSTOM "Implementation for AzureSdkGetCustomHttpTransport function must be linked to the final application" OFF)
    option(BUILD_TESTING "Build test cases. Not supported for production and is only meant for testing." OFF)
    option(BUILD_RTTI "Build libraries with run-time type information." ON)
    option(BUILD_CODE_COVERAGE "Build gcov targets for HTML and XML reports. Requires debug build and BUILD_TESTING" OFF)
    option(BUILD_DOCUMENTATION "Create HTML based API documentation (requires Doxygen)" OFF)
    option(BUILD_SAMPLES "Build sample application for Azure Storage clients" OFF)
    option(RUN_LONG_UNIT_TESTS "Tests that takes more than 5 minutes to complete. No effect if BUILD_TESTING is OFF" OFF)
    option(BUILD_PERFORMANCE_TESTS "Build the performance test library" OFF)
    option(MSVC_USE_STATIC_CRT "(MSVC only) Set to ON to link SDK with static CRT (/MT or /MTd switch)." OFF)
    option(FETCH_SOURCE_DEPS "fetch source dependencies for a package, not for global use, instead use when building specific component" OFF)
endmacro()

macro(SetCompileOptions project)
    message ("setting up compile options for ${project}")
    # Compile Options
    SetGlobalOptions()
    # When the SDK is being consumed via FolderList, an consumption mechanism alternative to vcpkg, do disable treating warnings as errors.
    SET(WARNINGS_AS_ERRORS OFF)
endmacro()

macro(DownloadDepVersion DEP_FOLDER DEP_NAME DEP_VERSION)

    file(REMOVE_RECURSE ${CMAKE_SOURCE_DIR}/build/${DEP_FOLDER})
    set(DOWNLOAD_FOLDER ${CMAKE_SOURCE_DIR}/build/downloads)
    set(DOWNLOAD_FILE ${DEP_NAME}_${DEP_VERSION}.zip)
    set(DEP_PREFIX azure-sdk-for-cpp)

    if(FETCH_SOURCE_DEPS STREQUAL "LATEST")
        SET(DOWNLOAD_MESSAGE "Downloading latest version of ${DEP_NAME}")
        #get the latest version from main
        SET(DOWNLOAD_LINK "http://github.com/Azure/azure-sdk-for-cpp/archive/main.zip")
    else()
        SET(DOWNLOAD_MESSAGE "Downloading version ${DEP_VERSION} of ${DEP_NAME}")
        # get the zip
        SET(DOWNLOAD_LINK "https://github.com/Azure/azure-sdk-for-cpp/archive/refs/tags/${DOWNLOAD_FILE}")
    endif()

    foreach(RETRY_ATTEMPT RANGE 2)
        math(EXPR RETRY_DELAY "10 * ${RETRY_ATTEMPT}" OUTPUT_FORMAT DECIMAL)
        if (RETRY_ATTEMPT GREATER 0)
            message("Waiting for ${RETRY_DELAY} seconds before retrying download.")
            execute_process(COMMAND ${CMAKE_COMMAND} -E sleep ${RETRY_DELAY})
        endif()

        message(${DOWNLOAD_MESSAGE})
        file(
            DOWNLOAD ${DOWNLOAD_LINK}
            ${DOWNLOAD_FOLDER}/${DOWNLOAD_FILE}
            SHOW_PROGRESS
            STATUS DOWNLOAD_STATUS
        )

        list(GET DOWNLOAD_STATUS 0 STATUS_CODE)
        if (${STATUS_CODE} EQUAL 0)
            break()
        else()
            list(GET DOWNLOAD_STATUS 1 ERROR_MESSAGE)
            message("Download failed with status code ${STATUS_CODE}: ${ERROR_MESSAGE}.")
        endif()
    endforeach()
    if (NOT ${STATUS_CODE} EQUAL 0)
        message(FATAL_ERROR "Dependency download failed (Link: ${DOWNLOAD_LINK}).")
    endif()

    #extract the zip
    file(ARCHIVE_EXTRACT INPUT ${DOWNLOAD_FOLDER}/${DOWNLOAD_FILE} DESTINATION ${DOWNLOAD_FOLDER}/${DEP_NAME})
    #make target folder
    file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/build/${DEP_FOLDER})
    
    # need a nicer way to copy/move folder 
    # i need to archive the folder then extract at new location
    if(FETCH_SOURCE_DEPS STREQUAL "LATEST")
        execute_process(COMMAND tar -cf  ${DOWNLOAD_FOLDER}/${DEP_NAME}.tar -C ${DOWNLOAD_FOLDER}/${DEP_NAME}/azure-sdk-for-cpp-main/${DEP_FOLDER} .)
    else()
        execute_process(COMMAND tar -cf  ${DOWNLOAD_FOLDER}/${DEP_NAME}.tar -C ${DOWNLOAD_FOLDER}/${DEP_NAME}/${DEP_PREFIX}-${DEP_NAME}_${DEP_VERSION}/${DEP_FOLDER} .)
    endif()
    
    file(ARCHIVE_EXTRACT INPUT ${DOWNLOAD_FOLDER}/${DEP_NAME}.tar DESTINATION ${CMAKE_SOURCE_DIR}/build/${DEP_FOLDER})
    #cleanup
    file(REMOVE_RECURSE ${DOWNLOAD_FOLDER})
    #add dependency folder to build list
    list(APPEND BUILD_FOLDERS build/${DEP_FOLDER})

endmacro()
