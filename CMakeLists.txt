# Specify the minimum required version of CMake
cmake_minimum_required(VERSION 3.10.2)

# Define the project name
project(CHUKEI-DNS)

# Build options
option(BUILD_TESTS "Build and run tests" OFF)

# Validate mutually exclusive platform flags and required SDK paths
if(ORBIS AND PROSPERO)
    message(FATAL_ERROR "ORBIS and PROSPERO cannot both be set. Please specify only one target platform.")
endif()
if(ORBIS)
    if(NOT DEFINED ENV{PS4_PAYLOAD_SDK})
        message(FATAL_ERROR "ORBIS build requires the PS4_PAYLOAD_SDK environment variable to be set.")
    endif()
    if(NOT EXISTS "$ENV{PS4_PAYLOAD_SDK}")
        message(FATAL_ERROR "PS4_PAYLOAD_SDK path does not exist: $ENV{PS4_PAYLOAD_SDK}")
    endif()
endif()
if(PROSPERO)
    if(NOT DEFINED ENV{PS5_PAYLOAD_SDK})
        message(FATAL_ERROR "PROSPERO build requires the PS5_PAYLOAD_SDK environment variable to be set.")
    endif()
    if(NOT EXISTS "$ENV{PS5_PAYLOAD_SDK}")
        message(FATAL_ERROR "PS5_PAYLOAD_SDK path does not exist: $ENV{PS5_PAYLOAD_SDK}")
    endif()
endif()

# Set the output directory for executables and archives under build/
set(BUILD_OUTPUT_DIR ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BUILD_OUTPUT_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${BUILD_OUTPUT_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${BUILD_OUTPUT_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${BUILD_OUTPUT_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${BUILD_OUTPUT_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG ${BUILD_OUTPUT_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE ${BUILD_OUTPUT_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_DEBUG ${BUILD_OUTPUT_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE ${BUILD_OUTPUT_DIR}/lib)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(WARNING "In-source build detected. Generated CMake files will stay in the source tree unless you configure out-of-source.")
    message(WARNING "To put build files under ${BUILD_OUTPUT_DIR}, run:")
    message(WARNING "  cmake -S ${CMAKE_SOURCE_DIR} -B ${BUILD_OUTPUT_DIR} -DCMAKE_BUILD_TYPE=Debug")
    message(WARNING "  cmake --build ${BUILD_OUTPUT_DIR} -- -j$(nproc)")
endif()

# Set the default build type to Debug if not specified, and ensure it's valid
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()
if(NOT (CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "Release"))
    message(FATAL_ERROR "Please specify a build type of either \"Release\" or \"Debug\"\nCurrent Value: ${CMAKE_BUILD_TYPE}")
endif()
message("-- Build Type: ${CMAKE_BUILD_TYPE}")

# Require C++17 or greater, and enforce no compiler extensions (e.g., GNU extensions)
if(NOT CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 17)
endif()
if(CMAKE_CXX_STANDARD LESS 17)
    message(FATAL_ERROR "Incompatible with C++${CMAKE_CXX_STANDARD}. Requires C++17 or greater.")
endif()
set(CMAKE_CXX_EXTENSIONS OFF)

# Build wolfSSL from the vendored submodule during CMake configure so that
# curl's feature-detection (which runs at configure time via add_subdirectory)
# can find the library and its headers. ExternalProject_Add cannot be used here
# because it only executes at build time, which is too late for curl's cmake.
include(ProcessorCount)
ProcessorCount(NPROC)
if(NPROC EQUAL 0)
    set(NPROC 1)
endif()

set(WOLFSSL_INSTALL_PREFIX ${BUILD_OUTPUT_DIR}/wolfssl-install)
set(WOLFSSL_LIBDIR ${WOLFSSL_INSTALL_PREFIX}/lib)

if(NOT EXISTS ${WOLFSSL_LIBDIR}/libwolfssl.a)
    message(STATUS "wolfSSL not found - building from submodule (this may take a moment)...")

    set(_wolfssl_cmake_args
        -DCMAKE_INSTALL_PREFIX=${WOLFSSL_INSTALL_PREFIX}
        -DCMAKE_BUILD_TYPE=Release
        -DBUILD_SHARED_LIBS=OFF
        -DWOLFSSL_CURL=ON
        -DWOLFSSL_TLS13=ON
        -DWOLFSSL_SNI=ON
        -DWOLFSSL_ALPN=ON
        -DWOLFSSL_TLSX=ON
        -DWOLFSSL_SESSION_TICKET=ON
        -DWOLFSSL_ALT_CERT_CHAINS=ON
        -DWOLFSSL_EXAMPLES=no
        -DWOLFSSL_CRYPT_TESTS=no
        -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
    )
    # Forward the active toolchain file so cross-compiles (e.g. PS4/PS5) use the correct compiler, sysroot, and flags for the *target*, not the host.
    if(CMAKE_TOOLCHAIN_FILE)
        list(APPEND _wolfssl_cmake_args -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE})
    endif()

    execute_process(
        COMMAND ${CMAKE_COMMAND}
            ${_wolfssl_cmake_args}
            -S ${CMAKE_SOURCE_DIR}/external/wolfssl
            -B ${BUILD_OUTPUT_DIR}/wolfssl-build
        RESULT_VARIABLE _wolfssl_configure_result
    )
    if(NOT _wolfssl_configure_result EQUAL 0)
        message(FATAL_ERROR "wolfSSL configure failed (exit ${_wolfssl_configure_result})")
    endif()

    execute_process(
        COMMAND ${CMAKE_COMMAND}
            --build ${BUILD_OUTPUT_DIR}/wolfssl-build
            --parallel ${NPROC}
            --target install
        RESULT_VARIABLE _wolfssl_build_result
    )
    if(NOT _wolfssl_build_result EQUAL 0)
        message(FATAL_ERROR "wolfSSL build failed (exit ${_wolfssl_build_result})")
    endif()

    message(STATUS "wolfSSL installed to ${WOLFSSL_INSTALL_PREFIX}")
endif()

# Pre-seed curl's FindWolfSSL variables so it uses our vendored build and never falls back to anything from the host system.
set(WOLFSSL_INCLUDE_DIR ${WOLFSSL_INSTALL_PREFIX}/include CACHE PATH "" FORCE)
set(WOLFSSL_LIBRARY ${WOLFSSL_LIBDIR}/libwolfssl.a CACHE FILEPATH "" FORCE)

# Build cURL from the vendored submodule, using the vendored wolfSSL above.
# Explicitly disable every other TLS backend so curl cannot pick up host libs.
set(BUILD_CURL_EXE     OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS  OFF CACHE BOOL "" FORCE)
set(BUILD_TESTING      OFF CACHE BOOL "" FORCE)
set(CURL_DISABLE_TESTS ON  CACHE BOOL "" FORCE)
set(CURL_USE_LIBPSL    OFF CACHE BOOL "" FORCE)
set(CURL_USE_WOLFSSL   ON  CACHE BOOL "" FORCE)
set(CURL_USE_OPENSSL   OFF CACHE BOOL "" FORCE)
set(CURL_USE_GNUTLS    OFF CACHE BOOL "" FORCE)
set(CURL_USE_NSS       OFF CACHE BOOL "" FORCE)
set(CURL_USE_SECTRANSP OFF CACHE BOOL "" FORCE)
set(CURL_USE_SCHANNEL  OFF CACHE BOOL "" FORCE)
# Disable zlib - curl uses it only for HTTP Content-Encoding decompression, which this DoH relay does not need. Disabling it removes the last dependency on a host-system library so the build is fully self-contained.
set(CURL_ZLIB          OFF CACHE BOOL "" FORCE)
add_subdirectory(${CMAKE_SOURCE_DIR}/external/curl ${BUILD_OUTPUT_DIR}/curl EXCLUDE_FROM_ALL)

# Set platform-specific preprocessor definitions and print the selected platform
if(ORBIS)
    add_compile_definitions(__ORBIS__)
    message("-- Platform Type: Orbis (PlayStation 4)")
elseif(PROSPERO)
    add_compile_definitions(__PROSPERO__)
    message("-- Platform Type: Prospero (PlayStation 5)")
else()
    add_compile_definitions(__LIBLOG_PC__)
    message("-- Platform Type: PC (default)")
endif()

# Set compiler flags for warnings, errors, and optimization/debugging
if(MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /Wall /WX /D_SDL_BANNED_RECOMMENDED=true")
    set(CMAKE_CXX_FLAGS_DEBUG "/Od /Z7") # Disable optimization, enable debug info
    set(CMAKE_CXX_FLAGS_RELEASE "/Ox -DNDEBUG") # Full optimization, disable debug
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror -D_SDL_BANNED_RECOMMENDED=true")
    set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g -fprofile-instr-generate -fcoverage-mapping") # Disable optimization, enable debug info, enable coverage
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG") # High optimization, disable debug
endif()

# Add include directories for external dependencies and project headers
include_directories(
    ${CMAKE_SOURCE_DIR}/external/asio/asio/include   # ASIO networking library
    ${CMAKE_SOURCE_DIR}/external/banned              # SDL banned functions
    ${CMAKE_SOURCE_DIR}/external/curl/include        # curl
    ${CMAKE_SOURCE_DIR}/external/json/single_include # nlohmann/json
    ${CMAKE_SOURCE_DIR}/external/libLog/include      # libLog logging library
    ${CMAKE_SOURCE_DIR}/include                      # Project headers
)

# Build the external libLog library
#
# For console platforms (Orbis/Prospero) we compile libLog.c directly as a
# CMake static library instead of shelling out to the submodule's own Makefile.
# This avoids requiring the OO_PS4_TOOLCHAIN. PS4_PAYLOAD_SDK does not ship
# an orbis/libkernel.h header, so the project provides a minimal shim in
# include/orbis/libkernel.h that forward-declares sceKernelDebugOutText
# (the symbol itself is exported by the SDK's libkernel.so stub).
if(ORBIS OR PROSPERO)
    add_library(libLog STATIC
        ${CMAKE_SOURCE_DIR}/external/libLog/src/libLog.c
    )
    target_include_directories(libLog PRIVATE
        ${CMAKE_SOURCE_DIR}/external/libLog/include # libLog's own header
        ${CMAKE_SOURCE_DIR}/include                 # orbis/libkernel.h shim
    )
    target_compile_options(libLog PRIVATE -std=c99 -D_DEFAULT_SOURCE)
    target_compile_definitions(libLog PRIVATE "LOG_SOURCE_ROOT=\"${CMAKE_SOURCE_DIR}/\"")
    set_target_properties(libLog PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${BUILD_OUTPUT_DIR}/lib)
    # Provide a no-op custom target so add_dependencies(... libLog_build) still works
    add_custom_target(libLog_build DEPENDS libLog)
    set(LIBLOG_ARTIFACT libLog)
else()
    add_custom_target(
        libLog_build
        COMMAND $(MAKE) -f Makefile.pc
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/external/libLog
        COMMENT "Building libLog with it's Makefile"
    )
    set(LIBLOG_ARTIFACT ${CMAKE_SOURCE_DIR}/external/libLog/build/libLog.o)
endif()

# Add the main source directory for building the project
add_subdirectory(${CMAKE_SOURCE_DIR}/src)

# Add tests if requested (not available for cross-compiled targets)
if(BUILD_TESTS AND NOT CMAKE_CROSSCOMPILING)
    add_subdirectory(${CMAKE_SOURCE_DIR}/tests)
endif()
