# Specify the minimum required version of CMake
cmake_minimum_required(VERSION 3.10.2)

# Define the project and its metadata (not strictly required for subdirectories, but useful for documentation)
project(main
    VERSION 0.9.0
    DESCRIPTION "Internal DNS relay for DoH with blocking and hijacking built in"
    HOMEPAGE_URL "https://github.com/Al-Azif/chukei-dns"
    LANGUAGES CXX
)

# Project metadata variables (for use in configure_file or documentation)
set(PROJECT_NICE_NAME "Chūkei DNS")
set(PROJECT_AUTHOR "Al Azif")
set(PROJECT_LICENSE "GPLv3")
set(PROJECT_BUILD_TYPE ${CMAKE_BUILD_TYPE})

# Generate a header with build variables from a template
configure_file(
    ${CMAKE_SOURCE_DIR}/include/cmake_vars.h.in
    ${CMAKE_SOURCE_DIR}/include/cmake_vars.h
    @ONLY
)

# Read the default DNS zones JSON file into a variable, then generate a header from a template
file(READ ${CMAKE_SOURCE_DIR}/zones.json ZONES_JSON_CONTENT)
configure_file(
    ${CMAKE_SOURCE_DIR}/include/default_json.h.in
    ${CMAKE_BINARY_DIR}/include/default_json.h
    @ONLY
)

# For console platforms (Orbis/Prospero) that cannot access the system certificate
# store at runtime, embed the Mozilla CA bundle as a compile-time C header so
# curl can verify TLS connections using CURLOPT_CAINFO_BLOB.
if(ORBIS OR PROSPERO)
    set(_CACERT_PEM "${CMAKE_SOURCE_DIR}/certs/cacert.pem")
    set(_CACERT_HEADER "${CMAKE_BINARY_DIR}/include/cacert_bundle.h")
    message(STATUS "Generating bundled CA certificate header for console platform...")
    execute_process(
        COMMAND ${CMAKE_COMMAND}
            -DCACERT_PEM=${_CACERT_PEM}
            -DCACERT_HEADER=${_CACERT_HEADER}
            -P ${CMAKE_SOURCE_DIR}/cmake/GenerateCacertBundle.cmake
        RESULT_VARIABLE _cacert_result
    )
    if(NOT _cacert_result EQUAL 0)
        message(FATAL_ERROR "Failed to generate cacert bundle header (exit ${_cacert_result})")
    endif()
endif()

# Create a static library 'CHUKEI' from the core source files (excluding main.cc)
add_library(CHUKEI
    config.cc
    config_parser.cc
    dns_cache.cc
    dns_over_https.cc
    dns_packet.cc
    dns_packet_answer.cc
    dns_packet_header.cc
    dns_packet_question.cc
    dns_parser.cc
    dns_response.cc
    local_dns.cc
    tcp_server.cc
    udp_server.cc
    utils.cc
)

# Select the platform-specific entry point
if(ORBIS OR PROSPERO)
    set(MAIN_SOURCE main-ps.cc)
else()
    set(MAIN_SOURCE main-pc.cc)
endif()

# Create the main executable
add_executable(main ${MAIN_SOURCE})

# Link the main executable with:
# - the CHUKEI static library
# - the external libLog artifact (path varies by platform, set in root CMakeLists)
# - the curl library built from submodule
target_link_libraries(main
    PRIVATE
        CHUKEI
        ${LIBLOG_ARTIFACT}
        CURL::libcurl
)

# For console platforms, name the output as an .elf and link required SCE/system libraries
if(ORBIS)
    set_target_properties(main PROPERTIES OUTPUT_NAME "chukei-ps4.elf")
    target_link_libraries(main
        PRIVATE
            -lSceNet
            -lSceLibcInternal
            -lkernel
    )
elseif(PROSPERO)
    set_target_properties(main PROPERTIES OUTPUT_NAME "chukei-ps5.elf")
    target_link_libraries(main
        PRIVATE
            -lSceNet
            -lSceLibcInternal
            -lkernel_web
    )
endif()

# Ensure libLog is built before building the main executable
add_dependencies(main libLog_build)
