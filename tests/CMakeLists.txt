# Specify the minimum required version of CMake
cmake_minimum_required(VERSION 3.10.2)

project(CHUKEI-DNS-TESTS LANGUAGES CXX)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}                        # Test headers (test_framework.h)
    ${CMAKE_SOURCE_DIR}/external/asio/asio/include/    # ASIO networking library
    ${CMAKE_SOURCE_DIR}/external/banned                # SDL banned functions
    ${CMAKE_SOURCE_DIR}/external/curl/include          # curl
    ${CMAKE_SOURCE_DIR}/external/json/single_include   # nlohmann/json
    ${CMAKE_SOURCE_DIR}/external/libLog/include        # libLog logging library
    ${CMAKE_SOURCE_DIR}/include                        # Project headers
    ${CMAKE_BINARY_DIR}/include                        # Generated headers (default_json.h)
)

# Test source files
set(TEST_SOURCES
    test_main.cc
    test_utils.cc
    test_dns_parser.cc
    test_dns_response.cc
    test_local_dns.cc
    test_config.cc
    test_config_parser.cc
    test_dns_packet.cc
    test_dns_over_https.cc
    test_dns_cache.cc
)

# Create test executable
add_executable(run_tests ${TEST_SOURCES})

# Link against the CHUKEI static library, libLog, and curl
target_link_libraries(run_tests
    PRIVATE
        CHUKEI
        ${LIBLOG_ARTIFACT}
        CURL::libcurl
)

# Ensure CHUKEI and libLog are built first
add_dependencies(run_tests CHUKEI libLog_build)

# Register with CTest
enable_testing()
add_test(NAME ChukeiDnsTests COMMAND run_tests)
