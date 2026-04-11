/** @file constants.h
 *  @brief Compile-time constants for application settings, network parameters, and DNS protocol values.
 */

#ifndef CONSTANTS_H_
#define CONSTANTS_H_

#include <netinet/in.h> // in_addr, in6_addr, INET_ADDRSTRLEN, INET6_ADDRSTRLEN

#include <cstddef> // std::size_t
#include <cstdint> // int32_t, uint16_t

/** @brief Top-level namespace for all compile-time constants used throughout the project. */
namespace Constants {

/** @brief Application identity and user-agent template constants. */
namespace App {
constexpr std::size_t MAX_APP_VERSION_LENGTH{128};
constexpr std::size_t MAX_CONSOLE_NAME_LENGTH{32};
constexpr std::size_t MAX_FIRMWARE_VERSION_LENGTH{32};
constexpr char MIN_PRINTABLE_ASCII{0x20};
constexpr char MAX_PRINTABLE_ASCII{0x7E};
constexpr const char *USERAGENT_TEMPLATE_SIMPLE{"chukei/{{APP_VERSION}} ({{CONSOLE}})"};
constexpr const char *USERAGENT_TEMPLATE_FULL{"chukei/{{APP_VERSION}} ({{CONSOLE}} {{FIRMWARE_VERSION}})"};
} // namespace App

/** @brief Network-related constants including port ranges, TTL limits, and IP address defaults. */
namespace Network {
constexpr uint16_t MIN_DNS_PORT{1};
constexpr uint16_t MAX_DNS_PORT{65535};
constexpr int32_t MIN_TTL{0};
constexpr int32_t MAX_TTL{604800}; // 7 days
constexpr int32_t DEFAULT_TTL{3600}; // 1 hour
constexpr uint16_t DEFAULT_DNS_PORT{53};
constexpr const char *DEFAULT_DNS_IP{"127.0.0.1"};
constexpr const char *DEFAULT_IPV4_REDIRECT{"127.0.0.1"};
constexpr const char *DEFAULT_IPV6_REDIRECT{"::1"};
constexpr const char *HTTPS_PREFIX{"https://"};
constexpr int DEFAULT_DOH_TIMEOUT_MS{15000}; // 15 seconds total budget
constexpr int MIN_DOH_TIMEOUT_MS{100};
constexpr int MAX_DOH_TIMEOUT_MS{60000};
constexpr std::size_t MAX_IPV4_STRING_LENGTH{INET_ADDRSTRLEN - 1};
constexpr std::size_t MAX_IPV6_STRING_LENGTH{INET6_ADDRSTRLEN - 1};
constexpr std::size_t IPV4_BINARY_SIZE{sizeof(struct in_addr)};
constexpr std::size_t IPV6_BINARY_SIZE{sizeof(struct in6_addr)};
} // namespace Network

/** @brief Default DNS-over-HTTPS resolver URLs for well-known public providers. */
namespace Doh {
constexpr const char *CLOUDFLARE_DOH_PRIMARY{"https://1.1.1.1/dns-query"};
constexpr const char *CLOUDFLARE_DOH_SECONDARY{"https://1.0.0.1/dns-query"};
constexpr const char *GOOGLE_DOH_PRIMARY{"https://8.8.8.8/dns-query"};
constexpr const char *GOOGLE_DOH_SECONDARY{"https://8.8.4.4/dns-query"};
constexpr const char *QUAD9_DOH{"https://9.9.9.9/dns-query"};
} // namespace Doh

/** @brief Default filesystem paths for configuration and zone data. */
namespace Paths {
#if defined(__ORBIS__) || defined(__PROSPERO__)
constexpr const char *DEFAULT_CONFIG_PATH{"/data/chukei/config.json"};
constexpr const char *DEFAULT_ZONES_PATH{"/data/chukei/zones.json"};
#else
constexpr const char *DEFAULT_ZONES_PATH{"./zones.json"};
#endif
} // namespace Paths

/** @brief Default CA certificate bundle paths for TLS verification. */
namespace Certs {
#if defined(__ORBIS__) || defined(__PROSPERO__)
constexpr const char *DEFAULT_CACERT_PATH{"/data/chukei/cacert.pem"};
#else
constexpr const char *DEFAULT_CACERT_PATH{""};
#endif
} // namespace Certs

/** @brief DNS protocol constants including response codes, record types, compression pointers, and packet size limits. */
namespace Dns {
// Domain pattern strings for label-type classification
constexpr const char *ROOT_DOMAIN_PATTERN{"^(.*\\.)*(.*\\..*[^\\.])$"};
constexpr const char *SUB_DOMAIN_PATTERN{"^(.*\\.?)\\.(.*\\..*[^\\.])$"};

// DNS name compression pointer following
constexpr int DNS_MAX_POINTER_HOPS{16}; // Prevent infinite loops from malicious packets (RFC 1035 §4.1.4)

// CNAME chain following
constexpr int DNS_MAX_CNAME_DEPTH{8}; // RFC 1034 limits chain depth; 8 prevents infinite loops

// Compiled-regex LRU/eviction cache for zone pattern matching
constexpr std::size_t DNS_REGEX_CACHE_SIZE{1024};

// DNS-over-HTTPS response size cap (max DNS message size over TCP/DoH, 64 KiB)
constexpr std::size_t MAX_DOH_RESPONSE_SIZE{65535};

// EDNS0 cookie option (RFC 7873)
constexpr uint16_t EDNS_OPTION_CODE_COOKIE{10};
constexpr uint16_t EDNS_COOKIE_MIN_LENGTH{8};  // 8-byte client cookie (minimum)
constexpr uint16_t EDNS_COOKIE_MAX_LENGTH{40}; // 8-byte client + up-to-32-byte server cookie

// DNS Response Codes (RCODE values, RFC 1035 §4.1.1)
constexpr uint16_t DNS_RCODE_NOERROR{0};  // No Error
constexpr uint16_t DNS_RCODE_FORMERR{1};  // Format Error
constexpr uint16_t DNS_RCODE_SERVFAIL{2}; // Server Failure
constexpr uint16_t DNS_RCODE_NXDOMAIN{3}; // Non-Existent Domain
constexpr uint16_t DNS_RCODE_NOTIMP{4};   // Not Implemented
constexpr uint16_t DNS_RCODE_REFUSED{5};  // Query Refused

// Legacy full response flag words (QR=1, AA=1, RD=1, RA=1 + RCODE) - for authoritative responses
constexpr uint16_t DNS_RESPONSE_NOERROR{0x8580}; // No Error (AA=1)
constexpr uint16_t DNS_RESPONSE_FORMERR{0x8181}; // Format error (AA=0)
constexpr uint16_t DNS_RESPONSE_SERVFAIL{0x8182}; // Server Failure (AA=0)
constexpr uint16_t DNS_RESPONSE_NXDOMAIN{0x8583}; // Non-Existent Domain (AA=1)
constexpr uint16_t DNS_RESPONSE_NOTIMP{0x8184}; // Not Implemented (AA=0)
constexpr uint16_t DNS_RESPONSE_REFUSED{0x8185}; // Query Refused (AA=0)

// DNS OPT / EDNS0 (RFC 6891)
constexpr uint16_t DNS_TYPE_OPT{41};

// DNS Record Types
constexpr uint16_t DNS_TYPE_A{0x0001};
constexpr uint16_t DNS_TYPE_NS{0x0002};
constexpr uint16_t DNS_TYPE_CNAME{0x0005};
constexpr uint16_t DNS_TYPE_SOA{0x0006};
constexpr uint16_t DNS_TYPE_PTR{0x000C};
constexpr uint16_t DNS_TYPE_MX{0x000F};
constexpr uint16_t DNS_TYPE_TXT{0x0010};
constexpr uint16_t DNS_TYPE_AAAA{0x001C};
constexpr uint16_t DNS_TYPE_SRV{0x0021};

// DNS Compression Pointer
constexpr uint16_t DNS_QUESTION_POINTER{0xC00C};

// DNS Limits
constexpr std::size_t DNS_HEADER_SIZE{12}; ///< DNS header size in bytes (always 12, RFC 1035 §4.1.1)
constexpr std::size_t DNS_MIN_PACKET_SIZE{DNS_HEADER_SIZE};
constexpr std::size_t DEFAULT_DNS_PACKET_SIZE{512};
// DEFAULT_EDNS_PACKET_SIZE should MTU size minus 48 bytes for the IPv6 and UDP headers
// This current value (MTU of 1280bytes) is the based on avoiding fragmentation on nearly all current networks (As of 2020)
// Could we detect the system's set MTU size rather than using a constant?
constexpr std::size_t DEFAULT_EDNS_PACKET_SIZE{1232};
constexpr std::size_t MAX_DNS_LABEL_LENGTH{63};
constexpr std::size_t MAX_DNS_NAME_LENGTH{253};
constexpr std::size_t MAX_TXT_STRING_LENGTH{255};
} // namespace Dns
} // namespace Constants

#endif
