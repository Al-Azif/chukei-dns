/** @file local_dns.h
 *  @brief Local DNS zone lookup with regex subdomain matching and reverse-IP support.
 */

#ifndef LOCAL_DNS_H_
#define LOCAL_DNS_H_

#include <memory>        // std::unique_ptr
#include <mutex>         // std::mutex
#include <regex>         // std::regex
#include <string>        // std::string
#include <unordered_map> // std::unordered_map
#include <vector>        // std::vector

#include "nlohmann/json.hpp"

#include "dns_parser.h"

/**
 * @brief Local DNS zone lookup and resolution engine
 *
 * Support exact, wildcard, and regex subdomain matching, blocked domain
 * detection, PTR reverse lookups, CNAME chain following, and ANY queries.
 */
namespace LocalDns {

/** @brief Thread-safe cache of compiled regex patterns for subdomain matching. */
extern std::unordered_map<std::string, std::unique_ptr<std::regex>> m_RegexCache_;

/** @brief Mutex protecting m_RegexCache_ access. */
extern std::mutex m_RegexCacheMutex_;

/**
 * @brief Test whether a string matches a regex pattern, caching compiled patterns
 * @param p_Input   String to match.
 * @param p_Pattern Regex pattern string.
 * @return true if the entire input matches the pattern.
 */
[[nodiscard]] bool SafeRegexMatch(const std::string &p_Input, const std::string &p_Pattern);

/**
 * @brief Reverse the dot-separated components of an IPv4 address string
 * @param p_Input IPv4 components in reverse order (e.g., "1.168.192" from in-addr.arpa).
 * @return Components in forward order (e.g., "192.168.1").
 */
[[nodiscard]] std::string ReverseIpv4Components(const std::string &p_Input);

/**
 * @brief Reverse and regroup the nibble components of an IPv6 reverse lookup string
 * @param p_Input Dot-separated nibbles from ip6.arpa.
 * @return Colon-separated IPv6 address groups.
 */
[[nodiscard]] std::string ReverseIpv6Components(const std::string &p_Input);

/**
 * @brief Simplify a full IPv6 address by stripping leading zeros and compressing zero runs
 * @param p_Input Full colon-separated IPv6 address.
 * @return Simplified IPv6 address with :: compression.
 */
[[nodiscard]] std::string SimplifyIpv6(const std::string &p_Input);

/**
 * @brief Check whether a parsed DNS query matches a locally configured zone entry
 *
 * Handle blocked domains, PTR reverse lookups, CNAME chains, ANY queries,
 * and standard record type lookups with regex subdomain matching.
 *
 * @param p_Parser Parsed DNS query.
 * @param p_Output Output vector receiving the wire-format response on match.
 * @return 0 if a local match was found and p_Output is populated, -1 otherwise.
 */
[[nodiscard]] int CheckLocalMatch(const DnsParser &p_Parser, std::vector<char> &p_Output);

/**
 * @brief Look up a specific record type for a domain in local zones
 * @param p_Domain     Full domain name to look up.
 * @param p_RecordType Record type string ("A", "AAAA", "CNAME", etc.).
 * @param p_Data       Output JSON receiving the record data on success.
 * @return true if a matching record was found.
 */
[[nodiscard]] bool LookupLocalRecord(const std::string &p_Domain, const std::string &p_RecordType, nlohmann::json &p_Data);

} // namespace LocalDns

#endif
