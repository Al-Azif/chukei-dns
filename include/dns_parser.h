/** @file dns_parser.h
 *  @brief DNS query packet parser with domain decomposition into root domain and subdomain.
 */

#ifndef DNS_PARSER_H_
#define DNS_PARSER_H_

#include <cstddef> // std::size_t
#include <memory>  // std::unique_ptr
#include <mutex>   // std::once_flag
#include <regex>   // std::regex
#include <string>  // std::string

#include "dns_packet.h"

/**
 * @brief DNS query parser with domain decomposition into root domain and subdomain
 *
 * Validate the incoming wire-format data, construct a DnsRequestPacket,
 * and split the queried domain name into its root (last two labels) and
 * subdomain (remaining labels) for zone lookup.
 *
 * @note Non-copyable; uses thread-safe lazy-initialized regex patterns.
 */
class DnsParser {
public:
  /**
   * @brief Construct a parser from raw DNS wire-format data
   * @param p_Data       Pointer to the DNS packet bytes.
   * @param p_DataLength Length of the data in bytes.
   * @throws std::out_of_range if the data is too small or too large.
   * @throws std::invalid_argument if the data pointer is null.
   * @throws std::runtime_error if parsing fails or the packet contains != 1 question.
   */
  DnsParser(const char *p_Data, std::size_t p_DataLength);

  // Move semantics
  DnsParser(DnsParser &&other) noexcept = default;
  DnsParser &operator=(DnsParser &&other) noexcept = default;

  // Delete copy semantics and default constructor
  DnsParser() = delete;
  DnsParser(const DnsParser &) = delete;
  DnsParser &operator=(const DnsParser &) = delete;

  /** @brief Get the full queried domain name (e.g., "www.example.com"). */
  [[nodiscard]] const std::string &Domain() const;

  /** @brief Get the root domain (last two labels, e.g., "example.com"). */
  [[nodiscard]] const std::string &RootDomain() const;

  /** @brief Get the subdomain portion (labels before the root domain, e.g., "www"). */
  [[nodiscard]] const std::string &SubDomain() const;

  /** @brief Get the human-readable record type string (e.g., "A", "AAAA", "CNAME"). */
  [[nodiscard]] std::string RecordType() const;

  /** @brief Get the parsed DNS request packet. */
  [[nodiscard]] const DnsRequestPacket &Packet() const;

private:
  // Thread-safe lazy-initialized regex patterns
  static const std::regex &RootDomainPattern();
  static const std::regex &SubDomainPattern();

  // Thread synchronization for lazy initialization
  static std::once_flag m_RootPatternInitFlag_;
  static std::once_flag m_SubPatternInitFlag_;

  // Storage for compiled patterns
  static std::unique_ptr<std::regex> m_RootDomainPattern_;
  static std::unique_ptr<std::regex> m_SubDomainPattern_;

  // Instance members
  DnsRequestPacket m_ParsedPacket_{};
  std::string m_Domain_{};
  std::string m_RootDomain_{};
  std::string m_SubDomain_{};

  void PrintPacketDebug() const;
  void CacheDomainParts();
};

#endif
