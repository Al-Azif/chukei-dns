/** @file dns_cache.h
 *  @brief In-memory DNS response cache with TTL-based expiration.
 */

#ifndef DNS_CACHE_H_
#define DNS_CACHE_H_

#include <chrono>  // std::chrono::steady_clock
#include <cstddef> // std::size_t
#include <cstdint> // uint16_t, uint32_t
#include <string>  // std::string
#include <unordered_map>
#include <vector> // std::vector

/**
 * @brief TTL-based DNS response cache keyed by domain name and query type
 *
 * Store raw wire-format DoH responses and serve cache hits with
 * adjusted transaction IDs and TTL values that account for elapsed time.
 * Expired entries are lazily evicted on insert when at capacity.
 */
class DnsCache {
public:
  /**
   * @brief Construct a cache with the specified maximum entry count
   * @param p_MaxEntries Maximum number of cached responses (default: 1024).
   */
  explicit DnsCache(std::size_t p_MaxEntries = 1024);

  /**
   * @brief Look up a cached response for a given domain and query type
   *
   * On a cache hit, rewrite the transaction ID in bytes 0-1 of the
   * response and subtract elapsed time from all resource record TTLs.
   *
   * @param p_Domain Domain name to look up.
   * @param p_Qtype  DNS query type (e.g., A = 1, AAAA = 28).
   * @param p_TxnId  Transaction ID to write into the returned response.
   * @param p_Output Output vector receiving the cached wire-format response.
   * @return true on cache hit, false on miss or expired entry.
   */
  [[nodiscard]] bool Lookup(const std::string &p_Domain, uint16_t p_Qtype, uint16_t p_TxnId, std::vector<char> &p_Output);

  /**
   * @brief Insert a DoH wire-format response into the cache
   *
   * Extract the minimum TTL from the answer, authority, and additional
   * sections and use it as the expiration interval. Responses with TTL 0
   * are not cached per RFC 1035 section 3.2.1.
   *
   * @param p_Domain   Domain name associated with the response.
   * @param p_Qtype    DNS query type.
   * @param p_Response Raw wire-format DNS response.
   */
  void Insert(const std::string &p_Domain, uint16_t p_Qtype, const std::vector<char> &p_Response);

  /** @brief Get the number of entries currently in the cache. */
  [[nodiscard]] std::size_t Size() const;

  /** @brief Remove all entries from the cache. */
  void Clear();

  /**
   * @brief Skip over a DNS name in wire format
   *
   * Handle both label sequences and compression pointers (0xC0 prefix).
   * Public for testability.
   *
   * @param p_Data   Pointer to the raw wire-format data.
   * @param p_Length Total length of the data buffer.
   * @param p_Offset Starting byte offset of the name.
   * @return Offset immediately after the name, or 0 on error.
   */
  [[nodiscard]] static std::size_t SkipDnsName(const char *p_Data, std::size_t p_Length, std::size_t p_Offset);

  /**
   * @brief Extract the minimum TTL from all resource records in a DNS response
   *
   * Examine the answer, authority, and additional sections; OPT pseudo-records
   * (type 41) are skipped. Public for testability.
   *
   * @param p_Data   Pointer to the raw wire-format response.
   * @param p_Length Total length of the response.
   * @return Minimum TTL in seconds, or 0 if no cacheable records exist.
   */
  [[nodiscard]] static uint32_t ExtractMinTtl(const char *p_Data, std::size_t p_Length);

private:
  struct CacheEntry {
    std::vector<char> response;
    std::chrono::steady_clock::time_point insert_time;
    uint32_t min_ttl; // seconds
  };

  struct CacheKey {
    std::string domain;
    uint16_t qtype;
    bool operator==(const CacheKey &other) const {
      return qtype == other.qtype && domain == other.domain;
    }
  };

  struct CacheKeyHash {
    std::size_t operator()(const CacheKey &k) const {
      std::size_t h1{std::hash<std::string>{}(k.domain)};
      std::size_t h2{std::hash<uint16_t>{}(k.qtype)};
      return h1 ^ (h2 << 16);
    }
  };

  std::unordered_map<CacheKey, CacheEntry, CacheKeyHash> m_Cache_;
  std::size_t m_MaxEntries_;

  void EvictExpired();

  static std::string ToLower(const std::string &p_Input);
  static bool AdjustTtls(std::vector<char> &p_Response, uint32_t p_Elapsed);
  static uint16_t ReadUint16(const char *p_Data, std::size_t p_Offset);
  static uint32_t ReadUint32(const char *p_Data, std::size_t p_Offset);
  static void WriteUint16(char *p_Data, std::size_t p_Offset, uint16_t p_Value);
  static void WriteUint32(char *p_Data, std::size_t p_Offset, uint32_t p_Value);
};

#endif
