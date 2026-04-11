// Self
#include "dns_cache.h"

// C

// C++
#include <algorithm> // std::min, std::min_element, std::transform
#include <chrono>    // std::chrono
#include <cstddef>   // std::size_t
#include <cstdint>   // uint16_t, uint32_t
#include <string>    // std::string
#include <vector>    // std::vector

// Other libraries

// This Project's

// Logging
#include "libLog.h"

// Banned
#include "banned.h"

DnsCache::DnsCache(std::size_t p_MaxEntries) : m_MaxEntries_(p_MaxEntries) {
}

bool DnsCache::Lookup(const std::string &p_Domain, uint16_t p_Qtype, uint16_t p_TxnId, std::vector<char> &p_Output) {
  CacheKey s_Key{ToLower(p_Domain), p_Qtype};
  std::unordered_map<CacheKey, CacheEntry, CacheKeyHash>::iterator s_It{m_Cache_.find(s_Key)};
  if (s_It == m_Cache_.end()) {
    return false;
  }

  const CacheEntry &s_Entry{s_It->second};
  std::chrono::steady_clock::time_point s_Now{std::chrono::steady_clock::now()};
  std::chrono::seconds::rep s_Elapsed{std::chrono::duration_cast<std::chrono::seconds>(s_Now - s_Entry.insert_time).count()};

  // Entry expired
  if (s_Elapsed >= static_cast<long>(s_Entry.min_ttl)) {
    m_Cache_.erase(s_It);
    return false;
  }

  // Copy response and adjust transaction ID + TTLs
  p_Output = s_Entry.response;

  // Rewrite transaction ID (bytes 0-1)
  if (p_Output.size() >= 2) {
    WriteUint16(p_Output.data(), 0, p_TxnId);
  }

  // Adjust TTLs to reflect time elapsed since caching
  AdjustTtls(p_Output, static_cast<uint32_t>(s_Elapsed));

  return true;
}

void DnsCache::Insert(const std::string &p_Domain, uint16_t p_Qtype, const std::vector<char> &p_Response) {
  // Minimum valid DNS response is 12 bytes (header only)
  if (p_Response.size() < 12) {
    return;
  }

  uint32_t s_MinTtl{ExtractMinTtl(p_Response.data(), p_Response.size())};
  if (s_MinTtl == 0) {
    // TTL 0 means do not cache (RFC 1035 §3.2.1)
    return;
  }

  CacheKey s_Key{ToLower(p_Domain), p_Qtype};

  // Evict expired entries if at capacity
  if (m_Cache_.size() >= m_MaxEntries_ && m_Cache_.find(s_Key) == m_Cache_.end()) {
    EvictExpired();

    // If still at capacity after evicting expired, remove oldest entry
    if (m_Cache_.size() >= m_MaxEntries_) {
      std::unordered_map<CacheKey, CacheEntry, CacheKeyHash>::iterator s_Oldest{std::min_element(m_Cache_.begin(), m_Cache_.end(), [](const auto &a, const auto &b) { return a.second.insert_time < b.second.insert_time; })};
      m_Cache_.erase(s_Oldest);
    }
  }

  m_Cache_[s_Key] = CacheEntry{p_Response, std::chrono::steady_clock::now(), s_MinTtl};
  logKernel(LL_Debug, "Cached response for %s (type %u, TTL %u)", p_Domain.c_str(), p_Qtype, s_MinTtl);
}

std::size_t DnsCache::Size() const {
  return m_Cache_.size();
}

void DnsCache::Clear() {
  m_Cache_.clear();
}

void DnsCache::EvictExpired() {
  std::chrono::steady_clock::time_point s_Now{std::chrono::steady_clock::now()};
  for (std::unordered_map<CacheKey, CacheEntry, CacheKeyHash>::iterator it{m_Cache_.begin()}; it != m_Cache_.end();) {
    std::chrono::seconds::rep s_Elapsed{std::chrono::duration_cast<std::chrono::seconds>(s_Now - it->second.insert_time).count()};
    if (s_Elapsed >= static_cast<long>(it->second.min_ttl)) {
      it = m_Cache_.erase(it);
    } else {
      ++it;
    }
  }
}

std::string DnsCache::ToLower(const std::string &p_Input) {
  std::string s_Result{p_Input};
  std::transform(s_Result.begin(), s_Result.end(), s_Result.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return s_Result;
}

// Skip a DNS name in wire format, returning the offset after the name.
// Handles both label sequences and compression pointers (0xC0 prefix).
// Returns 0 on error (name extends beyond data boundary).
std::size_t DnsCache::SkipDnsName(const char *p_Data, std::size_t p_Length, std::size_t p_Offset) {
  std::size_t s_Pos{p_Offset};
  while (s_Pos < p_Length) {
    uint8_t s_Byte{static_cast<uint8_t>(p_Data[s_Pos])};

    // Compression pointer: 2 bytes, done
    if ((s_Byte & 0xC0) == 0xC0) {
      return s_Pos + 2;
    }

    // End of name
    if (s_Byte == 0) {
      return s_Pos + 1;
    }

    // Label: skip length byte + label bytes
    s_Pos += 1 + s_Byte;
  }
  return 0; // Error: ran past end of data
}

uint16_t DnsCache::ReadUint16(const char *p_Data, std::size_t p_Offset) {
  return static_cast<uint16_t>((static_cast<uint8_t>(p_Data[p_Offset]) << 8) | static_cast<uint8_t>(p_Data[p_Offset + 1]));
}

uint32_t DnsCache::ReadUint32(const char *p_Data, std::size_t p_Offset) {
  return (static_cast<uint32_t>(static_cast<uint8_t>(p_Data[p_Offset])) << 24) | (static_cast<uint32_t>(static_cast<uint8_t>(p_Data[p_Offset + 1])) << 16) | (static_cast<uint32_t>(static_cast<uint8_t>(p_Data[p_Offset + 2])) << 8) | static_cast<uint32_t>(static_cast<uint8_t>(p_Data[p_Offset + 3]));
}

void DnsCache::WriteUint16(char *p_Data, std::size_t p_Offset, uint16_t p_Value) {
  p_Data[p_Offset] = static_cast<char>(p_Value >> 8);
  p_Data[p_Offset + 1] = static_cast<char>(p_Value & 0xFF);
}

void DnsCache::WriteUint32(char *p_Data, std::size_t p_Offset, uint32_t p_Value) {
  p_Data[p_Offset] = static_cast<char>((p_Value >> 24) & 0xFF);
  p_Data[p_Offset + 1] = static_cast<char>((p_Value >> 16) & 0xFF);
  p_Data[p_Offset + 2] = static_cast<char>((p_Value >> 8) & 0xFF);
  p_Data[p_Offset + 3] = static_cast<char>(p_Value & 0xFF);
}

// Extract the minimum TTL from all resource records in a DNS wire-format response.
// Examines answer, authority, and additional sections.
// Returns UINT32_MAX if no resource records are found (header-only response).
uint32_t DnsCache::ExtractMinTtl(const char *p_Data, std::size_t p_Length) {
  if (p_Length < 12) {
    return 0;
  }

  uint16_t s_Qdcount{ReadUint16(p_Data, 4)};
  uint16_t s_Ancount{ReadUint16(p_Data, 6)};
  uint16_t s_Nscount{ReadUint16(p_Data, 8)};
  uint16_t s_Arcount{ReadUint16(p_Data, 10)};

  uint16_t s_TotalRr{static_cast<uint16_t>(s_Ancount + s_Nscount + s_Arcount)};
  if (s_TotalRr == 0) {
    return 0; // No records to cache
  }

  // Skip past header (12 bytes) and question section
  std::size_t s_Offset{12};
  for (uint16_t l_Index{0}; l_Index < s_Qdcount; ++l_Index) {
    s_Offset = SkipDnsName(p_Data, p_Length, s_Offset);
    if (s_Offset == 0) {
      return 0;
    }
    s_Offset += 4; // QTYPE (2) + QCLASS (2)
    if (s_Offset > p_Length) {
      return 0;
    }
  }

  // Walk resource records and find minimum TTL
  uint32_t s_MinTtl{UINT32_MAX};
  for (uint16_t l_Index{0}; l_Index < s_TotalRr; ++l_Index) {
    // Skip NAME
    s_Offset = SkipDnsName(p_Data, p_Length, s_Offset);
    if (s_Offset == 0 || s_Offset + 10 > p_Length) {
      return (s_MinTtl == UINT32_MAX) ? 0 : s_MinTtl;
    }

    // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes
    uint16_t s_Type{ReadUint16(p_Data, s_Offset)};
    uint32_t s_Ttl{ReadUint32(p_Data, s_Offset + 4)};
    uint16_t s_Rdlength{ReadUint16(p_Data, s_Offset + 8)};

    // Skip OPT pseudo-records (type 41) - they don't have meaningful TTLs
    if (s_Type != 41) {
      s_MinTtl = std::min(s_MinTtl, s_Ttl);
    }

    s_Offset += 10 + s_Rdlength;
    if (s_Offset > p_Length) {
      return (s_MinTtl == UINT32_MAX) ? 0 : s_MinTtl;
    }
  }

  return (s_MinTtl == UINT32_MAX) ? 0 : s_MinTtl;
}

// Adjust all TTL fields in a DNS wire-format response by subtracting elapsed seconds.
// TTLs are clamped to a minimum of 1 second (0 means "do not cache" per RFC 1035).
// Returns false if the response is malformed.
bool DnsCache::AdjustTtls(std::vector<char> &p_Response, uint32_t p_Elapsed) {
  if (p_Response.size() < 12 || p_Elapsed == 0) {
    return true;
  }

  const char *s_Data{p_Response.data()};
  std::size_t s_Length{p_Response.size()};

  uint16_t s_Qdcount{ReadUint16(s_Data, 4)};
  uint16_t s_Ancount{ReadUint16(s_Data, 6)};
  uint16_t s_Nscount{ReadUint16(s_Data, 8)};
  uint16_t s_Arcount{ReadUint16(s_Data, 10)};

  uint16_t s_TotalRr{static_cast<uint16_t>(s_Ancount + s_Nscount + s_Arcount)};
  if (s_TotalRr == 0) {
    return true;
  }

  // Skip header + questions
  std::size_t s_Offset{12};
  for (uint16_t l_Index{0}; l_Index < s_Qdcount; ++l_Index) {
    s_Offset = SkipDnsName(s_Data, s_Length, s_Offset);
    if (s_Offset == 0) {
      return false;
    }
    s_Offset += 4;
    if (s_Offset > s_Length) {
      return false;
    }
  }

  // Walk records and adjust TTLs
  for (uint16_t l_Index{0}; l_Index < s_TotalRr; ++l_Index) {
    s_Offset = SkipDnsName(s_Data, s_Length, s_Offset);
    if (s_Offset == 0 || s_Offset + 10 > s_Length) {
      return false;
    }

    uint16_t s_Type{ReadUint16(s_Data, s_Offset)};
    uint16_t s_Rdlength{ReadUint16(s_Data, s_Offset + 8)};

    // Adjust TTL for non-OPT records
    if (s_Type != 41) {
      uint32_t s_Ttl{ReadUint32(s_Data, s_Offset + 4)};
      uint32_t s_NewTtl{(s_Ttl > p_Elapsed) ? (s_Ttl - p_Elapsed) : 1};
      WriteUint32(p_Response.data(), s_Offset + 4, s_NewTtl);
    }

    s_Offset += 10 + s_Rdlength;
    if (s_Offset > s_Length) {
      return false;
    }
  }

  return true;
}
