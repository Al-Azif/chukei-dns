// Unit tests for DnsCache
#include "test_framework.h"

#include "dns_cache.h"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

// ============================================================================
// Helper: Build a minimal DNS wire-format response
// ============================================================================

// Builds a synthetic DNS response with the specified header counts and
// resource records. This avoids relying on external DNS libraries.
namespace {

// Append a uint16_t in network byte order
void AppendUint16(std::vector<char> &p_Vec, uint16_t p_Val) {
  p_Vec.push_back(static_cast<char>(p_Val >> 8));
  p_Vec.push_back(static_cast<char>(p_Val & 0xFF));
}

// Append a uint32_t in network byte order
void AppendUint32(std::vector<char> &p_Vec, uint32_t p_Val) {
  p_Vec.push_back(static_cast<char>((p_Val >> 24) & 0xFF));
  p_Vec.push_back(static_cast<char>((p_Val >> 16) & 0xFF));
  p_Vec.push_back(static_cast<char>((p_Val >> 8) & 0xFF));
  p_Vec.push_back(static_cast<char>(p_Val & 0xFF));
}

// Append a DNS name in wire format (e.g. "example.com" -> [7]example[3]com[0])
void AppendDnsName(std::vector<char> &p_Vec, const std::string &p_Name) {
  std::size_t s_Pos{0};
  while (s_Pos < p_Name.size()) {
    std::string::size_type dot{p_Name.find('.', s_Pos)};
    if (dot == std::string::npos) {
      dot = p_Name.size();
    }
    std::string::size_type len{dot - s_Pos};
    p_Vec.push_back(static_cast<char>(len));
    for (std::size_t l_Index{0}; l_Index < len; ++l_Index) {
      p_Vec.push_back(p_Name[s_Pos + l_Index]);
    }
    s_Pos = dot + 1;
  }
  p_Vec.push_back(0); // null terminator
}

// Build a complete DNS response with one A record answer
std::vector<char> BuildAResponse(uint16_t p_TxnId, const std::string &p_Domain, uint32_t p_Ttl, uint8_t p_IpA, uint8_t p_IpB, uint8_t p_IpC, uint8_t p_IpD) {
  std::vector<char> s_Pkt;

  // Header
  AppendUint16(s_Pkt, p_TxnId);     // ID
  AppendUint16(s_Pkt, 0x8180);     // Flags: QR=1, RD=1, RA=1
  AppendUint16(s_Pkt, 1);          // QDCOUNT
  AppendUint16(s_Pkt, 1);          // ANCOUNT
  AppendUint16(s_Pkt, 0);          // NSCOUNT
  AppendUint16(s_Pkt, 0);          // ARCOUNT

  // Question
  AppendDnsName(s_Pkt, p_Domain);
  AppendUint16(s_Pkt, 1);          // QTYPE = A
  AppendUint16(s_Pkt, 1);          // QCLASS = IN

  // Answer: compression pointer to question name
  AppendUint16(s_Pkt, 0xC00C);     // NAME pointer
  AppendUint16(s_Pkt, 1);          // TYPE = A
  AppendUint16(s_Pkt, 1);          // CLASS = IN
  AppendUint32(s_Pkt, p_Ttl);        // TTL
  AppendUint16(s_Pkt, 4);          // RDLENGTH
  s_Pkt.push_back(static_cast<char>(p_IpA));
  s_Pkt.push_back(static_cast<char>(p_IpB));
  s_Pkt.push_back(static_cast<char>(p_IpC));
  s_Pkt.push_back(static_cast<char>(p_IpD));

  return s_Pkt;
}

// Build a response with multiple A records (varying TTLs)
std::vector<char> BuildMultiAResponse(uint16_t p_TxnId, const std::string &p_Domain, const std::vector<uint32_t> &p_Ttls) {
  std::vector<char> s_Pkt;

  // Header
  AppendUint16(s_Pkt, p_TxnId);
  AppendUint16(s_Pkt, 0x8180);
  AppendUint16(s_Pkt, 1);
  AppendUint16(s_Pkt, static_cast<uint16_t>(p_Ttls.size()));
  AppendUint16(s_Pkt, 0);
  AppendUint16(s_Pkt, 0);

  // Question
  AppendDnsName(s_Pkt, p_Domain);
  AppendUint16(s_Pkt, 1);
  AppendUint16(s_Pkt, 1);

  // Answers
  for (std::size_t l_Index{0}; l_Index < p_Ttls.size(); ++l_Index) {
    AppendUint16(s_Pkt, 0xC00C);   // NAME pointer
    AppendUint16(s_Pkt, 1);        // TYPE = A
    AppendUint16(s_Pkt, 1);        // CLASS = IN
    AppendUint32(s_Pkt, p_Ttls[l_Index]);  // TTL
    AppendUint16(s_Pkt, 4);        // RDLENGTH
    s_Pkt.push_back(static_cast<char>(10));
    s_Pkt.push_back(static_cast<char>(0));
    s_Pkt.push_back(static_cast<char>(0));
    s_Pkt.push_back(static_cast<char>(static_cast<uint8_t>(l_Index + 1)));
  }

  return s_Pkt;
}

// Build a header-only response (no resource records, e.g. NXDOMAIN without SOA)
std::vector<char> BuildHeaderOnlyResponse(uint16_t p_TxnId, uint16_t p_Flags) {
  std::vector<char> s_Pkt;
  AppendUint16(s_Pkt, p_TxnId);
  AppendUint16(s_Pkt, p_Flags);
  AppendUint16(s_Pkt, 0); // QDCOUNT
  AppendUint16(s_Pkt, 0); // ANCOUNT
  AppendUint16(s_Pkt, 0); // NSCOUNT
  AppendUint16(s_Pkt, 0); // ARCOUNT
  return s_Pkt;
}

// Build a response with an OPT record in the additional section
std::vector<char> BuildResponseWithOpt(uint16_t p_TxnId, const std::string &p_Domain, uint32_t p_AnswerTtl) {
  std::vector<char> s_Pkt;

  // Header
  AppendUint16(s_Pkt, p_TxnId);
  AppendUint16(s_Pkt, 0x8180);
  AppendUint16(s_Pkt, 1);  // QDCOUNT
  AppendUint16(s_Pkt, 1);  // ANCOUNT
  AppendUint16(s_Pkt, 0);  // NSCOUNT
  AppendUint16(s_Pkt, 1);  // ARCOUNT (OPT)

  // Question
  AppendDnsName(s_Pkt, p_Domain);
  AppendUint16(s_Pkt, 1);  // QTYPE = A
  AppendUint16(s_Pkt, 1);  // QCLASS = IN

  // Answer
  AppendUint16(s_Pkt, 0xC00C);
  AppendUint16(s_Pkt, 1);           // TYPE = A
  AppendUint16(s_Pkt, 1);           // CLASS = IN
  AppendUint32(s_Pkt, p_AnswerTtl);  // TTL
  AppendUint16(s_Pkt, 4);           // RDLENGTH
  s_Pkt.push_back(1);
  s_Pkt.push_back(2);
  s_Pkt.push_back(3);
  s_Pkt.push_back(4);

  // OPT pseudo-record in additional section
  s_Pkt.push_back(0);               // NAME = root
  AppendUint16(s_Pkt, 41);          // TYPE = OPT (41)
  AppendUint16(s_Pkt, 1232);        // CLASS = UDP payload size
  AppendUint32(s_Pkt, 0);           // TTL = extended RCODE + flags
  AppendUint16(s_Pkt, 0);           // RDLENGTH = 0

  return s_Pkt;
}

// Read uint32 at offset in network byte order
uint32_t ReadU32(const std::vector<char> &p_Data, std::size_t p_Offset) {
  return (static_cast<uint32_t>(static_cast<uint8_t>(p_Data[p_Offset])) << 24) | (static_cast<uint32_t>(static_cast<uint8_t>(p_Data[p_Offset + 1])) << 16) | (static_cast<uint32_t>(static_cast<uint8_t>(p_Data[p_Offset + 2])) << 8) | static_cast<uint32_t>(static_cast<uint8_t>(p_Data[p_Offset + 3]));
}

uint16_t ReadU16(const std::vector<char> &p_Data, std::size_t p_Offset) {
  return static_cast<uint16_t>((static_cast<uint8_t>(p_Data[p_Offset]) << 8) | static_cast<uint8_t>(p_Data[p_Offset + 1]));
}

} // namespace

// ============================================================================
// SkipDnsName tests
// ============================================================================

TEST(DnsCache_SkipDnsName_label_sequence) {
  // "example.com" = [7]example[3]com[0]
  std::vector<char> s_Data;
  AppendDnsName(s_Data, "example.com");
  std::size_t s_Result{DnsCache::SkipDnsName(s_Data.data(), s_Data.size(), 0)};
  ASSERT_EQ(s_Result, s_Data.size());
}

TEST(DnsCache_SkipDnsName_compression_pointer) {
  // Compression pointer: 0xC0 0x0C (2 bytes)
  std::vector<char> s_Data{static_cast<char>(0xC0), static_cast<char>(0x0C)};
  std::size_t s_Result{DnsCache::SkipDnsName(s_Data.data(), s_Data.size(), 0)};
  ASSERT_EQ(s_Result, static_cast<std::size_t>(2));
}

TEST(DnsCache_SkipDnsName_root_label) {
  // Root label: just a zero byte
  std::vector<char> s_Data{0};
  std::size_t s_Result{DnsCache::SkipDnsName(s_Data.data(), s_Data.size(), 0)};
  ASSERT_EQ(s_Result, static_cast<std::size_t>(1));
}

TEST(DnsCache_SkipDnsName_with_offset) {
  // Some s_Data before the name
  std::vector<char> s_Data{'X', 'Y'};
  AppendDnsName(s_Data, "test.org");
  std::size_t s_Result{DnsCache::SkipDnsName(s_Data.data(), s_Data.size(), 2)};
  ASSERT_EQ(s_Result, s_Data.size());
}

TEST(DnsCache_SkipDnsName_truncated_returns_zero) {
  // Label says 10 bytes but s_Data ends after 5
  std::vector<char> s_Data{10, 'a', 'b', 'c', 'd', 'e'};
  std::size_t s_Result{DnsCache::SkipDnsName(s_Data.data(), s_Data.size(), 0)};
  ASSERT_EQ(s_Result, static_cast<std::size_t>(0));
}

// ============================================================================
// ExtractMinTtl tests
// ============================================================================

TEST(DnsCache_ExtractMinTtl_single_a_record) {
  std::vector<char> s_Pkt{BuildAResponse(0x1234, "example.com", 300, 1, 2, 3, 4)};
  uint32_t s_Ttl{DnsCache::ExtractMinTtl(s_Pkt.data(), s_Pkt.size())};
  ASSERT_EQ(s_Ttl, static_cast<uint32_t>(300));
}

TEST(DnsCache_ExtractMinTtl_multiple_records_picks_min) {
  std::vector<char> s_Pkt{BuildMultiAResponse(0x1234, "example.com", {600, 120, 3600})};
  uint32_t s_Ttl{DnsCache::ExtractMinTtl(s_Pkt.data(), s_Pkt.size())};
  ASSERT_EQ(s_Ttl, static_cast<uint32_t>(120));
}

TEST(DnsCache_ExtractMinTtl_zero_ttl_returns_zero) {
  std::vector<char> s_Pkt{BuildAResponse(0x1234, "example.com", 0, 1, 2, 3, 4)};
  uint32_t s_Ttl{DnsCache::ExtractMinTtl(s_Pkt.data(), s_Pkt.size())};
  ASSERT_EQ(s_Ttl, static_cast<uint32_t>(0));
}

TEST(DnsCache_ExtractMinTtl_no_records_returns_zero) {
  std::vector<char> s_Pkt = BuildHeaderOnlyResponse(0x1234, 0x8183); // NXDOMAIN, no SOA
  uint32_t s_Ttl{DnsCache::ExtractMinTtl(s_Pkt.data(), s_Pkt.size())};
  ASSERT_EQ(s_Ttl, static_cast<uint32_t>(0));
}

TEST(DnsCache_ExtractMinTtl_too_short_returns_zero) {
  std::vector<char> s_Pkt(6, 0); // Too short to be valid
  uint32_t s_Ttl{DnsCache::ExtractMinTtl(s_Pkt.data(), s_Pkt.size())};
  ASSERT_EQ(s_Ttl, static_cast<uint32_t>(0));
}

TEST(DnsCache_ExtractMinTtl_skips_opt_record) {
  // OPT TTL field encodes extended RCODE + flags, not a real TTL
  std::vector<char> s_Pkt{BuildResponseWithOpt(0x1234, "example.com", 500)};
  uint32_t s_Ttl{DnsCache::ExtractMinTtl(s_Pkt.data(), s_Pkt.size())};
  ASSERT_EQ(s_Ttl, static_cast<uint32_t>(500)); // Should use the A record TTL, not OPT
}

// ============================================================================
// Insert + Lookup basic tests
// ============================================================================

TEST(DnsCache_Lookup_miss_returns_false) {
  DnsCache s_Cache;
  std::vector<char> s_Output;
  bool s_Hit{s_Cache.Lookup("notcached.com", 1, 0x1234, s_Output)};
  ASSERT_FALSE(s_Hit);
  ASSERT_TRUE(s_Output.empty());
}

TEST(DnsCache_Insert_and_Lookup_hit) {
  DnsCache s_Cache;
  std::vector<char> s_Pkt{BuildAResponse(0xAAAA, "example.com", 3600, 1, 2, 3, 4)};
  s_Cache.Insert("example.com", 1, s_Pkt);

  ASSERT_EQ(s_Cache.Size(), static_cast<std::size_t>(1));

  std::vector<char> s_Output;
  bool s_Hit{s_Cache.Lookup("example.com", 1, 0xBBBB, s_Output)};
  ASSERT_TRUE(s_Hit);
  ASSERT_FALSE(s_Output.empty());

  // Transaction ID should be rewritten to 0xBBBB
  ASSERT_EQ(ReadU16(s_Output, 0), static_cast<uint16_t>(0xBBBB));
}

TEST(DnsCache_Lookup_different_qtype_is_miss) {
  DnsCache s_Cache;
  std::vector<char> s_Pkt{BuildAResponse(0x1234, "example.com", 3600, 1, 2, 3, 4)};
  s_Cache.Insert("example.com", 1, s_Pkt); // Type A

  std::vector<char> s_Output;
  bool s_Hit{s_Cache.Lookup("example.com", 28, 0x1234, s_Output)}; // Type AAAA
  ASSERT_FALSE(s_Hit);
}

TEST(DnsCache_Lookup_different_domain_is_miss) {
  DnsCache s_Cache;
  std::vector<char> s_Pkt{BuildAResponse(0x1234, "example.com", 3600, 1, 2, 3, 4)};
  s_Cache.Insert("example.com", 1, s_Pkt);

  std::vector<char> s_Output;
  bool s_Hit{s_Cache.Lookup("other.com", 1, 0x1234, s_Output)};
  ASSERT_FALSE(s_Hit);
}

TEST(DnsCache_Lookup_case_insensitive) {
  DnsCache s_Cache;
  std::vector<char> s_Pkt{BuildAResponse(0x1234, "Example.Com", 3600, 1, 2, 3, 4)};
  s_Cache.Insert("Example.Com", 1, s_Pkt);

  std::vector<char> s_Output;
  bool s_Hit{s_Cache.Lookup("example.com", 1, 0x1234, s_Output)};
  ASSERT_TRUE(s_Hit);
}

TEST(DnsCache_Insert_overwrites_existing) {
  DnsCache s_Cache;
  std::vector<char> s_Pkt1{BuildAResponse(0x1234, "example.com", 3600, 1, 1, 1, 1)};
  std::vector<char> s_Pkt2{BuildAResponse(0x1234, "example.com", 3600, 2, 2, 2, 2)};
  s_Cache.Insert("example.com", 1, s_Pkt1);
  s_Cache.Insert("example.com", 1, s_Pkt2);

  ASSERT_EQ(s_Cache.Size(), static_cast<std::size_t>(1));

  std::vector<char> s_Output;
  ASSERT_TRUE(s_Cache.Lookup("example.com", 1, 0x1234, s_Output));
  // Last byte of RDATA should be 2 (from s_Pkt2)
  ASSERT_EQ(static_cast<uint8_t>(s_Output.back()), static_cast<uint8_t>(2));
}

// ============================================================================
// TTL adjustment tests
// ============================================================================

TEST(DnsCache_Lookup_adjusts_ttl) {
  DnsCache s_Cache;
  std::vector<char> s_Pkt{BuildAResponse(0x1234, "example.com", 100, 1, 2, 3, 4)};
  s_Cache.Insert("example.com", 1, s_Pkt);

  // Find the TTL offset in the original packet
  // Header (12) + question name + QTYPE(2) + QCLASS(2) + NAME pointer(2) + TYPE(2) + CLASS(2) = TTL offset
  // The TTL is at a fixed offset in our test packet. Let's verify by reading it.
  // For "example.com": [7]example[3]com[0] = 13 bytes
  // Question: 13 + 4 = 17 bytes after header = offset 29
  // Answer: pointer(2) + TYPE(2) + CLASS(2) + TTL(4)
  // TTL is at 29 + 2 + 2 + 2 = 35
  std::size_t s_TtlOffset{12 + 13 + 4 + 2 + 2 + 2}; // = 35

  // Immediately, TTL should still be ~100
  std::vector<char> s_Output;
  ASSERT_TRUE(s_Cache.Lookup("example.com", 1, 0x1234, s_Output));
  uint32_t s_TtlNow{ReadU32(s_Output, s_TtlOffset)};
  ASSERT_EQ(s_TtlNow, static_cast<uint32_t>(100)); // 0 seconds elapsed
}

// ============================================================================
// Expiry tests
// ============================================================================

TEST(DnsCache_expired_entry_is_evicted_on_lookup) {
  DnsCache s_Cache;
  // TTL = 1 second
  std::vector<char> s_Pkt{BuildAResponse(0x1234, "expire.com", 1, 1, 2, 3, 4)};
  s_Cache.Insert("expire.com", 1, s_Pkt);
  ASSERT_EQ(s_Cache.Size(), static_cast<std::size_t>(1));

  // Wait for expiry
  std::this_thread::sleep_for(std::chrono::milliseconds(1100));

  std::vector<char> s_Output;
  bool s_Hit{s_Cache.Lookup("expire.com", 1, 0x1234, s_Output)};
  ASSERT_FALSE(s_Hit);
  ASSERT_EQ(s_Cache.Size(), static_cast<std::size_t>(0));
}

// ============================================================================
// TTL=0 should not be cached
// ============================================================================

TEST(DnsCache_ttl_zero_not_cached) {
  DnsCache s_Cache;
  std::vector<char> s_Pkt{BuildAResponse(0x1234, "nocache.com", 0, 1, 2, 3, 4)};
  s_Cache.Insert("nocache.com", 1, s_Pkt);
  ASSERT_EQ(s_Cache.Size(), static_cast<std::size_t>(0));
}

// ============================================================================
// Header-only responses are not cached (no records)
// ============================================================================

TEST(DnsCache_header_only_not_cached) {
  DnsCache s_Cache;
  std::vector<char> s_Pkt{BuildHeaderOnlyResponse(0x1234, 0x8183)};
  s_Cache.Insert("blocked.com", 1, s_Pkt);
  ASSERT_EQ(s_Cache.Size(), static_cast<std::size_t>(0));
}

// ============================================================================
// Capacity/eviction tests
// ============================================================================

TEST(DnsCache_evicts_oldest_when_full) {
  DnsCache s_Cache(3); // Max 3 entries

  s_Cache.Insert("a.com", 1, BuildAResponse(0x01, "a.com", 3600, 1, 0, 0, 1));
  s_Cache.Insert("b.com", 1, BuildAResponse(0x02, "b.com", 3600, 1, 0, 0, 2));
  s_Cache.Insert("c.com", 1, BuildAResponse(0x03, "c.com", 3600, 1, 0, 0, 3));
  ASSERT_EQ(s_Cache.Size(), static_cast<std::size_t>(3));

  // Adding a 4th should evict the oldest
  s_Cache.Insert("d.com", 1, BuildAResponse(0x04, "d.com", 3600, 1, 0, 0, 4));
  ASSERT_EQ(s_Cache.Size(), static_cast<std::size_t>(3));

  // The oldest (a.com) should be gone
  std::vector<char> s_Output;
  ASSERT_FALSE(s_Cache.Lookup("a.com", 1, 0x01, s_Output));
  ASSERT_TRUE(s_Cache.Lookup("d.com", 1, 0x04, s_Output));
}

// ============================================================================
// Clear
// ============================================================================

TEST(DnsCache_Clear_empties_cache) {
  DnsCache s_Cache;
  s_Cache.Insert("a.com", 1, BuildAResponse(0x01, "a.com", 3600, 1, 0, 0, 1));
  s_Cache.Insert("b.com", 1, BuildAResponse(0x02, "b.com", 3600, 1, 0, 0, 2));
  ASSERT_EQ(s_Cache.Size(), static_cast<std::size_t>(2));
  s_Cache.Clear();
  ASSERT_EQ(s_Cache.Size(), static_cast<std::size_t>(0));
}

// ============================================================================
// Transaction ID rewriting
// ============================================================================

TEST(DnsCache_txn_id_rewritten_on_lookup) {
  DnsCache s_Cache;
  std::vector<char> s_Pkt{BuildAResponse(0xDEAD, "example.com", 3600, 1, 2, 3, 4)};
  s_Cache.Insert("example.com", 1, s_Pkt);

  std::vector<char> s_Output;
  ASSERT_TRUE(s_Cache.Lookup("example.com", 1, 0xBEEF, s_Output));

  // First two bytes = transaction ID
  uint16_t s_Txn{ReadU16(s_Output, 0)};
  ASSERT_EQ(s_Txn, static_cast<uint16_t>(0xBEEF));
}

// ============================================================================
// Response preserves rest of payload
// ============================================================================

TEST(DnsCache_response_body_preserved) {
  DnsCache s_Cache;
  std::vector<char> s_Pkt{BuildAResponse(0x1234, "example.com", 3600, 10, 20, 30, 40)};
  s_Cache.Insert("example.com", 1, s_Pkt);

  std::vector<char> s_Output;
  ASSERT_TRUE(s_Cache.Lookup("example.com", 1, 0x1234, s_Output));

  // RDATA should be 10.20.30.40
  ASSERT_EQ(s_Output.size(), s_Pkt.size());
  ASSERT_EQ(static_cast<uint8_t>(s_Output[s_Output.size() - 4]), static_cast<uint8_t>(10));
  ASSERT_EQ(static_cast<uint8_t>(s_Output[s_Output.size() - 3]), static_cast<uint8_t>(20));
  ASSERT_EQ(static_cast<uint8_t>(s_Output[s_Output.size() - 2]), static_cast<uint8_t>(30));
  ASSERT_EQ(static_cast<uint8_t>(s_Output[s_Output.size() - 1]), static_cast<uint8_t>(40));
}

// ============================================================================
// Response too small (< 12 bytes) is rejected
// ============================================================================

TEST(DnsCache_rejects_too_small_response) {
  DnsCache s_Cache;
  std::vector<char> s_Tiny(8, 0);
  s_Cache.Insert("small.com", 1, s_Tiny);
  ASSERT_EQ(s_Cache.Size(), static_cast<std::size_t>(0));
}

// ============================================================================
// Multiple types for same domain
// ============================================================================

TEST(DnsCache_different_types_cached_separately) {
  DnsCache s_Cache;
  std::vector<char> s_PktA{BuildAResponse(0x01, "example.com", 3600, 1, 2, 3, 4)};

  // Build an AAAA-like response (fake, just different qtype key)
  std::vector<char> s_PktAaaa{BuildAResponse(0x02, "example.com", 1800, 5, 6, 7, 8)};

  s_Cache.Insert("example.com", 1, s_PktA);    // A
  s_Cache.Insert("example.com", 28, s_PktAaaa); // AAAA
  ASSERT_EQ(s_Cache.Size(), static_cast<std::size_t>(2));

  std::vector<char> s_OutA, s_OutAaaa;
  ASSERT_TRUE(s_Cache.Lookup("example.com", 1, 0x10, s_OutA));
  ASSERT_TRUE(s_Cache.Lookup("example.com", 28, 0x20, s_OutAaaa));
}

// ============================================================================
// OPT-only response not cached (OPT TTL is skipped, so min_ttl = 0)
// ============================================================================

TEST(DnsCache_opt_only_response_not_cached) {
  // Build a response with only an OPT record in additional, no answer records
  std::vector<char> s_Pkt;
  AppendUint16(s_Pkt, 0x1234);  // ID
  AppendUint16(s_Pkt, 0x8180);  // Flags
  AppendUint16(s_Pkt, 1);       // QDCOUNT
  AppendUint16(s_Pkt, 0);       // ANCOUNT
  AppendUint16(s_Pkt, 0);       // NSCOUNT
  AppendUint16(s_Pkt, 1);       // ARCOUNT

  AppendDnsName(s_Pkt, "test.com");
  AppendUint16(s_Pkt, 1);       // QTYPE
  AppendUint16(s_Pkt, 1);       // QCLASS

  // OPT record
  s_Pkt.push_back(0);           // NAME = root
  AppendUint16(s_Pkt, 41);      // TYPE = OPT
  AppendUint16(s_Pkt, 1232);    // CLASS = UDP size
  AppendUint32(s_Pkt, 0);       // Extended RCODE + flags
  AppendUint16(s_Pkt, 0);       // RDLENGTH

  DnsCache s_Cache;
  s_Cache.Insert("test.com", 1, s_Pkt);
  // OPT is skipped for TTL extraction, so min_ttl stays 0 -> not cached
  ASSERT_EQ(s_Cache.Size(), static_cast<std::size_t>(0));
}

// ============================================================================
// Multi-record TTL: uses min across answers
// ============================================================================

TEST(DnsCache_multi_record_uses_min_ttl_for_expiry) {
  DnsCache s_Cache;
  std::vector<char> s_Pkt{BuildMultiAResponse(0x1234, "multi.com", {3600, 60, 1800})};
  s_Cache.Insert("multi.com", 1, s_Pkt);

  // min TTL is 60, should be cached
  ASSERT_EQ(s_Cache.Size(), static_cast<std::size_t>(1));

  std::vector<char> s_Output;
  ASSERT_TRUE(s_Cache.Lookup("multi.com", 1, 0xFFFF, s_Output));
}
