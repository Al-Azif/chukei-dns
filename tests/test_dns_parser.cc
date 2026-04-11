// Tests for DnsParser: header parsing, question parsing, domain extraction
#include "test_framework.h"

#include "dns_packet.h"
#include "dns_parser.h"
#include "utils.h"

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

// Helper: build a minimal valid DNS query for "example.com" type A class IN
std::vector<char> BuildQuery(const std::string &p_Domain, uint16_t p_Qtype = 1, uint16_t p_Qclass = 1, uint16_t p_Id = 0x1234) {
  std::vector<char> s_Pkt;

  // Header (12 bytes)
  uint16_t s_NetId{HostToNetwork(p_Id)};
  s_Pkt.push_back(reinterpret_cast<const char *>(&s_NetId)[0]);
  s_Pkt.push_back(reinterpret_cast<const char *>(&s_NetId)[1]);

  // Flags: standard query, RD=1 -> 0x0100 in network byte order
  uint16_t s_Flags{HostToNetwork(static_cast<uint16_t>(0x0100))};
  s_Pkt.push_back(reinterpret_cast<const char *>(&s_Flags)[0]);
  s_Pkt.push_back(reinterpret_cast<const char *>(&s_Flags)[1]);

  // QDCOUNT = 1
  uint16_t s_Qdcount{HostToNetwork(static_cast<uint16_t>(1))};
  s_Pkt.push_back(reinterpret_cast<const char *>(&s_Qdcount)[0]);
  s_Pkt.push_back(reinterpret_cast<const char *>(&s_Qdcount)[1]);

  // ANCOUNT, NSCOUNT, ARCOUNT = 0
  for (int l_Index = 0; l_Index < 6; ++l_Index) {
    s_Pkt.push_back(0);
  }

  // Question section: encode p_Domain name
  std::string s_Label;
  std::string s_D{p_Domain};
  // Remove trailing s_Dot if present
  if (!s_D.empty() && s_D.back() == '.') {
    s_D.pop_back();
  }

  std::size_t s_Pos{0};
  while (s_Pos < s_D.size()) {
    std::size_t s_Dot{s_D.find('.', s_Pos)};
    if (s_Dot == std::string::npos) {
      s_Dot = s_D.size();
    }
    std::size_t s_Len{s_Dot - s_Pos};
    s_Pkt.push_back(static_cast<char>(s_Len));
    for (std::size_t l_Index{s_Pos}; l_Index < s_Dot; ++l_Index) {
      s_Pkt.push_back(s_D[l_Index]);
    }
    s_Pos = s_Dot + 1;
  }
  s_Pkt.push_back(0); // null terminator

  // QTYPE
  uint16_t s_NetQtype{HostToNetwork(p_Qtype)};
  s_Pkt.push_back(reinterpret_cast<const char *>(&s_NetQtype)[0]);
  s_Pkt.push_back(reinterpret_cast<const char *>(&s_NetQtype)[1]);

  // QCLASS
  uint16_t s_NetQclass{HostToNetwork(p_Qclass)};
  s_Pkt.push_back(reinterpret_cast<const char *>(&s_NetQclass)[0]);
  s_Pkt.push_back(reinterpret_cast<const char *>(&s_NetQclass)[1]);

  return s_Pkt;
}

} // namespace

// ============================================================================
// Construction / basic parsing
// ============================================================================

TEST(DnsParser_valid_query) {
  std::vector<char> s_Pkt{BuildQuery("example.com")};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  ASSERT_EQ(s_Parser.Domain(), "example.com");
}

TEST(DnsParser_transaction_id) {
  std::vector<char> s_Pkt{BuildQuery("test.org", 1, 1, 0xABCD)};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  ASSERT_EQ(s_Parser.Packet().Header().Id(), static_cast<uint16_t>(0xABCD));
}

TEST(DnsParser_qdcount_one) {
  std::vector<char> s_Pkt{BuildQuery("hello.world")};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  ASSERT_EQ(s_Parser.Packet().Header().Qdcount(), static_cast<uint16_t>(1));
}

TEST(DnsParser_qtype_A) {
  std::vector<char> s_Pkt{BuildQuery("example.com", 1)};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  ASSERT_EQ(s_Parser.Packet().Questions()[0].Qtype(), static_cast<uint16_t>(1));
}

TEST(DnsParser_qtype_AAAA) {
  std::vector<char> s_Pkt{BuildQuery("example.com", 28)};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  ASSERT_EQ(s_Parser.Packet().Questions()[0].Qtype(), static_cast<uint16_t>(28));
}

TEST(DnsParser_qclass_IN) {
  std::vector<char> s_Pkt{BuildQuery("example.com", 1, 1)};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  ASSERT_EQ(s_Parser.Packet().Questions()[0].Qclass(), static_cast<uint16_t>(1));
}

// ============================================================================
// Domain / RootDomain / SubDomain extraction
// ============================================================================

TEST(DnsParser_root_domain_simple) {
  std::vector<char> s_Pkt{BuildQuery("example.com")};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  ASSERT_EQ(s_Parser.RootDomain(), "example.com");
}

TEST(DnsParser_root_domain_with_subdomain) {
  std::vector<char> s_Pkt{BuildQuery("www.example.com")};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  ASSERT_EQ(s_Parser.RootDomain(), "example.com");
}

TEST(DnsParser_subdomain_simple) {
  std::vector<char> s_Pkt{BuildQuery("www.example.com")};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  ASSERT_EQ(s_Parser.SubDomain(), "www");
}

TEST(DnsParser_subdomain_nested) {
  std::vector<char> s_Pkt{BuildQuery("a.b.c.example.com")};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  ASSERT_EQ(s_Parser.SubDomain(), "a.b.c");
}

TEST(DnsParser_subdomain_none) {
  std::vector<char> s_Pkt{BuildQuery("example.com")};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  ASSERT_EQ(s_Parser.SubDomain(), "");
}

TEST(DnsParser_record_type_A) {
  std::vector<char> s_Pkt{BuildQuery("example.com", 1)};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  ASSERT_EQ(s_Parser.RecordType(), "A");
}

TEST(DnsParser_record_type_AAAA) {
  std::vector<char> s_Pkt{BuildQuery("example.com", 28)};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  ASSERT_EQ(s_Parser.RecordType(), "AAAA");
}

TEST(DnsParser_record_type_CNAME) {
  std::vector<char> s_Pkt{BuildQuery("example.com", 5)};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  ASSERT_EQ(s_Parser.RecordType(), "CNAME");
}

TEST(DnsParser_record_type_PTR) {
  std::vector<char> s_Pkt{BuildQuery("1.0.0.127.in-addr.arpa", 12)};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  ASSERT_EQ(s_Parser.RecordType(), "PTR");
}

TEST(DnsParser_record_type_MX) {
  std::vector<char> s_Pkt{BuildQuery("example.com", 15)};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  ASSERT_EQ(s_Parser.RecordType(), "MX");
}

// ============================================================================
// Error handling
// ============================================================================

TEST(DnsParser_too_small) {
  char s_Data[4] = {};
  ASSERT_THROW(DnsParser(s_Data, 4), std::out_of_range);
}

TEST(DnsParser_null_pointer) {
  ASSERT_THROW(DnsParser(nullptr, 100), std::invalid_argument);
}

TEST(DnsParser_zero_length) {
  char s_Data[1] = {};
  ASSERT_THROW(DnsParser(s_Data, 0), std::out_of_range);
}

TEST(DnsParser_qdcount_zero) {
  // Build a packet with s_Qdcount=0
  std::vector<char> s_Pkt(12, 0);
  // id, flags, s_Qdcount=0, rest=0
  ASSERT_THROW(DnsParser(s_Pkt.data(), s_Pkt.size()), std::runtime_error);
}

TEST(DnsParser_qdcount_two) {
  // Build a packet with s_Qdcount=2
  std::vector<char> s_Pkt(12, 0);
  uint16_t s_Qdcount{HostToNetwork(static_cast<uint16_t>(2))};
  s_Pkt[4] = reinterpret_cast<const char *>(&s_Qdcount)[0];
  s_Pkt[5] = reinterpret_cast<const char *>(&s_Qdcount)[1];
  ASSERT_THROW(DnsParser(s_Pkt.data(), s_Pkt.size()), std::runtime_error);
}

TEST(DnsParser_truncated_question) {
  // Header with s_Qdcount=1 but no question s_Data beyond header
  std::vector<char> s_Pkt(12, 0);
  uint16_t s_Qdcount{HostToNetwork(static_cast<uint16_t>(1))};
  s_Pkt[4] = reinterpret_cast<const char *>(&s_Qdcount)[0];
  s_Pkt[5] = reinterpret_cast<const char *>(&s_Qdcount)[1];
  ASSERT_THROW(DnsParser(s_Pkt.data(), s_Pkt.size()), std::runtime_error);
}

TEST(DnsParser_label_too_long) {
  // Create a packet with a label length of 64 (exceeds max 63)
  std::vector<char> s_Pkt(12, 0);
  uint16_t s_Qdcount{HostToNetwork(static_cast<uint16_t>(1))};
  s_Pkt[4] = reinterpret_cast<const char *>(&s_Qdcount)[0];
  s_Pkt[5] = reinterpret_cast<const char *>(&s_Qdcount)[1];
  s_Pkt.push_back(64); // Label length 64 (invalid)
  for (int l_Index = 0; l_Index < 64; ++l_Index) {
    s_Pkt.push_back('a');
  }
  s_Pkt.push_back(0); // null terminator
  s_Pkt.push_back(0);
  s_Pkt.push_back(1); // QTYPE
  s_Pkt.push_back(0);
  s_Pkt.push_back(1); // QCLASS
  ASSERT_THROW(DnsParser(s_Pkt.data(), s_Pkt.size()), std::runtime_error);
}

TEST(DnsParser_compression_pointer_in_question) {
  // Compression pointers (0xC0xx) should be rejected in questions
  std::vector<char> s_Pkt(12, 0);
  uint16_t s_Qdcount{HostToNetwork(static_cast<uint16_t>(1))};
  s_Pkt[4] = reinterpret_cast<const char *>(&s_Qdcount)[0];
  s_Pkt[5] = reinterpret_cast<const char *>(&s_Qdcount)[1];
  s_Pkt.push_back(static_cast<char>(0xC0)); // Compression pointer
  s_Pkt.push_back(0x0C);
  ASSERT_THROW(DnsParser(s_Pkt.data(), s_Pkt.size()), std::runtime_error);
}

// ============================================================================
// Multi-label domains
// ============================================================================

TEST(DnsParser_three_label_domain) {
  std::vector<char> s_Pkt{BuildQuery("sub.example.co.uk")};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  ASSERT_EQ(s_Parser.Domain(), "sub.example.co.uk");
}

TEST(DnsParser_single_label) {
  std::vector<char> s_Pkt{BuildQuery("localhost")};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  ASSERT_EQ(s_Parser.Domain(), "localhost");
}

TEST(DnsParser_PTR_domain) {
  std::vector<char> s_Pkt{BuildQuery("1.168.192.in-addr.arpa", 12)};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  ASSERT_EQ(s_Parser.Domain(), "1.168.192.in-addr.arpa");
  ASSERT_EQ(s_Parser.RootDomain(), "in-addr.arpa");
}

// ============================================================================
// EDNS0 support (s_Arcount != 0)
// ============================================================================

TEST(DnsParser_edns0_query_accepted) {
  // Build a standard query, then append an OPT record in additional section
  std::vector<char> s_Pkt{BuildQuery("example.com")};

  // Set ARCOUNT=1 in header
  uint16_t s_Arcount{HostToNetwork(static_cast<uint16_t>(1))};
  s_Pkt[10] = reinterpret_cast<const char *>(&s_Arcount)[0];
  s_Pkt[11] = reinterpret_cast<const char *>(&s_Arcount)[1];

  // Append minimal OPT pseudo-record (RFC 6891)
  // NAME: 0x00 (root), TYPE: 0x0029 (OPT), CLASS: 0x1000 (4096 = UDP payload size)
  // TTL: 0x00000000, RDLENGTH: 0x0000
  s_Pkt.push_back(0x00);                     // NAME (root)
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(41);  // TYPE = OPT (41)
  s_Pkt.push_back(0x10);
  s_Pkt.push_back(0x00);// CLASS = 4096
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x00);// TTL
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x00);// RDLENGTH

  // Should parse without throwing
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  ASSERT_EQ(s_Parser.Domain(), "example.com");
}

// ============================================================================
// Compression pointer bounds check
// ============================================================================

TEST(DnsParser_compression_pointer_at_end_of_buffer) {
  // Build a header with s_Qdcount=1, then a question that starts with a compression pointer
  // at the very last byte of the buffer (no room for second byte)
  std::vector<char> s_Pkt(12, 0);
  uint16_t s_Qdcount{HostToNetwork(static_cast<uint16_t>(1))};
  s_Pkt[4] = reinterpret_cast<const char *>(&s_Qdcount)[0];
  s_Pkt[5] = reinterpret_cast<const char *>(&s_Qdcount)[1];
  s_Pkt.push_back(static_cast<char>(0xC0)); // Just one byte of compression pointer, no second byte
  // Should fail to parse (not crash)
  ASSERT_THROW(DnsParser(s_Pkt.data(), s_Pkt.size()), std::runtime_error);
}

// ============================================================================
// Fix #12: DnsParser domain caching
// ============================================================================

TEST(DnsParser_cached_domain_consistent) {
  std::vector<char> s_Pkt{BuildQuery("sub.example.com")};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  // Multiple calls should return the same cached values
  ASSERT_EQ(s_Parser.Domain(), "sub.example.com");
  ASSERT_EQ(s_Parser.Domain(), "sub.example.com");
  ASSERT_EQ(s_Parser.RootDomain(), "example.com");
  ASSERT_EQ(s_Parser.RootDomain(), "example.com");
  ASSERT_EQ(s_Parser.SubDomain(), "sub");
  ASSERT_EQ(s_Parser.SubDomain(), "sub");
}

TEST(DnsParser_cached_single_label) {
  std::vector<char> s_Pkt{BuildQuery("localhost")};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  ASSERT_EQ(s_Parser.Domain(), "localhost");
  ASSERT_EQ(s_Parser.RootDomain(), "localhost");
  ASSERT_EQ(s_Parser.SubDomain(), "");
}

TEST(DnsParser_cached_deep_subdomain) {
  std::vector<char> s_Pkt{BuildQuery("a.b.c.d.example.com")};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  ASSERT_EQ(s_Parser.Domain(), "a.b.c.d.example.com");
  ASSERT_EQ(s_Parser.RootDomain(), "example.com");
  ASSERT_EQ(s_Parser.SubDomain(), "a.b.c.d");
}

// ============================================================================
// Fix #7: DnsParser opcode extraction
// ============================================================================

TEST(DnsParser_opcode_standard_query) {
  std::vector<char> s_Pkt{BuildQuery("example.com")};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  ASSERT_EQ(s_Parser.Packet().Header().Opcode(), static_cast<uint8_t>(0));
}
