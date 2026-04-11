// Tests for DnsResponse: building DNS response packets
#include "test_framework.h"

#include "config.h"
#include "constants.h"
#include "dns_edns0.h"
#include "dns_packet.h"
#include "dns_response.h"
#include "utils.h"

#include "nlohmann/json.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace {

// Helper: create a DnsRequestPacket for testing (RD=1, like real clients)
DnsRequestPacket MakePacket(uint16_t p_Id, const std::vector<std::string> &p_Qname, uint16_t p_Qtype = 1, uint16_t p_Qclass = 1) {
  DnsHeader s_Hdr(p_Id, 0x0100, 1); // s_Flags: RD=1
  DnsQuestion s_Q(p_Qname, p_Qtype, p_Qclass);
  return DnsRequestPacket(s_Hdr, {s_Q});
}

// Helper: read uint16 from network byte order buffer
uint16_t ReadUint16(const std::vector<char> &p_Buf, std::size_t p_Offset) {
  return NetworkToHost(*reinterpret_cast<const uint16_t *>(p_Buf.data() + p_Offset));
}

// Helper: parse a domain name s_Wire format from a buffer and advance s_Offset.
// Supports both s_Raw s_Labels and compression pointers.
bool ParseName(const std::vector<char> &p_Buf, std::size_t &p_Offset) {
  const std::size_t s_Size = p_Buf.size();
  while (p_Offset < s_Size) {
    uint8_t s_Label{static_cast<uint8_t>(p_Buf[p_Offset])};
    if (s_Label == 0) {
      p_Offset += 1;
      return true;
    }
    if ((s_Label & 0xC0) == 0xC0) {
      if (p_Offset + 1 >= s_Size) {
        return false;
      }
      p_Offset += 2;
      return true;
    }
    if (s_Label > 63 || p_Offset + 1 + s_Label > s_Size) {
      return false;
    }
    p_Offset += 1 + s_Label;
  }
  return false;
}

} // namespace

// ============================================================================
// DomainToQuestion
// ============================================================================

TEST(DomainToQuestion_vector_simple) {
  std::vector<std::string> s_Labels{"example", "com"};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::DomainToQuestion(s_Labels, s_Output), 0);
  // Expected: \x07example\x03com\x00
  ASSERT_EQ(s_Output.size(), 13u); // 1+7 + 1+3 + 1
  ASSERT_EQ(s_Output[0], 7);
  ASSERT_EQ(s_Output[8], 3);
  ASSERT_EQ(s_Output[12], 0);
}

TEST(DomainToQuestion_string_simple) {
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::DomainToQuestion("example.com", s_Output), 0);
  ASSERT_EQ(s_Output.size(), 13u);
}

TEST(DomainToQuestion_empty_string) {
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::DomainToQuestion("", s_Output), 0);
  ASSERT_EQ(s_Output.size(), 1u);
  ASSERT_EQ(s_Output[0], 0);
}

TEST(DomainToQuestion_empty_label) {
  std::vector<std::string> s_Labels{"example", "", "com"};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::DomainToQuestion(s_Labels, s_Output), -1);
}

TEST(DomainToQuestion_label_too_long) {
  std::vector<std::string> s_Labels{std::string(64, 'a')};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::DomainToQuestion(s_Labels, s_Output), -1);
}

TEST(DomainToQuestion_max_label_63) {
  std::vector<std::string> s_Labels{std::string(63, 'a'), "com"};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::DomainToQuestion(s_Labels, s_Output), 0);
}

// ============================================================================
// NXDOMAIN response
// ============================================================================

TEST(DnsResponse_NXDOMAIN_basic) {
  DnsRequestPacket s_Pkt{MakePacket(0x1234, {"example", "com"})};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::NXDOMAIN(s_Pkt, s_Output), 0);

  // Check header
  ASSERT_GE(s_Output.size(), 12u);
  ASSERT_EQ(ReadUint16(s_Output, 0), static_cast<uint16_t>(0x1234));  // Transaction ID preserved
  ASSERT_EQ(ReadUint16(s_Output, 2), Constants::Dns::DNS_RESPONSE_NXDOMAIN); // Flags
  ASSERT_EQ(ReadUint16(s_Output, 4), static_cast<uint16_t>(1));       // QDCOUNT
  ASSERT_EQ(ReadUint16(s_Output, 6), static_cast<uint16_t>(0));       // ANCOUNT
}

TEST(DnsResponse_NXDOMAIN_preserves_id) {
  DnsRequestPacket s_Pkt{MakePacket(0xBEEF, {"test", "org"})};
  std::vector<char> s_Output;
  DnsResponse::NXDOMAIN(s_Pkt, s_Output);
  ASSERT_EQ(ReadUint16(s_Output, 0), static_cast<uint16_t>(0xBEEF));
}

TEST(DnsResponse_NXDOMAIN_with_zone_includes_SOA) {
  DnsRequestPacket s_Pkt{MakePacket(0xABCD, {"blocked", "example", "com"})};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::NXDOMAIN(s_Pkt, s_Output, "example.com"), 0);

  // Header checks
  ASSERT_GE(s_Output.size(), 12u);
  ASSERT_EQ(ReadUint16(s_Output, 0), static_cast<uint16_t>(0xABCD));         // Transaction ID
  ASSERT_EQ(ReadUint16(s_Output, 4), static_cast<uint16_t>(1));              // QDCOUNT
  ASSERT_EQ(ReadUint16(s_Output, 6), static_cast<uint16_t>(0));              // ANCOUNT
  ASSERT_EQ(ReadUint16(s_Output, 8), static_cast<uint16_t>(1));              // NSCOUNT (authority)
  ASSERT_EQ(ReadUint16(s_Output, 10), static_cast<uint16_t>(0));             // ARCOUNT

  // Parse the question section to reach the authority record.
  std::size_t s_Offset{12};
  ASSERT_TRUE(ParseName(s_Output, s_Offset));
  s_Offset += 4; // QTYPE + QCLASS

  // Parse authority section name
  ASSERT_TRUE(ParseName(s_Output, s_Offset));
  ASSERT_EQ(ReadUint16(s_Output, s_Offset), static_cast<uint16_t>(Constants::Dns::DNS_TYPE_SOA));
  s_Offset += 2;
  ASSERT_EQ(ReadUint16(s_Output, s_Offset), static_cast<uint16_t>(1)); // CLASS=IN
  s_Offset += 2;
  uint32_t s_Ttl{NetworkToHost(*reinterpret_cast<const uint32_t *>(s_Output.data() + s_Offset))};
  ASSERT_GT(s_Ttl, static_cast<uint32_t>(0));
  s_Offset += 4;
  uint16_t s_Rdlength{ReadUint16(s_Output, s_Offset)};
  ASSERT_GT(s_Rdlength, static_cast<uint16_t>(0));
}

TEST(DnsResponse_NXDOMAIN_without_zone_omits_SOA) {
  DnsRequestPacket s_Pkt{MakePacket(0xDEAD, {"missing", "example", "com"})};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::NXDOMAIN(s_Pkt, s_Output, ""), 0);

  ASSERT_EQ(ReadUint16(s_Output, 4), static_cast<uint16_t>(1));  // QDCOUNT
  ASSERT_EQ(ReadUint16(s_Output, 6), static_cast<uint16_t>(0));  // ANCOUNT
  ASSERT_EQ(ReadUint16(s_Output, 8), static_cast<uint16_t>(0));  // NSCOUNT
  ASSERT_EQ(ReadUint16(s_Output, 10), static_cast<uint16_t>(0)); // ARCOUNT

  // The packet should contain only the header + question section.
  std::size_t s_Offset{12};
  ASSERT_TRUE(ParseName(s_Output, s_Offset));
  s_Offset += 4; // QTYPE + QCLASS
  ASSERT_EQ(s_Offset, s_Output.size());
}

TEST(DnsResponse_NXDOMAIN_empty_zone_no_SOA) {
  DnsRequestPacket s_Pkt{MakePacket(0x1111, {"test", "com"})};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::NXDOMAIN(s_Pkt, s_Output, ""), 0);

  // Without zone, NSCOUNT should be 0 (no authority section)
  ASSERT_EQ(ReadUint16(s_Output, 8), static_cast<uint16_t>(0)); // NSCOUNT
}

TEST(DnsResponse_echoes_RD_bit) {
  // Query with RD=1 -> response should have RD=1
  DnsRequestPacket s_PktRd1{MakePacket(0x1000, {"example", "com"})};
  std::vector<char> s_Out1;
  DnsResponse::NXDOMAIN(s_PktRd1, s_Out1);
  uint16_t s_Flags1{ReadUint16(s_Out1, 2)};
  ASSERT_TRUE(s_Flags1 & 0x0100); // RD=1 echoed

  // Query with RD=0 -> response should have RD=0
  DnsHeader s_HdrNoRd(0x2000, 0x0000, 1); // s_Flags=0, no RD
  std::vector<std::string> s_Labels{"example", "com"};
  DnsQuestion s_Q(s_Labels, 1, 1);
  DnsRequestPacket s_PktRd0(s_HdrNoRd, {s_Q});
  std::vector<char> s_Out0;
  DnsResponse::NXDOMAIN(s_PktRd0, s_Out0);
  uint16_t s_Flags0{ReadUint16(s_Out0, 2)};
  ASSERT_FALSE(s_Flags0 & 0x0100); // RD=0 echoed
}

// ============================================================================
// FORMERR response
// ============================================================================

TEST(DnsResponse_FORMERR_from_packet) {
  DnsRequestPacket s_Pkt{MakePacket(0x5678, {"bad", "query"})};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::FORMERR(s_Pkt, s_Output), 0);

  ASSERT_GE(s_Output.size(), 12u);
  ASSERT_EQ(ReadUint16(s_Output, 0), static_cast<uint16_t>(0x5678));
  uint16_t s_Flags{ReadUint16(s_Output, 2)};
  ASSERT_EQ(s_Flags, Constants::Dns::DNS_RESPONSE_FORMERR);
}

TEST(DnsResponse_FORMERR_from_raw) {
  // Minimal s_Raw data: 2 bytes transaction ID
  char s_Raw[4] = {0x12, 0x34, 0x01, 0x00}; // ID=0x1234, s_Flags=0x0100 (RD=1)
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::FORMERR(s_Raw, 4, s_Output), 0);

  ASSERT_GE(s_Output.size(), 12u);
  ASSERT_EQ(ReadUint16(s_Output, 0), static_cast<uint16_t>(0x1234));
  // RD=1 in query should produce RD=1 in response
  uint16_t s_Flags{ReadUint16(s_Output, 2)};
  ASSERT_TRUE(s_Flags & 0x0100);
}

TEST(DnsResponse_FORMERR_from_raw_no_rd) {
  // Raw data with RD=0
  char s_Raw[4] = {0x12, 0x34, 0x00, 0x00}; // ID=0x1234, s_Flags=0x0000 (RD=0)
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::FORMERR(s_Raw, 4, s_Output), 0);
  uint16_t s_Flags{ReadUint16(s_Output, 2)};
  ASSERT_FALSE(s_Flags & 0x0100); // RD should NOT be set
}

TEST(DnsResponse_FORMERR_from_raw_null) {
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::FORMERR(nullptr, 0, s_Output), 0);
  ASSERT_EQ(s_Output.size(), 12u);
}

TEST(DnsResponse_FORMERR_from_raw_tiny) {
  // Only 1 byte - should still work (ID will be partial)
  char s_Raw[1] = {0x42};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::FORMERR(s_Raw, 1, s_Output), 0);
  ASSERT_EQ(s_Output.size(), 12u);
}

// ============================================================================
// A record response
// ============================================================================

TEST(DnsResponse_A_record) {
  DnsRequestPacket s_Pkt{MakePacket(0x1111, {"example", "com"})};

  // IPv4 binary for 192.168.1.1
  std::string s_Ipv4Hex;
  s_Ipv4Hex.push_back(static_cast<char>(192));
  s_Ipv4Hex.push_back(static_cast<char>(168));
  s_Ipv4Hex.push_back(static_cast<char>(1));
  s_Ipv4Hex.push_back(static_cast<char>(1));

  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::A(s_Pkt, s_Ipv4Hex, s_Output), 0);

  // Check header
  ASSERT_EQ(ReadUint16(s_Output, 0), static_cast<uint16_t>(0x1111));
  ASSERT_EQ(ReadUint16(s_Output, 2), Constants::Dns::DNS_RESPONSE_NOERROR);
  ASSERT_EQ(ReadUint16(s_Output, 4), static_cast<uint16_t>(1)); // QDCOUNT
  ASSERT_EQ(ReadUint16(s_Output, 6), static_cast<uint16_t>(1)); // ANCOUNT

  // Verify response includes IP data
  ASSERT_GT(s_Output.size(), 12u + 13u); // Header + question + answer
}

TEST(DnsResponse_A_record_invalid_size) {
  DnsRequestPacket s_Pkt{MakePacket(0x1111, {"example", "com"})};
  std::string s_BadIpv4(3, '\0'); // Wrong size (should be 4)
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::A(s_Pkt, s_BadIpv4, s_Output), -1);
}

// ============================================================================
// AAAA record response
// ============================================================================

TEST(DnsResponse_AAAA_record) {
  DnsRequestPacket s_Pkt = MakePacket(0x2222, {"example", "com"}, 28); // AAAA query

  std::string s_Ipv6Hex(16, '\0');
  s_Ipv6Hex[15] = 1; // ::1

  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::AAAA(s_Pkt, s_Ipv6Hex, s_Output), 0);

  ASSERT_EQ(ReadUint16(s_Output, 6), static_cast<uint16_t>(1)); // ANCOUNT
  ASSERT_GT(s_Output.size(), 12u);
}

TEST(DnsResponse_AAAA_record_invalid_size) {
  DnsRequestPacket s_Pkt{MakePacket(0x2222, {"example", "com"}, 28)};
  std::string s_BadIpv6(15, '\0'); // Wrong size (should be 16)
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::AAAA(s_Pkt, s_BadIpv6, s_Output), -1);
}

// ============================================================================
// CNAME record response
// ============================================================================

TEST(DnsResponse_CNAME_record) {
  DnsRequestPacket s_Pkt{MakePacket(0x3333, {"www", "example", "com"}, 5)};

  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::CNAME(s_Pkt, "other.example.com.", s_Output), 0);

  ASSERT_EQ(ReadUint16(s_Output, 6), static_cast<uint16_t>(1)); // ANCOUNT
}

TEST(DnsResponse_CNAME_empty_domain) {
  DnsRequestPacket s_Pkt{MakePacket(0x3333, {"www", "example", "com"}, 5)};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::CNAME(s_Pkt, "", s_Output), -1);
}

// ============================================================================
// PTR record response
// ============================================================================

TEST(DnsResponse_PTR_record) {
  DnsRequestPacket s_Pkt{MakePacket(0x4444, {"1", "0", "0", "127", "in-addr", "arpa"}, 12)};

  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::PTR(s_Pkt, "localhost.", s_Output), 0);

  ASSERT_EQ(ReadUint16(s_Output, 6), static_cast<uint16_t>(1)); // ANCOUNT
}

TEST(DnsResponse_PTR_empty_domain) {
  DnsRequestPacket s_Pkt{MakePacket(0x4444, {"1", "0", "0", "127", "in-addr", "arpa"}, 12)};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::PTR(s_Pkt, "", s_Output), -1);
}

// ============================================================================
// CallResponseFunction dispatch
// ============================================================================

TEST(DnsResponse_CallResponseFunction_NXDOMAIN) {
  DnsRequestPacket s_Pkt{MakePacket(0x5555, {"blocked", "com"})};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::CallResponseFunction("NXDOMAIN", s_Pkt, "", s_Output), 0);
}

TEST(DnsResponse_CallResponseFunction_NXDOMAIN_with_zone) {
  DnsRequestPacket s_Pkt{MakePacket(0x5556, {"sub", "blocked", "com"})};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::CallResponseFunction("NXDOMAIN", s_Pkt, "blocked.com", s_Output), 0);
  ASSERT_EQ(ReadUint16(s_Output, 8), static_cast<uint16_t>(1)); // NSCOUNT = 1 (SOA in authority)
}

TEST(DnsResponse_CallResponseFunction_FORMERR) {
  DnsRequestPacket s_Pkt{MakePacket(0x6666, {"bad", "com"})};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::CallResponseFunction("FORMERR", s_Pkt, "", s_Output), 0);
}

TEST(DnsResponse_CallResponseFunction_unsupported) {
  DnsRequestPacket s_Pkt{MakePacket(0x7777, {"test", "com"})};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::CallResponseFunction("UNKNOWN_TYPE", s_Pkt, "", s_Output), -1);
}

TEST(DnsResponse_CallResponseFunction_raw_FORMERR) {
  char s_Raw[4] = {0x12, 0x34, 0x01, 0x00};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::CallResponseFunction("FORMERR", s_Raw, 4, s_Output), 0);
}

TEST(DnsResponse_CallResponseFunction_raw_unsupported) {
  char s_Raw[4] = {0x12, 0x34, 0x01, 0x00};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::CallResponseFunction("A", s_Raw, 4, s_Output), -1);
}

// ============================================================================
// Fix #6: DomainToQuestion 255-byte total s_Wire name limit
// ============================================================================

TEST(DomainToQuestion_name_exactly_255_bytes) {
  // Build s_Labels that total exactly 255 bytes in s_Wire format
  // Each label adds length_byte + chars. Plus null terminator.
  // 4 s_Labels of 63 chars = 4*(1+63) + 1 = 257 => too long
  // 3 s_Labels of 63 chars + 1 label of 62 chars = 3*(1+63) + (1+62) + 1 = 192 + 63 + 1 = 256 => too long
  // 3 s_Labels of 63 chars + 1 label of 61 chars = 3*(1+63) + (1+61) + 1 = 192 + 62 + 1 = 255 => exact
  std::vector<std::string> s_Labels{std::string(63, 'a'), std::string(63, 'b'), std::string(63, 'c'), std::string(61, 'd')};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::DomainToQuestion(s_Labels, s_Output), 0);
  ASSERT_EQ(s_Output.size(), 255u);
}

TEST(DomainToQuestion_name_exceeds_255_bytes) {
  // 3 s_Labels of 63 chars + 1 label of 62 = 256 bytes total => should fail
  std::vector<std::string> s_Labels{std::string(63, 'a'), std::string(63, 'b'), std::string(63, 'c'), std::string(62, 'd')};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::DomainToQuestion(s_Labels, s_Output), -1);
}

// ============================================================================
// Fix #7: NOTIMP response
// ============================================================================

TEST(DnsResponse_NOTIMP_basic) {
  DnsRequestPacket s_Pkt{MakePacket(0xAAAA, {"example", "com"})};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::NOTIMP(s_Pkt, s_Output), 0);

  ASSERT_GE(s_Output.size(), 12u);
  ASSERT_EQ(ReadUint16(s_Output, 0), static_cast<uint16_t>(0xAAAA));  // Transaction ID preserved
  uint16_t s_Flags{ReadUint16(s_Output, 2)};
  // RCODE should be 4 (NOTIMP)
  ASSERT_EQ(s_Flags & 0x000F, static_cast<uint16_t>(4));
  // QR bit should be 1
  ASSERT_TRUE(s_Flags & 0x8000);
}

TEST(DnsResponse_NOTIMP_preserves_id) {
  DnsRequestPacket s_Pkt{MakePacket(0xDEAD, {"test", "org"})};
  std::vector<char> s_Output;
  DnsResponse::NOTIMP(s_Pkt, s_Output);
  ASSERT_EQ(ReadUint16(s_Output, 0), static_cast<uint16_t>(0xDEAD));
}

TEST(DnsResponse_NOTIMP_has_question_section) {
  DnsRequestPacket s_Pkt{MakePacket(0x1234, {"example", "com"})};
  std::vector<char> s_Output;
  DnsResponse::NOTIMP(s_Pkt, s_Output);
  ASSERT_EQ(ReadUint16(s_Output, 4), static_cast<uint16_t>(1)); // QDCOUNT
  ASSERT_EQ(ReadUint16(s_Output, 6), static_cast<uint16_t>(0)); // ANCOUNT
  ASSERT_GT(s_Output.size(), 12u); // Has question data after header
}

// ============================================================================
// Fix #7: CallResponseFunction with NOTIMP
// ============================================================================

TEST(DnsResponse_CallResponseFunction_NOTIMP) {
  DnsRequestPacket s_Pkt{MakePacket(0xBBBB, {"example", "com"})};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::CallResponseFunction("NOTIMP", s_Pkt, "", s_Output), 0);
  uint16_t s_Flags{ReadUint16(s_Output, 2)};
  ASSERT_EQ(s_Flags & 0x000F, static_cast<uint16_t>(4));
}

// ============================================================================
// SERVFAIL response
// ============================================================================

TEST(DnsResponse_SERVFAIL_basic) {
  DnsRequestPacket s_Pkt{MakePacket(0xCCCC, {"example", "com"})};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::SERVFAIL(s_Pkt, s_Output), 0);

  ASSERT_GE(s_Output.size(), 12u);
  ASSERT_EQ(ReadUint16(s_Output, 0), static_cast<uint16_t>(0xCCCC));
  uint16_t s_Flags{ReadUint16(s_Output, 2)};
  ASSERT_EQ(s_Flags & 0x000F, static_cast<uint16_t>(2)); // RCODE = SERVFAIL
  ASSERT_TRUE(s_Flags & 0x8000);                          // QR = 1
  ASSERT_EQ(ReadUint16(s_Output, 4), static_cast<uint16_t>(1)); // QDCOUNT
  ASSERT_EQ(ReadUint16(s_Output, 6), static_cast<uint16_t>(0)); // ANCOUNT
}

TEST(DnsResponse_SERVFAIL_preserves_id) {
  DnsRequestPacket s_Pkt{MakePacket(0xFACE, {"test", "org"})};
  std::vector<char> s_Output;
  DnsResponse::SERVFAIL(s_Pkt, s_Output);
  ASSERT_EQ(ReadUint16(s_Output, 0), static_cast<uint16_t>(0xFACE));
}

TEST(DnsResponse_SERVFAIL_via_dispatch) {
  DnsRequestPacket s_Pkt{MakePacket(0xDDDD, {"example", "com"})};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::CallResponseFunction("SERVFAIL", s_Pkt, "", s_Output), 0);
  uint16_t s_Flags{ReadUint16(s_Output, 2)};
  ASSERT_EQ(s_Flags & 0x000F, static_cast<uint16_t>(2));
}

// ============================================================================
// REFUSED response
// ============================================================================

TEST(DnsResponse_REFUSED_basic) {
  DnsRequestPacket s_Pkt{MakePacket(0xEEEE, {"example", "com"})};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::REFUSED(s_Pkt, s_Output), 0);

  ASSERT_GE(s_Output.size(), 12u);
  ASSERT_EQ(ReadUint16(s_Output, 0), static_cast<uint16_t>(0xEEEE));
  uint16_t s_Flags{ReadUint16(s_Output, 2)};
  ASSERT_EQ(s_Flags & 0x000F, static_cast<uint16_t>(5)); // RCODE = REFUSED
  ASSERT_TRUE(s_Flags & 0x8000);                          // QR = 1
  ASSERT_EQ(ReadUint16(s_Output, 4), static_cast<uint16_t>(1)); // QDCOUNT
  ASSERT_EQ(ReadUint16(s_Output, 6), static_cast<uint16_t>(0)); // ANCOUNT
}

TEST(DnsResponse_REFUSED_preserves_id) {
  DnsRequestPacket s_Pkt{MakePacket(0xF00D, {"test", "org"})};
  std::vector<char> s_Output;
  DnsResponse::REFUSED(s_Pkt, s_Output);
  ASSERT_EQ(ReadUint16(s_Output, 0), static_cast<uint16_t>(0xF00D));
}

TEST(DnsResponse_REFUSED_via_dispatch) {
  DnsRequestPacket s_Pkt{MakePacket(0x9999, {"example", "com"})};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::CallResponseFunction("REFUSED", s_Pkt, "", s_Output), 0);
  uint16_t s_Flags{ReadUint16(s_Output, 2)};
  ASSERT_EQ(s_Flags & 0x000F, static_cast<uint16_t>(5));
}

// ============================================================================
// NS record response
// ============================================================================

TEST(DnsResponse_NS_record) {
  DnsRequestPacket s_Pkt = MakePacket(0x1111, {"example", "com"}, 2); // NS query
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::NS(s_Pkt, "ns1.example.com.", s_Output), 0);

  ASSERT_EQ(ReadUint16(s_Output, 0), static_cast<uint16_t>(0x1111));
  ASSERT_EQ(ReadUint16(s_Output, 2), Constants::Dns::DNS_RESPONSE_NOERROR);
  ASSERT_EQ(ReadUint16(s_Output, 6), static_cast<uint16_t>(1)); // ANCOUNT
  ASSERT_GT(s_Output.size(), 12u);
}

TEST(DnsResponse_NS_empty_domain) {
  DnsRequestPacket s_Pkt{MakePacket(0x1111, {"example", "com"}, 2)};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::NS(s_Pkt, "", s_Output), -1);
}

TEST(DnsResponse_NS_via_dispatch) {
  DnsRequestPacket s_Pkt{MakePacket(0x1111, {"example", "com"}, 2)};
  std::vector<char> s_Output;
  nlohmann::json data = "ns1.example.com.";
  ASSERT_EQ(DnsResponse::CallResponseFunction("NS", s_Pkt, data, s_Output), 0);
  ASSERT_EQ(ReadUint16(s_Output, 6), static_cast<uint16_t>(1));
}

// ============================================================================
// SOA record response
// ============================================================================

TEST(DnsResponse_SOA_record) {
  DnsRequestPacket s_Pkt = MakePacket(0x2222, {"example", "com"}, 6); // SOA query
  nlohmann::json s_SoaData{{"primary", "ns1.example.com."}, {"admin", "admin.example.com."}, {"serial", 2024010101}, {"refresh", 3600}, {"retry", 900}, {"expire", 604800}, {"minimum", 86400}};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::SOA(s_Pkt, s_SoaData, s_Output), 0);

  ASSERT_EQ(ReadUint16(s_Output, 0), static_cast<uint16_t>(0x2222));
  ASSERT_EQ(ReadUint16(s_Output, 6), static_cast<uint16_t>(1)); // ANCOUNT
  ASSERT_GT(s_Output.size(), 12u + 13u); // Header + question + answer data
}

TEST(DnsResponse_SOA_missing_field) {
  DnsRequestPacket s_Pkt{MakePacket(0x2222, {"example", "com"}, 6)};
  nlohmann::json s_BadData{{"primary", "ns1.example.com."}};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::SOA(s_Pkt, s_BadData, s_Output), -1);
}

TEST(DnsResponse_SOA_not_object) {
  DnsRequestPacket s_Pkt{MakePacket(0x2222, {"example", "com"}, 6)};
  nlohmann::json s_BadData = "not an object";
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::SOA(s_Pkt, s_BadData, s_Output), -1);
}

TEST(DnsResponse_SOA_via_dispatch) {
  DnsRequestPacket s_Pkt{MakePacket(0x2222, {"example", "com"}, 6)};
  nlohmann::json s_SoaData{{"primary", "ns1.example.com."}, {"admin", "admin.example.com."}, {"serial", 1}, {"refresh", 3600}, {"retry", 900}, {"expire", 604800}, {"minimum", 86400}};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::CallResponseFunction("SOA", s_Pkt, s_SoaData, s_Output), 0);
}

// ============================================================================
// MX record response
// ============================================================================

TEST(DnsResponse_MX_record) {
  DnsRequestPacket s_Pkt = MakePacket(0x3333, {"example", "com"}, 15); // MX query
  nlohmann::json s_MxData{{"preference", 10}, {"exchange", "mail.example.com."}};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::MX(s_Pkt, s_MxData, s_Output), 0);

  ASSERT_EQ(ReadUint16(s_Output, 0), static_cast<uint16_t>(0x3333));
  ASSERT_EQ(ReadUint16(s_Output, 6), static_cast<uint16_t>(1)); // ANCOUNT
  ASSERT_GT(s_Output.size(), 12u);
}

TEST(DnsResponse_MX_missing_field) {
  DnsRequestPacket s_Pkt{MakePacket(0x3333, {"example", "com"}, 15)};
  nlohmann::json s_BadData{{"preference", 10}};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::MX(s_Pkt, s_BadData, s_Output), -1);
}

TEST(DnsResponse_MX_not_object) {
  DnsRequestPacket s_Pkt{MakePacket(0x3333, {"example", "com"}, 15)};
  nlohmann::json s_BadData = "not an object";
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::MX(s_Pkt, s_BadData, s_Output), -1);
}

TEST(DnsResponse_MX_via_dispatch) {
  DnsRequestPacket s_Pkt{MakePacket(0x3333, {"example", "com"}, 15)};
  nlohmann::json s_MxData{{"preference", 10}, {"exchange", "mail.example.com."}};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::CallResponseFunction("MX", s_Pkt, s_MxData, s_Output), 0);
}

// ============================================================================
// TXT record response
// ============================================================================

TEST(DnsResponse_TXT_record_single) {
  DnsRequestPacket s_Pkt = MakePacket(0x4444, {"example", "com"}, 16); // TXT query
  nlohmann::json s_TxtData{nlohmann::json::array({"v=spf1 include:example.com ~all"})};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::TXT(s_Pkt, s_TxtData, s_Output), 0);

  ASSERT_EQ(ReadUint16(s_Output, 0), static_cast<uint16_t>(0x4444));
  ASSERT_EQ(ReadUint16(s_Output, 6), static_cast<uint16_t>(1)); // ANCOUNT
}

TEST(DnsResponse_TXT_record_multiple_strings) {
  DnsRequestPacket s_Pkt{MakePacket(0x4444, {"example", "com"}, 16)};
  nlohmann::json s_TxtData{nlohmann::json::array({"chunk1", "chunk2", "chunk3"})};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::TXT(s_Pkt, s_TxtData, s_Output), 0);
  ASSERT_EQ(ReadUint16(s_Output, 6), static_cast<uint16_t>(1));
}

TEST(DnsResponse_TXT_empty_array) {
  DnsRequestPacket s_Pkt{MakePacket(0x4444, {"example", "com"}, 16)};
  nlohmann::json s_TxtData{nlohmann::json::array()};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::TXT(s_Pkt, s_TxtData, s_Output), -1);
}

TEST(DnsResponse_TXT_not_array) {
  DnsRequestPacket s_Pkt{MakePacket(0x4444, {"example", "com"}, 16)};
  nlohmann::json s_BadData = "just a string";
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::TXT(s_Pkt, s_BadData, s_Output), -1);
}

TEST(DnsResponse_TXT_string_too_long) {
  DnsRequestPacket s_Pkt{MakePacket(0x4444, {"example", "com"}, 16)};
  nlohmann::json s_TxtData{nlohmann::json::array({std::string(256, 'x')})};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::TXT(s_Pkt, s_TxtData, s_Output), -1);
}

TEST(DnsResponse_TXT_max_length_string) {
  DnsRequestPacket s_Pkt{MakePacket(0x4444, {"example", "com"}, 16)};
  nlohmann::json s_TxtData{nlohmann::json::array({std::string(255, 'a')})};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::TXT(s_Pkt, s_TxtData, s_Output), 0);
}

TEST(DnsResponse_TXT_via_dispatch) {
  DnsRequestPacket s_Pkt{MakePacket(0x4444, {"example", "com"}, 16)};
  nlohmann::json s_TxtData{nlohmann::json::array({"hello"})};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::CallResponseFunction("TXT", s_Pkt, s_TxtData, s_Output), 0);
}

// ============================================================================
// SRV record response
// ============================================================================

TEST(DnsResponse_SRV_record) {
  DnsRequestPacket s_Pkt = MakePacket(0x5555, {"_sip", "_tcp", "example", "com"}, 33); // SRV query
  nlohmann::json s_SrvData{{"priority", 10}, {"weight", 60}, {"port", 5060}, {"target", "sipserver.example.com."}};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::SRV(s_Pkt, s_SrvData, s_Output), 0);

  ASSERT_EQ(ReadUint16(s_Output, 0), static_cast<uint16_t>(0x5555));
  ASSERT_EQ(ReadUint16(s_Output, 6), static_cast<uint16_t>(1)); // ANCOUNT
}

TEST(DnsResponse_SRV_missing_field) {
  DnsRequestPacket s_Pkt{MakePacket(0x5555, {"_sip", "_tcp", "example", "com"}, 33)};
  nlohmann::json s_BadData{{"priority", 10}, {"weight", 60}};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::SRV(s_Pkt, s_BadData, s_Output), -1);
}

TEST(DnsResponse_SRV_not_object) {
  DnsRequestPacket s_Pkt{MakePacket(0x5555, {"_sip", "_tcp", "example", "com"}, 33)};
  nlohmann::json s_BadData = 42;
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::SRV(s_Pkt, s_BadData, s_Output), -1);
}

TEST(DnsResponse_SRV_via_dispatch) {
  DnsRequestPacket s_Pkt{MakePacket(0x5555, {"_sip", "_tcp", "example", "com"}, 33)};
  nlohmann::json s_SrvData{{"priority", 10}, {"weight", 60}, {"port", 5060}, {"target", "sipserver.example.com."}};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::CallResponseFunction("SRV", s_Pkt, s_SrvData, s_Output), 0);
}

// ============================================================================
// AppendAnswer
// ============================================================================

TEST(DnsResponse_AppendAnswer_A) {
  DnsRequestPacket s_Pkt{MakePacket(0x1111, {"example", "com"})};
  // Build a base response first (header + question)
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::NXDOMAIN(s_Pkt, s_Output), 0);
  std::size_t s_BaseSize{s_Output.size()};

  // Append an A answer record
  std::string s_Ipv4;
  s_Ipv4.push_back(static_cast<char>(10));
  s_Ipv4.push_back(static_cast<char>(0));
  s_Ipv4.push_back(static_cast<char>(0));
  s_Ipv4.push_back(static_cast<char>(1));
  ASSERT_EQ(DnsResponse::AppendAnswer("A", s_Pkt, s_Ipv4, s_Output), 0);
  // Should have appended 16 bytes (2+2+2+4+2+4)
  ASSERT_EQ(s_Output.size(), s_BaseSize + 16);
}

TEST(DnsResponse_AppendAnswer_CNAME) {
  DnsRequestPacket s_Pkt{MakePacket(0x2222, {"www", "example", "com"})};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::AppendAnswer("CNAME", s_Pkt, "other.example.com.", s_Output), 0);
  ASSERT_GT(s_Output.size(), 0u);
}

TEST(DnsResponse_AppendAnswer_with_name) {
  // AppendAnswer with explicit name (for CNAME chain resolved s_Records)
  DnsRequestPacket s_Pkt{MakePacket(0x3333, {"alias", "example", "com"})};
  std::vector<char> s_Output;
  std::string s_Ipv4;
  s_Ipv4.push_back(static_cast<char>(1));
  s_Ipv4.push_back(static_cast<char>(2));
  s_Ipv4.push_back(static_cast<char>(3));
  s_Ipv4.push_back(static_cast<char>(4));
  // Append with explicit name "target.example.com."
  ASSERT_EQ(DnsResponse::AppendAnswer("A", s_Pkt, s_Ipv4, s_Output, "target.example.com."), 0);
  ASSERT_GT(s_Output.size(), 4u); // At least the IP data
}

TEST(DnsResponse_AppendAnswer_unsupported) {
  DnsRequestPacket s_Pkt{MakePacket(0x4444, {"example", "com"})};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::AppendAnswer("UNKNOWN", s_Pkt, "", s_Output), -1);
}

// ============================================================================
// MultiAnswer
// ============================================================================

TEST(DnsResponse_MultiAnswer_single) {
  DnsRequestPacket s_Pkt{MakePacket(0xAA01, {"example", "com"})};
  std::string s_Ipv4;
  s_Ipv4.push_back(static_cast<char>(10));
  s_Ipv4.push_back(static_cast<char>(0));
  s_Ipv4.push_back(static_cast<char>(0));
  s_Ipv4.push_back(static_cast<char>(1));

  std::vector<DnsResponse::AnswerRecord> s_Records{{"A", s_Ipv4, ""}};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::MultiAnswer(s_Pkt, s_Records, s_Output), 0);

  ASSERT_EQ(ReadUint16(s_Output, 0), static_cast<uint16_t>(0xAA01));
  ASSERT_EQ(ReadUint16(s_Output, 2), Constants::Dns::DNS_RESPONSE_NOERROR);
  ASSERT_EQ(ReadUint16(s_Output, 4), static_cast<uint16_t>(1)); // QDCOUNT
  ASSERT_EQ(ReadUint16(s_Output, 6), static_cast<uint16_t>(1)); // ANCOUNT
}

TEST(DnsResponse_MultiAnswer_two_records) {
  DnsRequestPacket s_Pkt{MakePacket(0xAA02, {"example", "com"})};
  std::string s_Ipv4(4, '\0');
  s_Ipv4[0] = static_cast<char>(192);
  s_Ipv4[1] = static_cast<char>(168);
  s_Ipv4[2] = static_cast<char>(1);
  s_Ipv4[3] = static_cast<char>(1);
  std::string s_Ipv6(16, '\0');
  s_Ipv6[15] = 1;

  std::vector<DnsResponse::AnswerRecord> s_Records{{"A", s_Ipv4, ""}, {"AAAA", s_Ipv6, ""}};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::MultiAnswer(s_Pkt, s_Records, s_Output), 0);

  ASSERT_EQ(ReadUint16(s_Output, 6), static_cast<uint16_t>(2)); // ANCOUNT = 2
}

TEST(DnsResponse_MultiAnswer_cname_chain) {
  // Simulate CNAME + A resolution
  DnsRequestPacket s_Pkt{MakePacket(0xAA03, {"alias", "example", "com"})};
  std::string s_Ipv4;
  s_Ipv4.push_back(static_cast<char>(1));
  s_Ipv4.push_back(static_cast<char>(2));
  s_Ipv4.push_back(static_cast<char>(3));
  s_Ipv4.push_back(static_cast<char>(4));

  std::vector<DnsResponse::AnswerRecord> s_Records{
      {"CNAME", "target.example.com.", ""},                 // CNAME answer (name via question pointer)
      {"A", s_Ipv4, "target.example.com."}                    // A answer for canonical name
  };
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::MultiAnswer(s_Pkt, s_Records, s_Output), 0);

  ASSERT_EQ(ReadUint16(s_Output, 6), static_cast<uint16_t>(2)); // ANCOUNT = 2
  ASSERT_EQ(ReadUint16(s_Output, 2), Constants::Dns::DNS_RESPONSE_NOERROR);
}

TEST(DnsResponse_MultiAnswer_empty) {
  DnsRequestPacket s_Pkt{MakePacket(0xAA04, {"example", "com"})};
  std::vector<DnsResponse::AnswerRecord> s_Records{};
  std::vector<char> s_Output;
  ASSERT_EQ(DnsResponse::MultiAnswer(s_Pkt, s_Records, s_Output), -1);
}

TEST(DnsResponse_MultiAnswer_preserves_id) {
  DnsRequestPacket s_Pkt{MakePacket(0xDEAD, {"test", "org"})};
  std::string s_Ipv4(4, '\0');
  std::vector<DnsResponse::AnswerRecord> s_Records{{"A", s_Ipv4, ""}};
  std::vector<char> s_Output;
  DnsResponse::MultiAnswer(s_Pkt, s_Records, s_Output);
  ASSERT_EQ(ReadUint16(s_Output, 0), static_cast<uint16_t>(0xDEAD));
}

// ============================================================================
// EDNS0 / OPT Response tests
// ============================================================================

namespace {

// Read uint32 from network byte order buffer
uint32_t ReadUint32(const std::vector<char> &p_Buf, std::size_t p_Offset) {
  return NetworkToHost(*reinterpret_cast<const uint32_t *>(p_Buf.data() + p_Offset));
}

// Find OPT record in additional section of a response.
// Returns s_Offset of the OPT NAME byte, or 0 if not found.
// Scans backwards from the end since OPT is always appended last.
std::size_t FindOpt(const std::vector<char> &p_Buf) {
  if (p_Buf.size() < 23) {
    return 0; // minimum: 12-byte header + 11-byte OPT
  }
  // Walk from end: the last OPT record starts with NAME(1)+TYPE(2)+CLASS(2)+TTL(4)+RDLENGTH(2) = 11 bytes + RDATA
  // Read ARCOUNT
  uint16_t s_Arcount{ReadUint16(p_Buf, 10)};
  if (s_Arcount == 0) {
    return 0;
  }
  // Scan backwards for the pattern: byte 0x00 followed by TYPE=41 (0x0029)
  for (std::size_t l_Index{p_Buf.size() - 11}; l_Index >= 12; l_Index--) {
    if (static_cast<uint8_t>(p_Buf[l_Index]) == 0x00 && l_Index + 3 <= p_Buf.size() && ReadUint16(p_Buf, l_Index + 1) == Constants::Dns::DNS_TYPE_OPT) {
      return l_Index;
    }
  }
  return 0;
}

} // namespace

TEST(DnsResponse_AppendOpt_basic) {
  DnsRequestPacket s_Pkt{MakePacket(0x1234, {"example", "com"})};
  std::vector<char> s_Output;
  DnsResponse::NXDOMAIN(s_Pkt, s_Output);
  std::size_t s_BeforeSize{s_Output.size()};
  uint16_t s_ArBefore{ReadUint16(s_Output, 10)};
  DnsResponse::AppendOpt(s_Output, 0, nullptr);
  // Should have grown by at least 11 bytes (1 NAME + 2 TYPE + 2 CLASS + 4 TTL + 2 RDLENGTH)
  ASSERT_GT(s_Output.size(), s_BeforeSize + 10);
  // ARCOUNT should have incremented
  ASSERT_EQ(ReadUint16(s_Output, 10), static_cast<uint16_t>(s_ArBefore + 1));
  // Find the OPT record
  std::size_t s_Opt{FindOpt(s_Output)};
  ASSERT_GT(s_Opt, static_cast<std::size_t>(0));
  // TYPE = 41
  ASSERT_EQ(ReadUint16(s_Output, s_Opt + 1), static_cast<uint16_t>(41));
  // CLASS = Constants::Dns::DEFAULT_EDNS_PACKET_SIZE (1232)
  ASSERT_EQ(ReadUint16(s_Output, s_Opt + 3), static_cast<uint16_t>(Constants::Dns::DEFAULT_EDNS_PACKET_SIZE));
  // TTL = 0 (version 0, ext_rcode 0, DO=0)
  ASSERT_EQ(ReadUint32(s_Output, s_Opt + 5), static_cast<uint32_t>(0));
  // RDLENGTH = 0 (no options echoed)
  ASSERT_EQ(ReadUint16(s_Output, s_Opt + 9), static_cast<uint16_t>(0));
}

TEST(DnsResponse_AppendOpt_with_extended_rcode) {
  DnsRequestPacket s_Pkt{MakePacket(0x5678, {"test", "org"})};
  std::vector<char> s_Output;
  DnsResponse::NXDOMAIN(s_Pkt, s_Output);
  DnsResponse::AppendOpt(s_Output, 1, nullptr); // ext_rcode=1 => BADVERS
  std::size_t s_Opt{FindOpt(s_Output)};
  ASSERT_GT(s_Opt, static_cast<std::size_t>(0));
  uint32_t s_Ttl{ReadUint32(s_Output, s_Opt + 5)};
  // ext_rcode=1 is in high byte of TTL
  ASSERT_EQ((s_Ttl >> 24) & 0xFF, static_cast<uint32_t>(1));
}

TEST(DnsResponse_AppendOpt_echoes_cookie) {
  // Build EdnsData with a COOKIE option
  EdnsData s_Edns{};
  s_Edns.m_UdpPayloadSize_ = 4096;
  EdnsOption s_Cookie{};
  s_Cookie.m_Code_ = Constants::Dns::EDNS_OPTION_CODE_COOKIE;
  s_Cookie.m_Data_ = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  s_Edns.m_Options_.push_back(s_Cookie);

  DnsRequestPacket s_Pkt{MakePacket(0xAAAA, {"a", "com"})};
  std::vector<char> s_Output;
  DnsResponse::NXDOMAIN(s_Pkt, s_Output);
  DnsResponse::AppendOpt(s_Output, 0, &s_Edns);

  std::size_t s_Opt{FindOpt(s_Output)};
  ASSERT_GT(s_Opt, static_cast<std::size_t>(0));
  // RDLENGTH should be 4 (option header) + 8 (s_Cookie data) = 12
  uint16_t s_Rdlen{ReadUint16(s_Output, s_Opt + 9)};
  ASSERT_EQ(s_Rdlen, static_cast<uint16_t>(12));
  // Option code = 10 (COOKIE)
  std::size_t s_RdataStart{s_Opt + 11};
  ASSERT_EQ(ReadUint16(s_Output, s_RdataStart), static_cast<uint16_t>(Constants::Dns::EDNS_OPTION_CODE_COOKIE));
  // Option length = 8
  ASSERT_EQ(ReadUint16(s_Output, s_RdataStart + 2), static_cast<uint16_t>(8));
  // Cookie data echoed
  ASSERT_EQ(static_cast<uint8_t>(s_Output[s_RdataStart + 4]), static_cast<uint8_t>(0x01));
  ASSERT_EQ(static_cast<uint8_t>(s_Output[s_RdataStart + 11]), static_cast<uint8_t>(0x08));
}

TEST(DnsResponse_AppendOpt_ignores_non_cookie_options) {
  EdnsData s_Edns{};
  EdnsOption s_Unknown{};
  s_Unknown.m_Code_ = 65001;
  s_Unknown.m_Data_ = {0xFF, 0xFF, 0xFF, 0xFF};
  s_Edns.m_Options_.push_back(s_Unknown);

  DnsRequestPacket s_Pkt{MakePacket(0xBBBB, {"b", "com"})};
  std::vector<char> s_Output;
  DnsResponse::NXDOMAIN(s_Pkt, s_Output);
  DnsResponse::AppendOpt(s_Output, 0, &s_Edns);

  std::size_t s_Opt{FindOpt(s_Output)};
  ASSERT_GT(s_Opt, static_cast<std::size_t>(0));
  // RDLENGTH should be 0: s_Unknown option is not echoed
  ASSERT_EQ(ReadUint16(s_Output, s_Opt + 9), static_cast<uint16_t>(0));
}

TEST(DnsResponse_FORMERR_OPT_includes_opt) {
  DnsRequestPacket s_Pkt{MakePacket(0xCCCC, {"c", "com"})};
  std::vector<char> s_Output;
  int s_Ret{DnsResponse::FORMERR_OPT(s_Pkt, s_Output, nullptr)};
  ASSERT_EQ(s_Ret, 0);
  // RCODE should be FORMERR (1)
  uint16_t s_Flags{ReadUint16(s_Output, 2)};
  ASSERT_EQ(s_Flags & 0x000F, static_cast<uint16_t>(1)); // RCODE = FORMERR
  // ARCOUNT should be 1 (from AppendOpt)
  ASSERT_EQ(ReadUint16(s_Output, 10), static_cast<uint16_t>(1));
  // OPT record should be present
  ASSERT_GT(FindOpt(s_Output), static_cast<size_t>(0));
}

TEST(DnsResponse_FORMERR_OPT_raw_includes_opt) {
  // Build s_Raw query s_Wire
  DnsRequestPacket s_Req{MakePacket(0xDDDD, {"d", "com"})};
  std::vector<char> s_Wire(s_Req.WireSize());
  s_Req.ToWire(s_Wire.data(), s_Wire.size());

  std::vector<char> s_Output;
  int s_Ret{DnsResponse::FORMERR_OPT(s_Wire.data(), s_Wire.size(), s_Output, nullptr)};
  ASSERT_EQ(s_Ret, 0);
  uint16_t s_Flags{ReadUint16(s_Output, 2)};
  ASSERT_EQ(s_Flags & 0x000F, static_cast<uint16_t>(1));
  ASSERT_EQ(ReadUint16(s_Output, 10), static_cast<uint16_t>(1));
}

TEST(DnsResponse_BADVERS_rcode_and_opt) {
  DnsRequestPacket s_Pkt{MakePacket(0xEEEE, {"e", "com"})};
  EdnsData s_Edns{};
  s_Edns.m_UdpPayloadSize_ = 4096;

  std::vector<char> s_Output;
  int s_Ret{DnsResponse::BADVERS(s_Pkt, s_Output, &s_Edns)};
  ASSERT_EQ(s_Ret, 0);
  // Header RCODE should be 0 (NOERROR)
  uint16_t s_Flags{ReadUint16(s_Output, 2)};
  ASSERT_EQ(s_Flags & 0x000F, static_cast<uint16_t>(0));
  // OPT should have ext_rcode=1 (so full RCODE = 1<<4 | 0 = 16 = BADVERS)
  std::size_t s_Opt{FindOpt(s_Output)};
  ASSERT_GT(s_Opt, static_cast<std::size_t>(0));
  uint32_t s_Ttl{ReadUint32(s_Output, s_Opt + 5)};
  ASSERT_EQ((s_Ttl >> 24) & 0xFF, static_cast<uint32_t>(1));
  // ARCOUNT = 1
  ASSERT_EQ(ReadUint16(s_Output, 10), static_cast<uint16_t>(1));
}
