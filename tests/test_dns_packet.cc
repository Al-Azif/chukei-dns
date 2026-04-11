// Tests for the new DnsHeader, DnsQuestion, DnsAnswer, DnsRequestPacket, DnsResponsePacket classes
#include "test_framework.h"

#include "constants.h"
#include "dns_edns0.h"
#include "dns_packet.h"
#include "dns_packet_answer.h"
#include "dns_packet_header.h"
#include "dns_packet_question.h"
#include "utils.h"

#include <cstdint>
#include <string>
#include <vector>

// ============================================================================
// DnsHeader - Basic construction
// ============================================================================

TEST(DnsHeader_default_all_zero) {
  DnsHeader s_Hdr;
  ASSERT_EQ(s_Hdr.Id(), static_cast<uint16_t>(0));
  ASSERT_EQ(s_Hdr.Qdcount(), static_cast<uint16_t>(0));
  ASSERT_EQ(s_Hdr.Ancount(), static_cast<uint16_t>(0));
  ASSERT_FALSE(s_Hdr.Qr());
  ASSERT_EQ(s_Hdr.Rcode(), static_cast<uint8_t>(0));
}

TEST(DnsHeader_explicit_constructor) {
  DnsHeader s_Hdr(0x1234, 0x0100, 1, 0, 0, 0);
  ASSERT_EQ(s_Hdr.Id(), static_cast<uint16_t>(0x1234));
  ASSERT_EQ(s_Hdr.Qdcount(), static_cast<uint16_t>(1));
}

TEST(DnsHeader_size_is_12) {
  ASSERT_EQ(DnsHeader::WireSize(), static_cast<DnsHeader::size_type>(12)); // 12 bytes
}

// ============================================================================
// DnsHeader - Field setters/getters
// ============================================================================

TEST(DnsHeader_set_id) {
  DnsHeader s_Hdr;
  s_Hdr.SetId(0xABCD);
  ASSERT_EQ(s_Hdr.Id(), static_cast<uint16_t>(0xABCD));
}

TEST(DnsHeader_set_qr) {
  DnsHeader s_Hdr;
  s_Hdr.SetQr(true);
  ASSERT_TRUE(s_Hdr.Qr());
  s_Hdr.SetQr(false);
  ASSERT_FALSE(s_Hdr.Qr());
}

TEST(DnsHeader_set_opcode) {
  DnsHeader s_Hdr;
  s_Hdr.SetOpcode(2);
  ASSERT_EQ(s_Hdr.Opcode(), static_cast<uint8_t>(2));
}

TEST(DnsHeader_set_rd) {
  DnsHeader s_Hdr;
  s_Hdr.SetRd(true);
  ASSERT_TRUE(s_Hdr.Rd());
}

TEST(DnsHeader_set_ra) {
  DnsHeader s_Hdr;
  s_Hdr.SetRa(true);
  ASSERT_TRUE(s_Hdr.Ra());
}

TEST(DnsHeader_set_rcode) {
  DnsHeader s_Hdr;
  s_Hdr.SetRcode(3); // NXDOMAIN
  ASSERT_EQ(s_Hdr.Rcode(), static_cast<uint8_t>(3));
}

TEST(DnsHeader_set_counts) {
  DnsHeader s_Hdr;
  s_Hdr.SetQdcount(1);
  s_Hdr.SetAncount(2);
  ASSERT_EQ(s_Hdr.Qdcount(), static_cast<uint16_t>(1));
  ASSERT_EQ(s_Hdr.Ancount(), static_cast<uint16_t>(2));
}

// ============================================================================
// DnsHeader - Factory methods
// ============================================================================

TEST(DnsHeader_make_query_header) {
  DnsHeader s_Hdr{DnsHeader::MakeQueryHeader(0x1234)};
  ASSERT_EQ(s_Hdr.Id(), static_cast<uint16_t>(0x1234));
  ASSERT_FALSE(s_Hdr.Qr());
  ASSERT_TRUE(s_Hdr.Rd());
  ASSERT_EQ(s_Hdr.Qdcount(), static_cast<uint16_t>(1));
}

TEST(DnsHeader_make_response_header) {
  DnsHeader s_Query{DnsHeader::MakeQueryHeader(0x5678)};
  DnsHeader s_Resp{DnsHeader::MakeResponseHeader(s_Query)};
  ASSERT_EQ(s_Resp.Id(), static_cast<uint16_t>(0x5678));
  ASSERT_TRUE(s_Resp.Qr());
  ASSERT_TRUE(s_Resp.Ra());
  ASSERT_EQ(s_Resp.Rcode(), static_cast<uint8_t>(0));
}

TEST(DnsHeader_make_response_nxdomain) {
  DnsHeader s_Query{DnsHeader::MakeQueryHeader(0x9999)};
  DnsHeader s_Resp = DnsHeader::MakeResponseHeader(s_Query, 3); // NXDOMAIN
  ASSERT_EQ(s_Resp.Rcode(), static_cast<uint8_t>(3));
}

// ============================================================================
// DnsHeader - Wire format round-trip
// ============================================================================

TEST(DnsHeader_to_wire_and_back) {
  DnsHeader s_Original{DnsHeader::MakeQueryHeader(0xBEEF)};
  s_Original.SetOpcode(0);
  s_Original.SetRd(true);

  uint8_t s_Wire[12];
  DnsHeader::size_type s_Written{s_Original.ToWire(s_Wire, sizeof(s_Wire))};
  ASSERT_EQ(s_Written, static_cast<DnsHeader::size_type>(12));

  DnsHeader s_Parsed;
  ASSERT_TRUE(DnsHeader::FromWire(s_Wire, sizeof(s_Wire), s_Parsed));

  ASSERT_EQ(s_Parsed.Id(), s_Original.Id());
  ASSERT_EQ(s_Parsed.Qr(), s_Original.Qr());
  ASSERT_EQ(s_Parsed.Rd(), s_Original.Rd());
  ASSERT_EQ(s_Parsed.Qdcount(), s_Original.Qdcount());
}

// ============================================================================
// DnsHeader - Equality
// ============================================================================

TEST(DnsHeader_equality) {
  DnsHeader s_A(0x1234, 0x0100, 1);
  DnsHeader s_B(0x1234, 0x0100, 1);
  ASSERT_TRUE(s_A == s_B);
}

TEST(DnsHeader_inequality) {
  DnsHeader s_A(0x1234, 0x0100, 1);
  DnsHeader s_B(0x5678, 0x0100, 1);
  ASSERT_TRUE(s_A != s_B);
}

// ============================================================================
// DnsQuestion - Basic construction and domain handling
// ============================================================================

TEST(DnsQuestion_default_constructor) {
  DnsQuestion s_Q;
  ASSERT_TRUE(s_Q.empty());
  ASSERT_EQ(s_Q.Qtype(), static_cast<uint16_t>(0));
  ASSERT_EQ(s_Q.Qclass(), static_cast<uint16_t>(0));
}

TEST(DnsQuestion_MakeAQuery) {
  DnsQuestion s_Q{DnsQuestion::MakeAQuery("example.com")};
  ASSERT_FALSE(s_Q.empty());
  ASSERT_EQ(s_Q.Qtype(), static_cast<uint16_t>(1));  // A
  ASSERT_EQ(s_Q.Qclass(), static_cast<uint16_t>(1)); // IN
  ASSERT_EQ(s_Q.QnameAsString(), "example.com");
}

TEST(DnsQuestion_MakeAaaaQuery) {
  DnsQuestion s_Q{DnsQuestion::MakeAaaaQuery("test.org")};
  ASSERT_EQ(s_Q.Qtype(), static_cast<uint16_t>(28)); // AAAA
  ASSERT_EQ(s_Q.QnameAsString(), "test.org");
}

TEST(DnsQuestion_MakeSoaQuery) {
  DnsQuestion s_Q{DnsQuestion::MakeSoaQuery("example.com")};
  ASSERT_FALSE(s_Q.empty());
  ASSERT_EQ(s_Q.Qtype(), static_cast<uint16_t>(6));  // SOA
  ASSERT_EQ(s_Q.Qclass(), static_cast<uint16_t>(1)); // IN
  ASSERT_EQ(s_Q.QnameAsString(), "example.com");
}

TEST(DnsQuestion_MakeSrvQuery) {
  DnsQuestion s_Q{DnsQuestion::MakeSrvQuery("_sip._tcp.example.com")};
  ASSERT_FALSE(s_Q.empty());
  ASSERT_EQ(s_Q.Qtype(), static_cast<uint16_t>(33)); // SRV
  ASSERT_EQ(s_Q.Qclass(), static_cast<uint16_t>(1)); // IN
  ASSERT_EQ(s_Q.QnameAsString(), "_sip._tcp.example.com");
  ASSERT_EQ(s_Q.size(), static_cast<DnsQuestion::size_type>(4)); // _sip, _tcp, example, com
}

TEST(DnsQuestion_MakeSoaQuery_wire_roundtrip) {
  DnsQuestion s_Original{DnsQuestion::MakeSoaQuery("example.com")};
  std::vector<uint8_t> s_Wire(s_Original.WireSize());
  DnsQuestion::size_type s_Written{s_Original.ToWire(s_Wire.data(), s_Wire.size())};
  ASSERT_GT(s_Written, static_cast<DnsQuestion::size_type>(0));

  DnsQuestion s_Parsed;
  std::size_t s_Offset{0};
  ASSERT_TRUE(DnsQuestion::FromWire(s_Wire.data(), s_Wire.size(), s_Offset, s_Parsed));
  ASSERT_EQ(s_Parsed.QnameAsString(), "example.com");
  ASSERT_EQ(s_Parsed.Qtype(), static_cast<uint16_t>(6));
  ASSERT_EQ(s_Parsed.Qclass(), static_cast<uint16_t>(1));
}

TEST(DnsQuestion_MakeSrvQuery_wire_roundtrip) {
  DnsQuestion s_Original{DnsQuestion::MakeSrvQuery("_http._tcp.example.com")};
  std::vector<uint8_t> s_Wire(s_Original.WireSize());
  DnsQuestion::size_type s_Written{s_Original.ToWire(s_Wire.data(), s_Wire.size())};
  ASSERT_GT(s_Written, static_cast<DnsQuestion::size_type>(0));

  DnsQuestion s_Parsed;
  std::size_t s_Offset{0};
  ASSERT_TRUE(DnsQuestion::FromWire(s_Wire.data(), s_Wire.size(), s_Offset, s_Parsed));
  ASSERT_EQ(s_Parsed.QnameAsString(), "_http._tcp.example.com");
  ASSERT_EQ(s_Parsed.Qtype(), static_cast<uint16_t>(33));
  ASSERT_EQ(s_Parsed.Qclass(), static_cast<uint16_t>(1));
}

TEST(DnsQuestion_MakePtrQuery) {
  DnsQuestion s_Q{DnsQuestion::MakePtrQuery("192.168.1.1")};
  ASSERT_EQ(s_Q.Qtype(), static_cast<uint16_t>(12)); // PTR
}

TEST(DnsQuestion_MakePtrQuery_ipv4_qname) {
  DnsQuestion s_Q{DnsQuestion::MakePtrQuery("192.168.1.1")};
  ASSERT_EQ(s_Q.QnameAsString(), "1.1.168.192.in-addr.arpa");
}

TEST(DnsQuestion_MakePtrQuery_ipv6_full) {
  DnsQuestion s_Q{DnsQuestion::MakePtrQuery("2001:0db8:0000:0000:0000:0000:0000:0001")};
  ASSERT_EQ(s_Q.Qtype(), static_cast<uint16_t>(12));
  ASSERT_EQ(s_Q.QnameAsString(), "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa");
}

TEST(DnsQuestion_MakePtrQuery_ipv6_abbreviated) {
  DnsQuestion s_Q{DnsQuestion::MakePtrQuery("2001:db8::1")};
  ASSERT_EQ(s_Q.Qtype(), static_cast<uint16_t>(12));
  ASSERT_EQ(s_Q.QnameAsString(), "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa");
}

TEST(DnsQuestion_MakePtrQuery_ipv6_loopback) {
  DnsQuestion s_Q{DnsQuestion::MakePtrQuery("::1")};
  ASSERT_EQ(s_Q.Qtype(), static_cast<uint16_t>(12));
  ASSERT_EQ(s_Q.QnameAsString(), "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa");
}

TEST(DnsQuestion_MakePtrQuery_ipv6_all_zeros) {
  DnsQuestion s_Q{DnsQuestion::MakePtrQuery("::")};
  ASSERT_EQ(s_Q.Qtype(), static_cast<uint16_t>(12));
  ASSERT_EQ(s_Q.QnameAsString(), "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa");
}

TEST(DnsQuestion_MakePtrQuery_ipv6_mixed) {
  DnsQuestion s_Q{DnsQuestion::MakePtrQuery("fe80::1ff:fe23:4567:890a")};
  ASSERT_EQ(s_Q.Qtype(), static_cast<uint16_t>(12));
  ASSERT_EQ(s_Q.QnameAsString(), "a.0.9.8.7.6.5.4.3.2.e.f.f.f.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa");
}

TEST(DnsQuestion_domain_labels) {
  DnsQuestion s_Q{DnsQuestion::MakeAQuery("sub.example.com")};
  ASSERT_EQ(s_Q.size(), static_cast<DnsQuestion::size_type>(3));
}

TEST(DnsQuestion_wire_roundtrip) {
  DnsQuestion s_Original{DnsQuestion::MakeAQuery("example.com")};
  std::vector<uint8_t> s_Wire(s_Original.WireSize());
  DnsQuestion::size_type s_Written{s_Original.ToWire(s_Wire.data(), s_Wire.size())};
  ASSERT_GT(s_Written, static_cast<DnsQuestion::size_type>(0));

  DnsQuestion s_Parsed;
  std::size_t s_Offset{0};
  ASSERT_TRUE(DnsQuestion::FromWire(s_Wire.data(), s_Wire.size(), s_Offset, s_Parsed));
  ASSERT_EQ(s_Parsed.QnameAsString(), "example.com");
  ASSERT_EQ(s_Parsed.Qtype(), static_cast<uint16_t>(1));
}

// ============================================================================
// DnsAnswer - Factory methods
// ============================================================================

TEST(DnsAnswer_make_a_record) {
  DnsAnswer s_Ans{DnsAnswer::MakeARecord("example.com", "192.168.1.1")};
  ASSERT_EQ(s_Ans.Type(), static_cast<uint16_t>(1)); // A
  ASSERT_EQ(s_Ans.Rclass(), static_cast<uint16_t>(1)); // IN
  ASSERT_EQ(s_Ans.NameAsString(), "example.com");
}

TEST(DnsAnswer_make_aaaa_record) {
  DnsAnswer s_Ans{DnsAnswer::MakeAaaaRecord("example.com", "::1")};
  ASSERT_EQ(s_Ans.Type(), static_cast<uint16_t>(28)); // AAAA
}

TEST(DnsAnswer_make_cname_record) {
  DnsAnswer s_Ans{DnsAnswer::MakeCnameRecord("www.example.com", "example.com")};
  ASSERT_EQ(s_Ans.Type(), static_cast<uint16_t>(5)); // CNAME
}

TEST(DnsAnswer_make_ptr_record) {
  DnsAnswer s_Ans{DnsAnswer::MakePtrRecord("1.0.0.127.in-addr.arpa", "localhost")};
  ASSERT_EQ(s_Ans.Type(), static_cast<uint16_t>(12)); // PTR
}

TEST(DnsAnswer_ttl) {
  DnsAnswer s_Ans{DnsAnswer::MakeARecord("example.com", "1.2.3.4", 7200)};
  ASSERT_EQ(s_Ans.Ttl(), static_cast<uint32_t>(7200));
}

TEST(DnsAnswer_default_ttl) {
  DnsAnswer s_Ans{DnsAnswer::MakeARecord("example.com", "1.2.3.4")};
  ASSERT_EQ(s_Ans.Ttl(), static_cast<uint32_t>(300)); // Default
}

TEST(DnsAnswer_wire_serializable) {
  DnsAnswer s_Original{DnsAnswer::MakeARecord("test.org", "10.0.0.1", 300)};
  ASSERT_GT(s_Original.WireSize(), static_cast<DnsAnswer::size_type>(0));
}

// ============================================================================
// DnsRequestPacket / DnsResponsePacket
// ============================================================================

TEST(DnsRequestPacket_MakeAQuery) {
  DnsRequestPacket s_Req{DnsRequestPacket::MakeAQuery(0x1234, "example.com")};
  ASSERT_FALSE(s_Req.Header().Qr());
  ASSERT_EQ(s_Req.Header().Qdcount(), static_cast<uint16_t>(1));
}

TEST(DnsRequestPacket_wire_roundtrip) {
  DnsRequestPacket s_Req{DnsRequestPacket::MakeAQuery(0x1234, "example.com")};
  std::vector<char> s_Wire(s_Req.WireSize());
  DnsRequestPacket::size_type s_Written{s_Req.ToWire(s_Wire.data(), s_Wire.size())};
  ASSERT_GT(s_Written, static_cast<DnsRequestPacket::size_type>(12)); // At minimum header + question

  DnsRequestPacket s_Parsed;
  ASSERT_TRUE(DnsRequestPacket::FromWire(s_Wire.data(), s_Wire.size(), s_Parsed));
  ASSERT_EQ(s_Parsed.Header().Qdcount(), static_cast<uint16_t>(1));
}

TEST(DnsResponsePacket_make_error_nxdomain) {
  DnsRequestPacket s_Req{DnsRequestPacket::MakeAQuery(0x1234, "blocked.com")};
  DnsResponsePacket s_Resp = DnsResponsePacket::MakeErrorResponse(s_Req, 3); // NXDOMAIN
  ASSERT_TRUE(s_Resp.Header().Qr());
  ASSERT_EQ(s_Resp.Header().Rcode(), static_cast<uint8_t>(3));
}

TEST(DnsResponsePacket_make_response_noerror) {
  DnsRequestPacket s_Req{DnsRequestPacket::MakeAQuery(0x1234, "example.com")};
  DnsResponsePacket s_Resp = DnsResponsePacket::MakeResponse(s_Req, 0); // NOERROR
  ASSERT_TRUE(s_Resp.Header().Qr());
  ASSERT_EQ(s_Resp.Header().Rcode(), static_cast<uint8_t>(0));
}

// ============================================================================
// DnsHeader - IncrementCount overflow saturation
// ============================================================================

TEST(DnsHeader_IncrementCount_normal) {
  DnsHeader s_Hdr;
  ASSERT_EQ(s_Hdr.IncrementCount('q'), static_cast<uint16_t>(1));
  ASSERT_EQ(s_Hdr.Qdcount(), static_cast<uint16_t>(1));
  ASSERT_EQ(s_Hdr.IncrementCount('a'), static_cast<uint16_t>(1));
  ASSERT_EQ(s_Hdr.Ancount(), static_cast<uint16_t>(1));
  ASSERT_EQ(s_Hdr.IncrementCount('n'), static_cast<uint16_t>(1));
  ASSERT_EQ(s_Hdr.Nscount(), static_cast<uint16_t>(1));
  ASSERT_EQ(s_Hdr.IncrementCount('r'), static_cast<uint16_t>(1));
  ASSERT_EQ(s_Hdr.Arcount(), static_cast<uint16_t>(1));
}

TEST(DnsHeader_IncrementCount_overflow_qdcount) {
  DnsHeader s_Hdr;
  s_Hdr.SetQdcount(UINT16_MAX);
  ASSERT_EQ(s_Hdr.IncrementCount('q'), static_cast<uint16_t>(0));
  // Count should remain at UINT16_MAX (not wrapped to 0)
  ASSERT_EQ(s_Hdr.Qdcount(), static_cast<uint16_t>(UINT16_MAX));
}

TEST(DnsHeader_IncrementCount_overflow_ancount) {
  DnsHeader s_Hdr;
  s_Hdr.SetAncount(UINT16_MAX);
  ASSERT_EQ(s_Hdr.IncrementCount('A'), static_cast<uint16_t>(0));
  ASSERT_EQ(s_Hdr.Ancount(), static_cast<uint16_t>(UINT16_MAX));
}

TEST(DnsHeader_IncrementCount_overflow_nscount) {
  DnsHeader s_Hdr;
  s_Hdr.SetNscount(UINT16_MAX);
  ASSERT_EQ(s_Hdr.IncrementCount('N'), static_cast<uint16_t>(0));
  ASSERT_EQ(s_Hdr.Nscount(), static_cast<uint16_t>(UINT16_MAX));
}

TEST(DnsHeader_IncrementCount_overflow_arcount) {
  DnsHeader s_Hdr;
  s_Hdr.SetArcount(UINT16_MAX);
  ASSERT_EQ(s_Hdr.IncrementCount('R'), static_cast<uint16_t>(0));
  ASSERT_EQ(s_Hdr.Arcount(), static_cast<uint16_t>(UINT16_MAX));
}

TEST(DnsHeader_IncrementCount_invalid_section) {
  DnsHeader s_Hdr;
  ASSERT_EQ(s_Hdr.IncrementCount('x'), static_cast<uint16_t>(0));
}

// ============================================================================
// DnsAnswer - SetRdataIpv6 :: expansion
// ============================================================================

TEST(DnsAnswer_set_rdata_ipv6_loopback) {
  // ::1 should expand to 0000:0000:0000:0000:0000:0000:0000:0001
  DnsAnswer s_Ans{DnsAnswer::MakeAaaaRecord("example.com", "::1")};
  ASSERT_EQ(s_Ans.Rdlength(), static_cast<uint16_t>(16));
  const std::vector<char> &s_Rdata = s_Ans.Rdata();
  // First 14 bytes should be zero
  for (int l_Index = 0; l_Index < 14; ++l_Index) {
    ASSERT_EQ(s_Rdata[l_Index], 0);
  }
  // Last 2 bytes: 0x00, 0x01
  ASSERT_EQ(s_Rdata[14], 0);
  ASSERT_EQ(s_Rdata[15], 1);
}

TEST(DnsAnswer_set_rdata_ipv6_all_zeros) {
  // :: should be all zeros
  DnsAnswer s_Ans{DnsAnswer::MakeAaaaRecord("example.com", "::")};
  ASSERT_EQ(s_Ans.Rdlength(), static_cast<uint16_t>(16));
  const std::vector<char> &s_Rdata = s_Ans.Rdata();
  for (int l_Index = 0; l_Index < 16; ++l_Index) {
    ASSERT_EQ(s_Rdata[l_Index], 0);
  }
}

TEST(DnsAnswer_set_rdata_ipv6_prefix_only) {
  // 2001:db8:: should expand to 2001:0db8:0000:...:0000
  DnsAnswer s_Ans{DnsAnswer::MakeAaaaRecord("example.com", "2001:db8::")};
  ASSERT_EQ(s_Ans.Rdlength(), static_cast<uint16_t>(16));
  const std::vector<char> &s_Rdata = s_Ans.Rdata();
  ASSERT_EQ(static_cast<unsigned char>(s_Rdata[0]), 0x20u);
  ASSERT_EQ(static_cast<unsigned char>(s_Rdata[1]), 0x01u);
  ASSERT_EQ(static_cast<unsigned char>(s_Rdata[2]), 0x0Du);
  ASSERT_EQ(static_cast<unsigned char>(s_Rdata[3]), 0xB8u);
  for (int l_Index = 4; l_Index < 16; ++l_Index) {
    ASSERT_EQ(s_Rdata[l_Index], 0);
  }
}

TEST(DnsAnswer_set_rdata_ipv6_middle_compression) {
  // 2001::1 should be 2001:0000:0000:0000:0000:0000:0000:0001
  DnsAnswer s_Ans{DnsAnswer::MakeAaaaRecord("example.com", "2001::1")};
  ASSERT_EQ(s_Ans.Rdlength(), static_cast<uint16_t>(16));
  const std::vector<char> &s_Rdata = s_Ans.Rdata();
  ASSERT_EQ(static_cast<unsigned char>(s_Rdata[0]), 0x20u);
  ASSERT_EQ(static_cast<unsigned char>(s_Rdata[1]), 0x01u);
  for (int l_Index = 2; l_Index < 14; ++l_Index) {
    ASSERT_EQ(s_Rdata[l_Index], 0);
  }
  ASSERT_EQ(s_Rdata[14], 0);
  ASSERT_EQ(s_Rdata[15], 1);
}

TEST(DnsAnswer_set_rdata_ipv6_full_address) {
  // Full 8-group address with no compression
  DnsAnswer s_Ans{DnsAnswer::MakeAaaaRecord("example.com", "2001:0db8:85a3:0000:0000:8a2e:0370:7334")};
  ASSERT_EQ(s_Ans.Rdlength(), static_cast<uint16_t>(16));
  const std::vector<char> &s_Rdata = s_Ans.Rdata();
  ASSERT_EQ(static_cast<unsigned char>(s_Rdata[0]), 0x20u);
  ASSERT_EQ(static_cast<unsigned char>(s_Rdata[1]), 0x01u);
  ASSERT_EQ(static_cast<unsigned char>(s_Rdata[2]), 0x0Du);
  ASSERT_EQ(static_cast<unsigned char>(s_Rdata[3]), 0xB8u);
}

TEST(DnsAnswer_set_rdata_ipv6_invalid_too_many_groups) {
  ASSERT_THROW((void)DnsAnswer::MakeAaaaRecord("example.com", "1:2:3:4:5:6:7:8:9"), std::invalid_argument);
}

// ============================================================================
// DnsQuestion - Underscore label support (SRV/DKIM records)
// ============================================================================

TEST(DnsQuestion_underscore_labels) {
  // SRV-style domain with underscore prefixed s_Labels
  DnsQuestion s_Q("_sip._tcp.example.com", 33, 1); // SRV type
  std::vector<std::string> s_Labels{s_Q.Qname()};
  ASSERT_EQ(s_Labels.size(), static_cast<std::size_t>(4));
  ASSERT_EQ(s_Labels[0], "_sip");
  ASSERT_EQ(s_Labels[1], "_tcp");
  ASSERT_EQ(s_Labels[2], "example");
  ASSERT_EQ(s_Labels[3], "com");
}

TEST(DnsQuestion_dkim_underscore_label) {
  // DKIM-style domain
  DnsQuestion s_Q("_dmarc.example.com", 16, 1); // TXT type
  std::vector<std::string> s_Labels{s_Q.Qname()};
  ASSERT_EQ(s_Labels.size(), static_cast<std::size_t>(3));
  ASSERT_EQ(s_Labels[0], "_dmarc");
}

// ============================================================================
// DnsAnswer - SetRdataDomainName with underscores
// ============================================================================

TEST(DnsAnswer_domain_name_with_underscores) {
  DnsAnswer s_Ans{DnsAnswer::MakeCnameRecord("_sip._tcp.example.com", "sip.example.com")};
  std::vector<std::string> s_Name{s_Ans.Name()};
  ASSERT_EQ(s_Name.size(), static_cast<std::size_t>(4));
  ASSERT_EQ(s_Name[0], "_sip");
  ASSERT_EQ(s_Name[1], "_tcp");
}

TEST(DnsAnswer_set_rdata_ipv4_basic) {
  DnsAnswer s_Ans{DnsAnswer::MakeARecord("example.com", "192.168.1.1")};
  ASSERT_EQ(s_Ans.Rdlength(), static_cast<uint16_t>(4));
  const std::vector<char> &s_Rdata = s_Ans.Rdata();
  ASSERT_EQ(static_cast<unsigned char>(s_Rdata[0]), 192u);
  ASSERT_EQ(static_cast<unsigned char>(s_Rdata[1]), 168u);
  ASSERT_EQ(static_cast<unsigned char>(s_Rdata[2]), 1u);
  ASSERT_EQ(static_cast<unsigned char>(s_Rdata[3]), 1u);
}

TEST(DnsAnswer_set_rdata_ipv4_zeros) {
  DnsAnswer s_Ans{DnsAnswer::MakeARecord("example.com", "0.0.0.0")};
  const std::vector<char> &s_Rdata = s_Ans.Rdata();
  for (int l_Index = 0; l_Index < 4; ++l_Index) {
    ASSERT_EQ(s_Rdata[l_Index], 0);
  }
}

TEST(DnsAnswer_set_rdata_ipv4_max) {
  DnsAnswer s_Ans{DnsAnswer::MakeARecord("example.com", "255.255.255.255")};
  const std::vector<char> &s_Rdata = s_Ans.Rdata();
  for (int l_Index = 0; l_Index < 4; ++l_Index) {
    ASSERT_EQ(static_cast<unsigned char>(s_Rdata[l_Index]), 255u);
  }
}

TEST(DnsAnswer_set_rdata_ipv4_invalid_octet) {
  ASSERT_THROW((void)DnsAnswer::MakeARecord("example.com", "256.0.0.0"), std::invalid_argument);
}

TEST(DnsAnswer_set_rdata_ipv4_too_few_octets) {
  ASSERT_THROW((void)DnsAnswer::MakeARecord("example.com", "1.2.3"), std::invalid_argument);
}

// ============================================================================
// Fix #2: DnsHeader::operator< strict weak ordering
// ============================================================================

TEST(DnsHeader_less_than_by_id) {
  DnsHeader s_A(0x0001, 0x0100, 1);
  DnsHeader s_B(0x0002, 0x0100, 1);
  ASSERT_TRUE(s_A < s_B);
  ASSERT_FALSE(s_B < s_A);
}

TEST(DnsHeader_less_than_equal_not_less) {
  DnsHeader s_A(0x1234, 0x0100, 1);
  DnsHeader s_B(0x1234, 0x0100, 1);
  ASSERT_FALSE(s_A < s_B);
  ASSERT_FALSE(s_B < s_A);
}

TEST(DnsHeader_less_than_by_flags) {
  DnsHeader s_A(0x1234, 0x0100, 1);
  DnsHeader s_B(0x1234, 0x0200, 1);
  ASSERT_TRUE(s_A < s_B);
  ASSERT_FALSE(s_B < s_A);
}

TEST(DnsHeader_less_than_by_qdcount) {
  DnsHeader s_A(0x1234, 0x0100, 1);
  DnsHeader s_B(0x1234, 0x0100, 2);
  ASSERT_TRUE(s_A < s_B);
}

TEST(DnsHeader_less_than_by_ancount) {
  DnsHeader s_A(0x1234, 0x0100, 1, 0);
  DnsHeader s_B(0x1234, 0x0100, 1, 1);
  ASSERT_TRUE(s_A < s_B);
}

TEST(DnsHeader_less_than_by_nscount) {
  DnsHeader s_A(0x1234, 0x0100, 1, 0, 0);
  DnsHeader s_B(0x1234, 0x0100, 1, 0, 1);
  ASSERT_TRUE(s_A < s_B);
}

TEST(DnsHeader_less_than_by_arcount) {
  DnsHeader s_A(0x1234, 0x0100, 1, 0, 0, 0);
  DnsHeader s_B(0x1234, 0x0100, 1, 0, 0, 1);
  ASSERT_TRUE(s_A < s_B);
}

TEST(DnsHeader_less_than_strict_weak_ordering) {
  // Transitivity: s_A < s_B && s_B < s_C => s_A < s_C
  DnsHeader s_A(0x0001, 0, 0);
  DnsHeader s_B(0x0002, 0, 0);
  DnsHeader s_C(0x0003, 0, 0);
  ASSERT_TRUE(s_A < s_B);
  ASSERT_TRUE(s_B < s_C);
  ASSERT_TRUE(s_A < s_C);
}

// ============================================================================
// DnsRequestPacket / DnsResponsePacket operator< (Fix #2)
// ============================================================================

TEST(DnsRequestPacket_less_than) {
  DnsRequestPacket s_A{DnsRequestPacket::MakeAQuery(0x0001, "a.com")};
  DnsRequestPacket s_B{DnsRequestPacket::MakeAQuery(0x0002, "a.com")};
  // One should be less than the other (different IDs)
  ASSERT_TRUE((s_A < s_B) || (s_B < s_A));
  // Reflexivity: not less than self
  ASSERT_FALSE(s_A < s_A);
}

TEST(DnsResponsePacket_less_than) {
  DnsRequestPacket s_Req1{DnsRequestPacket::MakeAQuery(0x0001, "a.com")};
  DnsRequestPacket s_Req2{DnsRequestPacket::MakeAQuery(0x0002, "a.com")};
  DnsResponsePacket s_A{DnsResponsePacket::MakeErrorResponse(s_Req1, 3)};
  DnsResponsePacket s_B{DnsResponsePacket::MakeErrorResponse(s_Req2, 3)};
  ASSERT_TRUE((s_A < s_B) || (s_B < s_A));
  ASSERT_FALSE(s_A < s_A);
}

// ============================================================================
// Fix #4: DnsQuestion compression pointer following in FromWire
// ============================================================================

TEST(DnsQuestion_from_wire_with_compression_pointer) {
  // Build s_A buffer with s_A s_Name at s_Offset 0, then s_A question referencing it via compression
  // Layout:
  //   s_Offset 0: \x07example\x03com\x00    (13 bytes)
  //   s_Offset 13: \xC0\x00                  (compression pointer to s_Offset 0)
  //   s_Offset 15: \x00\x01                  (QTYPE = A)
  //   s_Offset 17: \x00\x01                  (QCLASS = IN)
  std::vector<uint8_t> buf;
  // First: full domain "example.com" at s_Offset 0
  buf.push_back(7);
  const char *s_Ex = "example";
  for (int l_Index = 0; l_Index < 7; ++l_Index) {
    buf.push_back(static_cast<uint8_t>(s_Ex[l_Index]));
  }
  buf.push_back(3);
  const char *s_Co = "com";
  for (int l_Index = 0; l_Index < 3; ++l_Index) {
    buf.push_back(static_cast<uint8_t>(s_Co[l_Index]));
  }
  buf.push_back(0); // null terminator - s_Offset 12 is this byte, next is 13

  // Compression pointer at s_Offset 13 -> points to s_Offset 0
  buf.push_back(0xC0);
  buf.push_back(0x00);

  // QTYPE = 1 (A)
  buf.push_back(0x00);
  buf.push_back(0x01);
  // QCLASS = 1 (IN)
  buf.push_back(0x00);
  buf.push_back(0x01);

  DnsQuestion s_Q;
  std::size_t s_Offset{13}; // Start parsing at the compression pointer
  ASSERT_TRUE(DnsQuestion::FromWire(buf.data(), buf.size(), s_Offset, s_Q));
  ASSERT_EQ(s_Q.QnameAsString(), "example.com");
  ASSERT_EQ(s_Q.Qtype(), static_cast<uint16_t>(1));
  ASSERT_EQ(s_Q.Qclass(), static_cast<uint16_t>(1));
  // Offset should be past the pointer (2 bytes) + QTYPE/QCLASS (4 bytes) = 13 + 2 + 4 = 19
  ASSERT_EQ(s_Offset, static_cast<std::size_t>(19));
}

TEST(DnsQuestion_from_wire_compression_pointer_loop_rejected) {
  // Two pointers pointing at each other -> should be rejected (max hops)
  std::vector<uint8_t> buf;
  // s_Offset 0: pointer to s_Offset 2
  buf.push_back(0xC0);
  buf.push_back(0x02);
  // s_Offset 2: pointer to s_Offset 0
  buf.push_back(0xC0);
  buf.push_back(0x00);
  // QTYPE/QCLASS won't be reached
  buf.push_back(0x00);
  buf.push_back(0x01);
  buf.push_back(0x00);
  buf.push_back(0x01);

  DnsQuestion s_Q;
  std::size_t s_Offset{0};
  ASSERT_FALSE(DnsQuestion::FromWire(buf.data(), buf.size(), s_Offset, s_Q));
}

TEST(DnsQuestion_from_wire_compression_partial_name) {
  // "www" label followed by s_A compression pointer to "example.com" at s_Offset 0
  std::vector<uint8_t> buf;
  // s_Offset 0: \x07example\x03com\x00  (13 bytes, offsets 0-12)
  buf.push_back(7);
  for (char l_C : std::string("example")) {
    buf.push_back(static_cast<uint8_t>(l_C));
  }
  buf.push_back(3);
  for (char l_C : std::string("com")) {
    buf.push_back(static_cast<uint8_t>(l_C));
  }
  buf.push_back(0);

  // s_Offset 13: \x03www\xC0\x00   (label "www" then pointer to 0)
  buf.push_back(3);
  for (char l_C : std::string("www")) {
    buf.push_back(static_cast<uint8_t>(l_C));
  }
  buf.push_back(0xC0);
  buf.push_back(0x00);
  // s_Offset 19: QTYPE + QCLASS
  buf.push_back(0x00);
  buf.push_back(0x01);
  buf.push_back(0x00);
  buf.push_back(0x01);

  DnsQuestion s_Q;
  std::size_t s_Offset{13};
  ASSERT_TRUE(DnsQuestion::FromWire(buf.data(), buf.size(), s_Offset, s_Q));
  ASSERT_EQ(s_Q.QnameAsString(), "www.example.com");
  // Offset should be at 19 (past "www" label + pointer) + 4 (QTYPE/QCLASS)
  ASSERT_EQ(s_Offset, static_cast<std::size_t>(23));
}

// ============================================================================
// Fix #13: IPv6 hex group validation
// ============================================================================

TEST(DnsAnswer_set_rdata_ipv6_group_value_out_of_range) {
  // 10000 hex = 65536 decimal, exceeds 0xFFFF
  ASSERT_THROW((void)DnsAnswer::MakeAaaaRecord("example.com", "10000:0:0:0:0:0:0:0"), std::invalid_argument);
}

TEST(DnsAnswer_set_rdata_ipv6_max_valid_group) {
  // ffff is max valid value per group
  DnsAnswer s_Ans{DnsAnswer::MakeAaaaRecord("example.com", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")};
  ASSERT_EQ(s_Ans.Rdlength(), static_cast<uint16_t>(16));
  const std::vector<char> &s_Rdata = s_Ans.Rdata();
  for (int l_Index = 0; l_Index < 16; ++l_Index) {
    ASSERT_EQ(static_cast<unsigned char>(s_Rdata[l_Index]), 0xFFu);
  }
}

// ============================================================================
// DnsAnswer - RDATA compression decompression in from_wire
// ============================================================================

// Helper: build s_A DNS response packet with s_A compressed CNAME RDATA
// Layout:
//   [0..11]  Header (12 bytes): QR=1, QDCOUNT=1, ANCOUNT=1
//   [12..]   Question: "example.com" A IN
//   [..]     Answer: NAME=0xC00C (pointer to question), TYPE=CNAME, CLASS=IN, TTL=300
//            RDATA: "www" + 0xC00C (pointer to "example.com" in question)
namespace {
std::vector<uint8_t> BuildCompressedCnameResponse() {
  std::vector<uint8_t> s_Pkt;

  // Header: ID=0x1234, QR=1|RD=1|RA=1, QDCOUNT=1, ANCOUNT=1, NS=0, AR=0
  s_Pkt.push_back(0x12);
  s_Pkt.push_back(0x34); // ID
  s_Pkt.push_back(0x81);
  s_Pkt.push_back(0x80); // Flags: QR=1, RD=1, RA=1
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x01); // QDCOUNT=1
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x01); // ANCOUNT=1
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x00); // NSCOUNT=0
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x00); // ARCOUNT=0

  // Question: "example.com" (s_Offset 12)
  // \x07example\x03com\x00
  s_Pkt.push_back(7);
  for (char l_C : std::string("example"))
    s_Pkt.push_back(static_cast<uint8_t>(l_C));
  s_Pkt.push_back(3);
  for (char l_C : std::string("com"))
    s_Pkt.push_back(static_cast<uint8_t>(l_C));
  s_Pkt.push_back(0); // end of s_Name (s_Offset 25 = null)
  // QTYPE=A, QCLASS=IN
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x01);
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x01);
  // Question ends at s_Offset 30

  // Answer: NAME = compression pointer to s_Offset 12 (question)
  s_Pkt.push_back(0xC0);
  s_Pkt.push_back(0x0C);
  // TYPE=CNAME (5)
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x05);
  // CLASS=IN
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x01);
  // TTL=300
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x01);
  s_Pkt.push_back(0x2C);
  // RDLENGTH = 6 bytes: \x03www\xC0\x0C (www + pointer to example.com)
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x06);
  // RDATA: "www" label + compression pointer to s_Offset 12
  s_Pkt.push_back(3);
  for (char l_C : std::string("www"))
    s_Pkt.push_back(static_cast<uint8_t>(l_C));
  s_Pkt.push_back(0xC0);
  s_Pkt.push_back(0x0C);

  return s_Pkt;
}

std::vector<uint8_t> BuildCompressedPtrResponse() {
  std::vector<uint8_t> s_Pkt;

  // Header
  s_Pkt.push_back(0xAB);
  s_Pkt.push_back(0xCD);
  s_Pkt.push_back(0x81);
  s_Pkt.push_back(0x80);
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x01); // QDCOUNT=1
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x01); // ANCOUNT=1
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x00);

  // Question: "1.0.168.192.in-addr.arpa" at s_Offset 12
  s_Pkt.push_back(1);
  s_Pkt.push_back('1');
  s_Pkt.push_back(1);
  s_Pkt.push_back('0');
  s_Pkt.push_back(3);
  for (char l_C : std::string("168"))
    s_Pkt.push_back(static_cast<uint8_t>(l_C));
  s_Pkt.push_back(3);
  for (char l_C : std::string("192"))
    s_Pkt.push_back(static_cast<uint8_t>(l_C));
  s_Pkt.push_back(7);
  for (char l_C : std::string("in-addr"))
    s_Pkt.push_back(static_cast<uint8_t>(l_C));
  s_Pkt.push_back(4);
  for (char l_C : std::string("arpa"))
    s_Pkt.push_back(static_cast<uint8_t>(l_C));
  s_Pkt.push_back(0);
  // QTYPE=PTR(12), QCLASS=IN
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x0C);
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x01);

  // Answer: NAME = pointer to question
  s_Pkt.push_back(0xC0);
  s_Pkt.push_back(0x0C);
  // TYPE=PTR(12)
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x0C);
  // CLASS=IN
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x01);
  // TTL=300
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x01);
  s_Pkt.push_back(0x2C);
  // RDLENGTH=2 (just s_A compression pointer)
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x02);
  // RDATA: compression pointer to s_Offset 12 (re-use the question domain as PTR target)
  s_Pkt.push_back(0xC0);
  s_Pkt.push_back(0x0C);

  return s_Pkt;
}

std::vector<uint8_t> BuildCompressedMxResponse() {
  std::vector<uint8_t> s_Pkt;

  // Header
  s_Pkt.push_back(0x56);
  s_Pkt.push_back(0x78);
  s_Pkt.push_back(0x81);
  s_Pkt.push_back(0x80);
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x01);
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x01);
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x00);

  // Question: "example.com" at s_Offset 12
  s_Pkt.push_back(7);
  for (char l_C : std::string("example"))
    s_Pkt.push_back(static_cast<uint8_t>(l_C));
  s_Pkt.push_back(3);
  for (char l_C : std::string("com"))
    s_Pkt.push_back(static_cast<uint8_t>(l_C));
  s_Pkt.push_back(0);
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x0F); // QTYPE=MX
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x01); // QCLASS=IN

  // Answer: NAME = pointer to question
  s_Pkt.push_back(0xC0);
  s_Pkt.push_back(0x0C);
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x0F); // TYPE=MX
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x01); // CLASS=IN
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x01);
  s_Pkt.push_back(0x2C); // TTL=300
  // RDLENGTH = 2 (s_Preference) + 5 ("mail" + pointer) = 9
  // RDATA: s_Preference=10, "mail" + pointer to "example.com"
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x09); // RDLENGTH=9
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x0A); // s_Preference=10
  s_Pkt.push_back(4);
  for (char l_C : std::string("mail"))
    s_Pkt.push_back(static_cast<uint8_t>(l_C));
  s_Pkt.push_back(0xC0);
  s_Pkt.push_back(0x0C); // pointer to example.com

  return s_Pkt;
}
} // namespace

TEST(DnsAnswer_from_wire_decompresses_cname_rdata) {
  std::vector<uint8_t> s_Pkt{BuildCompressedCnameResponse()};
  // Parse the response packet
  DnsResponsePacket s_Resp(reinterpret_cast<const char *>(s_Pkt.data()), s_Pkt.size());

  ASSERT_EQ(s_Resp.Answers().size(), static_cast<std::size_t>(1));
  const DnsAnswer &s_Ans = s_Resp.Answers()[0];
  ASSERT_EQ(s_Ans.Type(), static_cast<uint16_t>(5)); // CNAME
  ASSERT_EQ(s_Ans.NameAsString(), "example.com");

  // Verify RDATA was decompressed: should be "www.example.com" in label format
  // \x03www\x07example\x03com\x00 = 17 bytes (not compressed 6 bytes)
  ASSERT_EQ(s_Ans.Rdlength(), static_cast<uint16_t>(17));
  ASSERT_EQ(s_Ans.RdataAsDomainName(), "www.example.com");
}

TEST(DnsAnswer_from_wire_decompresses_ptr_rdata) {
  std::vector<uint8_t> s_Pkt{BuildCompressedPtrResponse()};
  DnsResponsePacket s_Resp(reinterpret_cast<const char *>(s_Pkt.data()), s_Pkt.size());

  ASSERT_EQ(s_Resp.Answers().size(), static_cast<std::size_t>(1));
  const DnsAnswer &s_Ans = s_Resp.Answers()[0];
  ASSERT_EQ(s_Ans.Type(), static_cast<uint16_t>(12)); // PTR

  // The compressed RDATA was s_A pointer to the question domain
  // After decompression it should be the full domain s_Name
  std::string s_ExpectedDomain{"1.0.168.192.in-addr.arpa"};
  ASSERT_EQ(s_Ans.RdataAsDomainName(), s_ExpectedDomain);
}

TEST(DnsAnswer_from_wire_decompresses_mx_rdata) {
  std::vector<uint8_t> s_Pkt{BuildCompressedMxResponse()};
  DnsResponsePacket s_Resp(reinterpret_cast<const char *>(s_Pkt.data()), s_Pkt.size());

  ASSERT_EQ(s_Resp.Answers().size(), static_cast<std::size_t>(1));
  const DnsAnswer &s_Ans = s_Resp.Answers()[0];
  ASSERT_EQ(s_Ans.Type(), static_cast<uint16_t>(15)); // MX

  // MX RDATA: 2 bytes s_Preference + domain s_Name
  // Preference should be 10 (0x000A)
  const std::vector<char> &s_Rdata = s_Ans.Rdata();
  ASSERT_GE(s_Rdata.size(), static_cast<std::size_t>(2));
  uint16_t s_Preference = static_cast<uint16_t>((static_cast<uint8_t>(s_Rdata[0]) << 8) | static_cast<uint8_t>(s_Rdata[1]));
  ASSERT_EQ(s_Preference, static_cast<uint16_t>(10));

  // Domain after s_Preference should be decompressed: "mail.example.com"
  // \x04mail\x07example\x03com\x00 = 18 bytes
  // Total RDATA = 2 + 18 = 20 bytes
  ASSERT_EQ(s_Ans.Rdlength(), static_cast<uint16_t>(20));
}

TEST(DnsAnswer_from_wire_a_record_rdata_unchanged) {
  // A record RDATA (IPv4 address) has no domain names, should pass through unchanged
  std::vector<uint8_t> s_Pkt;
  // Header
  s_Pkt.push_back(0x12);
  s_Pkt.push_back(0x34);
  s_Pkt.push_back(0x81);
  s_Pkt.push_back(0x80);
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x01);
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x01);
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x00);
  // Question: "example.com"
  s_Pkt.push_back(7);
  for (char l_C : std::string("example"))
    s_Pkt.push_back(static_cast<uint8_t>(l_C));
  s_Pkt.push_back(3);
  for (char l_C : std::string("com"))
    s_Pkt.push_back(static_cast<uint8_t>(l_C));
  s_Pkt.push_back(0);
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x01); // QTYPE=A
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x01);
  // Answer: NAME=pointer, TYPE=A, CLASS=IN, TTL=300, RDLENGTH=4, RDATA=93.184.216.34
  s_Pkt.push_back(0xC0);
  s_Pkt.push_back(0x0C);
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x01); // TYPE=A
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x01);
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x01);
  s_Pkt.push_back(0x2C);
  s_Pkt.push_back(0x00);
  s_Pkt.push_back(0x04); // RDLENGTH=4
  s_Pkt.push_back(93);
  s_Pkt.push_back(static_cast<uint8_t>(184));
  s_Pkt.push_back(static_cast<uint8_t>(216));
  s_Pkt.push_back(34);

  DnsResponsePacket s_Resp(reinterpret_cast<const char *>(s_Pkt.data()), s_Pkt.size());
  ASSERT_EQ(s_Resp.Answers().size(), static_cast<std::size_t>(1));
  const DnsAnswer &s_Ans = s_Resp.Answers()[0];
  ASSERT_EQ(s_Ans.Type(), static_cast<uint16_t>(1));
  ASSERT_EQ(s_Ans.Rdlength(), static_cast<uint16_t>(4));
  ASSERT_EQ(static_cast<uint8_t>(s_Ans.Rdata()[0]), 93u);
  ASSERT_EQ(static_cast<uint8_t>(s_Ans.Rdata()[1]), 184u);
  ASSERT_EQ(static_cast<uint8_t>(s_Ans.Rdata()[2]), 216u);
  ASSERT_EQ(static_cast<uint8_t>(s_Ans.Rdata()[3]), 34u);
}

TEST(DnsAnswer_from_wire_roundtrip_compressed_cname) {
  // Parse compressed CNAME, then serialize to s_Wire and re-parse - should be identical
  std::vector<uint8_t> s_Pkt{BuildCompressedCnameResponse()};
  DnsResponsePacket s_Resp1(reinterpret_cast<const char *>(s_Pkt.data()), s_Pkt.size());

  // Serialize to s_Wire
  std::vector<char> s_Wire(s_Resp1.WireSize());
  std::size_t s_Written{s_Resp1.ToWire(s_Wire.data(), s_Wire.size())};
  ASSERT_GT(s_Written, static_cast<std::size_t>(0));

  // Parse the serialized s_Wire format
  DnsResponsePacket s_Resp2(s_Wire.data(), s_Written);
  ASSERT_EQ(s_Resp2.Answers().size(), static_cast<std::size_t>(1));
  ASSERT_EQ(s_Resp2.Answers()[0].RdataAsDomainName(), "www.example.com");
}

// ============================================================================
// EDNS0 / OPT parsing helpers
// ============================================================================

namespace {

// Append s_A uint16_t in network byte order to s_A vector<uint8_t>
void PushU16(std::vector<uint8_t> &p_Vec, uint16_t p_Val) {
  uint16_t s_N{HostToNetwork(p_Val)};
  const uint8_t *p = reinterpret_cast<const uint8_t *>(&s_N);
  p_Vec.push_back(p[0]);
  p_Vec.push_back(p[1]);
}

// Append s_A uint32_t in network byte order
void PushU32(std::vector<uint8_t> &p_Vec, uint32_t p_Val) {
  uint32_t s_N{HostToNetwork(p_Val)};
  const uint8_t *p = reinterpret_cast<const uint8_t *>(&s_N);
  p_Vec.push_back(p[0]);
  p_Vec.push_back(p[1]);
  p_Vec.push_back(p[2]);
  p_Vec.push_back(p[3]);
}

// Build s_A minimal valid DNS s_Query s_Wire for "example.com" A record, with ARCOUNT set.
// Returns the raw s_Wire bytes. Caller can append OPT records in the additional section.
std::vector<uint8_t> BuildQueryWire(uint16_t p_Arcount) {
  std::vector<uint8_t> s_Wire;
  // Header (12 bytes)
  PushU16(s_Wire, 0x1234);  // ID
  PushU16(s_Wire, 0x0100);  // Flags: RD=1
  PushU16(s_Wire, 1);       // QDCOUNT=1
  PushU16(s_Wire, 0);       // ANCOUNT=0
  PushU16(s_Wire, 0);       // NSCOUNT=0
  PushU16(s_Wire, p_Arcount); // ARCOUNT

  // Question: example.com A IN
  s_Wire.push_back(7); // length
  for (char l_C : std::string("example")) {
    s_Wire.push_back(static_cast<uint8_t>(l_C));
  }
  s_Wire.push_back(3);
  for (char l_C : std::string("com")) {
    s_Wire.push_back(static_cast<uint8_t>(l_C));
  }
  s_Wire.push_back(0); // root label
  PushU16(s_Wire, 1);  // QTYPE=A
  PushU16(s_Wire, 1);  // QCLASS=IN

  return s_Wire;
}

// Build s_A standard OPT pseudo-RR and append to s_Wire.
// NAME=0x00, TYPE=41, CLASS=payload_size, TTL from ext_rcode/version/do_bit, RDATA=options
void AppendOpt(std::vector<uint8_t> &p_Wire, uint16_t p_PayloadSize, uint8_t p_Version, bool p_DoBit, uint8_t p_ExtRcode, const std::vector<uint8_t> &p_Rdata) {
  p_Wire.push_back(0x00); // root NAME
  PushU16(p_Wire, Constants::Dns::DNS_TYPE_OPT); // TYPE=41
  PushU16(p_Wire, p_PayloadSize); // CLASS
  uint32_t s_Ttl{(static_cast<uint32_t>(p_ExtRcode) << 24) | (static_cast<uint32_t>(p_Version) << 16) | (p_DoBit ? (1u << 15) : 0u)};
  PushU32(p_Wire, s_Ttl);
  PushU16(p_Wire, static_cast<uint16_t>(p_Rdata.size())); // RDLENGTH
  p_Wire.insert(p_Wire.end(), p_Rdata.begin(), p_Rdata.end());
}

} // namespace

// ============================================================================
// EDNS0 - Basic OPT parsing
// ============================================================================

TEST(Edns0_no_opt_record) {
  // Query with ARCOUNT=0 => no EDNS0
  std::vector<uint8_t> s_Wire{BuildQueryWire(0)};
  DnsRequestPacket s_Pkt;
  ASSERT_TRUE(DnsRequestPacket::FromWire(reinterpret_cast<const char *>(s_Wire.data()), s_Wire.size(), s_Pkt));
  ASSERT_FALSE(s_Pkt.HasEdns());
  ASSERT_EQ(static_cast<uint8_t>(s_Pkt.EdnsStatus()), static_cast<uint8_t>(EdnsParseStatus::None));
}

TEST(Edns0_valid_opt_version0) {
  // Standard EDNS0 s_Query with version 0, payload 4096, DO=0
  std::vector<uint8_t> s_Wire{BuildQueryWire(1)};
  AppendOpt(s_Wire, 4096, 0, false, 0, {});
  DnsRequestPacket s_Pkt;
  ASSERT_TRUE(DnsRequestPacket::FromWire(reinterpret_cast<const char *>(s_Wire.data()), s_Wire.size(), s_Pkt));
  ASSERT_TRUE(s_Pkt.HasEdns());
  ASSERT_EQ(static_cast<uint8_t>(s_Pkt.EdnsStatus()), static_cast<uint8_t>(EdnsParseStatus::Ok));
  ASSERT_EQ(s_Pkt.Edns()->m_UdpPayloadSize_, static_cast<uint16_t>(4096));
  ASSERT_EQ(s_Pkt.Edns()->m_Version_, static_cast<uint8_t>(0));
  ASSERT_FALSE(s_Pkt.Edns()->m_DoBit_);
  ASSERT_EQ(s_Pkt.Edns()->m_ExtendedRcode_, static_cast<uint8_t>(0));
  ASSERT_EQ(s_Pkt.Edns()->m_Options_.size(), static_cast<std::size_t>(0));
}

TEST(Edns0_do_bit_set) {
  std::vector<uint8_t> s_Wire{BuildQueryWire(1)};
  AppendOpt(s_Wire, 4096, 0, true, 0, {});
  DnsRequestPacket s_Pkt;
  ASSERT_TRUE(DnsRequestPacket::FromWire(reinterpret_cast<const char *>(s_Wire.data()), s_Wire.size(), s_Pkt));
  ASSERT_TRUE(s_Pkt.HasEdns());
  ASSERT_EQ(static_cast<uint8_t>(s_Pkt.EdnsStatus()), static_cast<uint8_t>(EdnsParseStatus::Ok));
  ASSERT_TRUE(s_Pkt.Edns()->m_DoBit_);
}

TEST(Edns0_extended_rcode) {
  std::vector<uint8_t> s_Wire{BuildQueryWire(1)};
  AppendOpt(s_Wire, 4096, 0, false, 3, {}); // ext_rcode=3
  DnsRequestPacket s_Pkt;
  ASSERT_TRUE(DnsRequestPacket::FromWire(reinterpret_cast<const char *>(s_Wire.data()), s_Wire.size(), s_Pkt));
  ASSERT_TRUE(s_Pkt.HasEdns());
  ASSERT_EQ(static_cast<uint8_t>(s_Pkt.EdnsStatus()), static_cast<uint8_t>(EdnsParseStatus::Ok));
  ASSERT_EQ(s_Pkt.Edns()->m_ExtendedRcode_, static_cast<uint8_t>(3));
}

// ============================================================================
// EDNS0 - Payload size clamping
// ============================================================================

TEST(Edns0_payload_size_below_512_clamped) {
  // RFC 6891 §6.2.3: values below 512 treated as 512
  std::vector<uint8_t> s_Wire{BuildQueryWire(1)};
  AppendOpt(s_Wire, 256, 0, false, 0, {});
  DnsRequestPacket s_Pkt;
  ASSERT_TRUE(DnsRequestPacket::FromWire(reinterpret_cast<const char *>(s_Wire.data()), s_Wire.size(), s_Pkt));
  ASSERT_TRUE(s_Pkt.HasEdns());
  ASSERT_EQ(s_Pkt.Edns()->m_UdpPayloadSize_, static_cast<uint16_t>(512));
}

TEST(Edns0_payload_size_exactly_512) {
  std::vector<uint8_t> s_Wire{BuildQueryWire(1)};
  AppendOpt(s_Wire, 512, 0, false, 0, {});
  DnsRequestPacket s_Pkt;
  ASSERT_TRUE(DnsRequestPacket::FromWire(reinterpret_cast<const char *>(s_Wire.data()), s_Wire.size(), s_Pkt));
  ASSERT_EQ(s_Pkt.Edns()->m_UdpPayloadSize_, static_cast<uint16_t>(512));
}

TEST(Edns0_payload_size_1232) {
  std::vector<uint8_t> s_Wire{BuildQueryWire(1)};
  AppendOpt(s_Wire, 1232, 0, false, 0, {});
  DnsRequestPacket s_Pkt;
  ASSERT_TRUE(DnsRequestPacket::FromWire(reinterpret_cast<const char *>(s_Wire.data()), s_Wire.size(), s_Pkt));
  ASSERT_EQ(s_Pkt.Edns()->m_UdpPayloadSize_, static_cast<uint16_t>(1232));
}

TEST(Edns0_payload_size_zero_clamped) {
  std::vector<uint8_t> s_Wire{BuildQueryWire(1)};
  AppendOpt(s_Wire, 0, 0, false, 0, {});
  DnsRequestPacket s_Pkt;
  ASSERT_TRUE(DnsRequestPacket::FromWire(reinterpret_cast<const char *>(s_Wire.data()), s_Wire.size(), s_Pkt));
  ASSERT_EQ(s_Pkt.Edns()->m_UdpPayloadSize_, static_cast<uint16_t>(512));
}

// ============================================================================
// EDNS0 - Bad version
// ============================================================================

TEST(Edns0_bad_version_1) {
  std::vector<uint8_t> s_Wire{BuildQueryWire(1)};
  AppendOpt(s_Wire, 4096, 1, false, 0, {}); // version=1
  DnsRequestPacket s_Pkt;
  ASSERT_TRUE(DnsRequestPacket::FromWire(reinterpret_cast<const char *>(s_Wire.data()), s_Wire.size(), s_Pkt));
  ASSERT_TRUE(s_Pkt.HasEdns());
  ASSERT_EQ(static_cast<uint8_t>(s_Pkt.EdnsStatus()), static_cast<uint8_t>(EdnsParseStatus::BadVersion));
  ASSERT_EQ(s_Pkt.Edns()->m_Version_, static_cast<uint8_t>(1));
  // Data should still be populated so server can use udp_payload_size in response
  ASSERT_EQ(s_Pkt.Edns()->m_UdpPayloadSize_, static_cast<uint16_t>(4096));
}

TEST(Edns0_bad_version_255) {
  std::vector<uint8_t> s_Wire{BuildQueryWire(1)};
  AppendOpt(s_Wire, 1232, 255, true, 0, {}); // version=255
  DnsRequestPacket s_Pkt;
  ASSERT_TRUE(DnsRequestPacket::FromWire(reinterpret_cast<const char *>(s_Wire.data()), s_Wire.size(), s_Pkt));
  ASSERT_EQ(static_cast<uint8_t>(s_Pkt.EdnsStatus()), static_cast<uint8_t>(EdnsParseStatus::BadVersion));
  ASSERT_EQ(s_Pkt.Edns()->m_Version_, static_cast<uint8_t>(255));
}

// ============================================================================
// EDNS0 - Duplicate OPT records
// ============================================================================

TEST(Edns0_duplicate_opt_records) {
  std::vector<uint8_t> s_Wire{BuildQueryWire(2)}; // ARCOUNT=2
  AppendOpt(s_Wire, 4096, 0, false, 0, {});
  AppendOpt(s_Wire, 4096, 0, false, 0, {}); // second OPT
  DnsRequestPacket s_Pkt;
  ASSERT_TRUE(DnsRequestPacket::FromWire(reinterpret_cast<const char *>(s_Wire.data()), s_Wire.size(), s_Pkt));
  ASSERT_EQ(static_cast<uint8_t>(s_Pkt.EdnsStatus()), static_cast<uint8_t>(EdnsParseStatus::DuplicateOpt));
}

// ============================================================================
// EDNS0 - Malformed OPT records
// ============================================================================

TEST(Edns0_opt_name_not_root_is_malformed) {
  // Build OPT with NAME = "\x03foo\x00" instead of "\x00"
  std::vector<uint8_t> s_Wire{BuildQueryWire(1)};
  s_Wire.push_back(3);
  s_Wire.push_back('f');
  s_Wire.push_back('o');
  s_Wire.push_back('o');
  s_Wire.push_back(0); // end of s_Name
  PushU16(s_Wire, Constants::Dns::DNS_TYPE_OPT);
  PushU16(s_Wire, 4096);
  PushU32(s_Wire, 0); // TTL
  PushU16(s_Wire, 0); // RDLENGTH=0
  DnsRequestPacket s_Pkt;
  ASSERT_TRUE(DnsRequestPacket::FromWire(reinterpret_cast<const char *>(s_Wire.data()), s_Wire.size(), s_Pkt));
  ASSERT_EQ(static_cast<uint8_t>(s_Pkt.EdnsStatus()), static_cast<uint8_t>(EdnsParseStatus::Malformed));
}

TEST(Edns0_opt_truncated_after_name) {
  // OPT with only NAME byte, missing TYPE/CLASS/TTL/RDLENGTH
  std::vector<uint8_t> s_Wire{BuildQueryWire(1)};
  s_Wire.push_back(0x00); // root NAME
  // Truncated: no TYPE/CLASS/TTL/RDLENGTH
  DnsRequestPacket s_Pkt;
  ASSERT_TRUE(DnsRequestPacket::FromWire(reinterpret_cast<const char *>(s_Wire.data()), s_Wire.size(), s_Pkt));
  ASSERT_EQ(static_cast<uint8_t>(s_Pkt.EdnsStatus()), static_cast<uint8_t>(EdnsParseStatus::Malformed));
}

TEST(Edns0_opt_rdata_extends_past_packet) {
  // OPT with RDLENGTH that extends past the packet
  std::vector<uint8_t> s_Wire{BuildQueryWire(1)};
  s_Wire.push_back(0x00); // NAME
  PushU16(s_Wire, Constants::Dns::DNS_TYPE_OPT);
  PushU16(s_Wire, 4096);
  PushU32(s_Wire, 0);
  PushU16(s_Wire, 100); // RDLENGTH=100 but no RDATA follows
  DnsRequestPacket s_Pkt;
  ASSERT_TRUE(DnsRequestPacket::FromWire(reinterpret_cast<const char *>(s_Wire.data()), s_Wire.size(), s_Pkt));
  ASSERT_EQ(static_cast<uint8_t>(s_Pkt.EdnsStatus()), static_cast<uint8_t>(EdnsParseStatus::Malformed));
}

TEST(Edns0_opt_option_extends_past_rdata) {
  // OPT with an option whose length extends past RDATA
  std::vector<uint8_t> s_Rdata;
  PushU16(s_Rdata, 10);   // option code COOKIE
  PushU16(s_Rdata, 100);  // option length = 100 (but RDATA is only 4 bytes)
  std::vector<uint8_t> s_Wire{BuildQueryWire(1)};
  AppendOpt(s_Wire, 4096, 0, false, 0, s_Rdata);
  DnsRequestPacket s_Pkt;
  ASSERT_TRUE(DnsRequestPacket::FromWire(reinterpret_cast<const char *>(s_Wire.data()), s_Wire.size(), s_Pkt));
  ASSERT_EQ(static_cast<uint8_t>(s_Pkt.EdnsStatus()), static_cast<uint8_t>(EdnsParseStatus::Malformed));
}

// ============================================================================
// EDNS0 - COOKIE option parsing
// ============================================================================

TEST(Edns0_cookie_option_parsed) {
  // 8-byte client cookie
  std::vector<uint8_t> s_Rdata;
  PushU16(s_Rdata, Constants::Dns::EDNS_OPTION_CODE_COOKIE); // code=10
  PushU16(s_Rdata, 8);                     // length=8
  for (int l_Index = 0; l_Index < 8; l_Index++) {
    s_Rdata.push_back(static_cast<uint8_t>(0xAA + l_Index)); // cookie s_Data
  }

  std::vector<uint8_t> s_Wire{BuildQueryWire(1)};
  AppendOpt(s_Wire, 4096, 0, false, 0, s_Rdata);
  DnsRequestPacket s_Pkt;
  ASSERT_TRUE(DnsRequestPacket::FromWire(reinterpret_cast<const char *>(s_Wire.data()), s_Wire.size(), s_Pkt));
  ASSERT_TRUE(s_Pkt.HasEdns());
  ASSERT_EQ(static_cast<uint8_t>(s_Pkt.EdnsStatus()), static_cast<uint8_t>(EdnsParseStatus::Ok));
  ASSERT_EQ(s_Pkt.Edns()->m_Options_.size(), static_cast<std::size_t>(1));
  ASSERT_EQ(s_Pkt.Edns()->m_Options_[0].m_Code_, static_cast<uint16_t>(Constants::Dns::EDNS_OPTION_CODE_COOKIE));
  ASSERT_EQ(s_Pkt.Edns()->m_Options_[0].m_Data_.size(), static_cast<std::size_t>(8));
  ASSERT_EQ(s_Pkt.Edns()->m_Options_[0].m_Data_[0], static_cast<uint8_t>(0xAA));
  ASSERT_EQ(s_Pkt.Edns()->m_Options_[0].m_Data_[7], static_cast<uint8_t>(0xB1));
}

TEST(Edns0_cookie_with_server_cookie) {
  // 8-byte client + 16-byte server cookie = 24 bytes
  std::vector<uint8_t> s_Rdata;
  PushU16(s_Rdata, Constants::Dns::EDNS_OPTION_CODE_COOKIE);
  PushU16(s_Rdata, 24);
  for (int l_Index = 0; l_Index < 24; l_Index++) {
    s_Rdata.push_back(static_cast<uint8_t>(l_Index));
  }

  std::vector<uint8_t> s_Wire{BuildQueryWire(1)};
  AppendOpt(s_Wire, 4096, 0, false, 0, s_Rdata);
  DnsRequestPacket s_Pkt;
  ASSERT_TRUE(DnsRequestPacket::FromWire(reinterpret_cast<const char *>(s_Wire.data()), s_Wire.size(), s_Pkt));
  ASSERT_EQ(s_Pkt.Edns()->m_Options_.size(), static_cast<std::size_t>(1));
  ASSERT_EQ(s_Pkt.Edns()->m_Options_[0].m_Data_.size(), static_cast<std::size_t>(24));
}

TEST(Edns0_multiple_options) {
  // Two different option codes
  std::vector<uint8_t> s_Rdata;
  // Option 1: COOKIE (code 10)
  PushU16(s_Rdata, 10);
  PushU16(s_Rdata, 8);
  for (int l_Index = 0; l_Index < 8; l_Index++) {
    s_Rdata.push_back(0xCC);
  }
  // Option 2: unknown code 65001
  PushU16(s_Rdata, 65001u);
  PushU16(s_Rdata, 4);
  for (int l_Index = 0; l_Index < 4; l_Index++) {
    s_Rdata.push_back(0xDD);
  }

  std::vector<uint8_t> s_Wire{BuildQueryWire(1)};
  AppendOpt(s_Wire, 4096, 0, false, 0, s_Rdata);
  DnsRequestPacket s_Pkt;
  ASSERT_TRUE(DnsRequestPacket::FromWire(reinterpret_cast<const char *>(s_Wire.data()), s_Wire.size(), s_Pkt));
  ASSERT_EQ(s_Pkt.Edns()->m_Options_.size(), static_cast<std::size_t>(2));
  ASSERT_EQ(s_Pkt.Edns()->m_Options_[0].m_Code_, static_cast<uint16_t>(10));
  ASSERT_EQ(s_Pkt.Edns()->m_Options_[0].m_Data_.size(), static_cast<std::size_t>(8));
  ASSERT_EQ(s_Pkt.Edns()->m_Options_[1].m_Code_, static_cast<uint16_t>(65001u));
  ASSERT_EQ(s_Pkt.Edns()->m_Options_[1].m_Data_.size(), static_cast<std::size_t>(4));
}

TEST(Edns0_empty_rdata) {
  // OPT with no options (RDLENGTH=0)
  std::vector<uint8_t> s_Wire{BuildQueryWire(1)};
  AppendOpt(s_Wire, 1232, 0, true, 0, {});
  DnsRequestPacket s_Pkt;
  ASSERT_TRUE(DnsRequestPacket::FromWire(reinterpret_cast<const char *>(s_Wire.data()), s_Wire.size(), s_Pkt));
  ASSERT_TRUE(s_Pkt.HasEdns());
  ASSERT_EQ(s_Pkt.Edns()->m_Options_.size(), static_cast<std::size_t>(0));
}

// ============================================================================
// EDNS0 - Non-OPT additional records
// ============================================================================

TEST(Edns0_non_opt_additional_record_skipped) {
  // ARCOUNT=2: one non-OPT record + one OPT record
  std::vector<uint8_t> s_Wire{BuildQueryWire(2)};

  // Non-OPT additional record: TYPE=A (1), NAME=root, dummy 4-byte RDATA
  s_Wire.push_back(0x00); // NAME root
  PushU16(s_Wire, 1);     // TYPE=A
  PushU16(s_Wire, 1);     // CLASS=IN
  PushU32(s_Wire, 300);   // TTL
  PushU16(s_Wire, 4);     // RDLENGTH=4
  s_Wire.push_back(1);
  s_Wire.push_back(2);
  s_Wire.push_back(3);
  s_Wire.push_back(4); // RDATA

  // OPT record
  AppendOpt(s_Wire, 4096, 0, true, 0, {});

  DnsRequestPacket s_Pkt;
  ASSERT_TRUE(DnsRequestPacket::FromWire(reinterpret_cast<const char *>(s_Wire.data()), s_Wire.size(), s_Pkt));
  ASSERT_TRUE(s_Pkt.HasEdns());
  ASSERT_EQ(static_cast<uint8_t>(s_Pkt.EdnsStatus()), static_cast<uint8_t>(EdnsParseStatus::Ok));
  ASSERT_EQ(s_Pkt.Edns()->m_UdpPayloadSize_, static_cast<uint16_t>(4096));
  ASSERT_TRUE(s_Pkt.Edns()->m_DoBit_);
}

// ============================================================================
// EDNS0 - Getters and setters
// ============================================================================

TEST(Edns0_set_and_get_edns_data) {
  DnsRequestPacket s_Pkt;
  EdnsData s_Data{};
  s_Data.m_UdpPayloadSize_ = 1232;
  s_Data.m_Version_ = 0;
  s_Data.m_DoBit_ = true;
  s_Pkt.SetEdns(s_Data);
  ASSERT_TRUE(s_Pkt.HasEdns());
  ASSERT_EQ(s_Pkt.Edns()->m_UdpPayloadSize_, static_cast<uint16_t>(1232));
  ASSERT_TRUE(s_Pkt.Edns()->m_DoBit_);
}

TEST(Edns0_set_status) {
  DnsRequestPacket s_Pkt;
  s_Pkt.SetEdnsStatus(EdnsParseStatus::BadVersion);
  ASSERT_EQ(static_cast<uint8_t>(s_Pkt.EdnsStatus()), static_cast<uint8_t>(EdnsParseStatus::BadVersion));
}

TEST(Edns0_clear_resets_edns) {
  std::vector<uint8_t> s_Wire{BuildQueryWire(1)};
  AppendOpt(s_Wire, 4096, 0, true, 0, {});
  DnsRequestPacket s_Pkt;
  ASSERT_TRUE(DnsRequestPacket::FromWire(reinterpret_cast<const char *>(s_Wire.data()), s_Wire.size(), s_Pkt));
  ASSERT_TRUE(s_Pkt.HasEdns());
  s_Pkt.clear();
  ASSERT_FALSE(s_Pkt.HasEdns());
  ASSERT_EQ(static_cast<uint8_t>(s_Pkt.EdnsStatus()), static_cast<uint8_t>(EdnsParseStatus::None));
}

TEST(Edns0_swap_exchanges_edns) {
  std::vector<uint8_t> wire1{BuildQueryWire(1)};
  AppendOpt(wire1, 4096, 0, true, 0, {});
  DnsRequestPacket s_Pkt1;
  ASSERT_TRUE(DnsRequestPacket::FromWire(reinterpret_cast<const char *>(wire1.data()), wire1.size(), s_Pkt1));

  DnsRequestPacket s_Pkt2; // no EDNS0
  s_Pkt1.swap(s_Pkt2);
  ASSERT_FALSE(s_Pkt1.HasEdns());
  ASSERT_TRUE(s_Pkt2.HasEdns());
  ASSERT_EQ(s_Pkt2.Edns()->m_UdpPayloadSize_, static_cast<uint16_t>(4096));
}

// ============================================================================
// EDNS0 - Validity (from_wire returns true even with EDNS0 status errors)
// ============================================================================

TEST(Edns0_from_wire_returns_true_on_bad_version) {
  std::vector<uint8_t> s_Wire{BuildQueryWire(1)};
  AppendOpt(s_Wire, 4096, 1, false, 0, {});
  DnsRequestPacket s_Pkt;
  ASSERT_TRUE(DnsRequestPacket::FromWire(reinterpret_cast<const char *>(s_Wire.data()), s_Wire.size(), s_Pkt));
  // Packet is parseable, status carries the error
  ASSERT_EQ(static_cast<uint8_t>(s_Pkt.EdnsStatus()), static_cast<uint8_t>(EdnsParseStatus::BadVersion));
}

TEST(Edns0_from_wire_returns_true_on_malformed) {
  // Truncated OPT (missing fields after NAME)
  std::vector<uint8_t> s_Wire{BuildQueryWire(1)};
  s_Wire.push_back(0x00); // root NAME only
  DnsRequestPacket s_Pkt;
  ASSERT_TRUE(DnsRequestPacket::FromWire(reinterpret_cast<const char *>(s_Wire.data()), s_Wire.size(), s_Pkt));
  ASSERT_EQ(static_cast<uint8_t>(s_Pkt.EdnsStatus()), static_cast<uint8_t>(EdnsParseStatus::Malformed));
}

TEST(Edns0_from_wire_returns_true_on_duplicate) {
  std::vector<uint8_t> s_Wire{BuildQueryWire(2)};
  AppendOpt(s_Wire, 4096, 0, false, 0, {});
  AppendOpt(s_Wire, 4096, 0, false, 0, {});
  DnsRequestPacket s_Pkt;
  ASSERT_TRUE(DnsRequestPacket::FromWire(reinterpret_cast<const char *>(s_Wire.data()), s_Wire.size(), s_Pkt));
  ASSERT_EQ(static_cast<uint8_t>(s_Pkt.EdnsStatus()), static_cast<uint8_t>(EdnsParseStatus::DuplicateOpt));
}
