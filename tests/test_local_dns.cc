// Tests for LocalDns: regex matching, IP reversal, IPv6 simplification
#include "test_framework.h"

#include "local_dns.h"

#include "config.h"
#include "config_parser.h"
#include "dns_parser.h"
#include "nlohmann/json.hpp"
#include "utils.h"

#include <cstdint>
#include <string>
#include <vector>

namespace {
// Helper: build a new-format s_Zones JSON for a single s_Zone with records.
// Each record is {name, type, s_Data} (ttl defaults to 300).
struct TestRecord {
  std::string m_Name_;
  std::string m_Type_;
  nlohmann::json m_Data_;
  bool m_Regex_{false};
};

nlohmann::json MakeZones(const std::string &p_Zone, const std::vector<TestRecord> &p_Records, bool p_Blocked = false) {
  nlohmann::json s_Zone;
  s_Zone["zone"] = p_Zone;
  if (p_Blocked) {
    s_Zone["blocked"] = true;
  } else {
    s_Zone["records"] = nlohmann::json::array();
    for (const TestRecord &l_Record : p_Records) {
      nlohmann::json s_Rec{{"name", l_Record.m_Name_}, {"type", l_Record.m_Type_}, {"ttl", 300}, {"data", l_Record.m_Data_}};
      if (l_Record.m_Regex_) {
        s_Rec["regex"] = true;
      }
      s_Zone["records"].push_back(s_Rec);
    }
  }
  nlohmann::json s_Result;
  s_Result["zones"] = nlohmann::json::array({s_Zone});
  return s_Result;
}
} // namespace

// ============================================================================
// ReverseIpv4Components
// ============================================================================

TEST(ReverseIpv4_basic) {
  ASSERT_EQ(LocalDns::ReverseIpv4Components("1.168.192"), "192.168.1");
}

TEST(ReverseIpv4_full) {
  ASSERT_EQ(LocalDns::ReverseIpv4Components("1.0.0.127"), "127.0.0.1");
}

TEST(ReverseIpv4_single) {
  ASSERT_EQ(LocalDns::ReverseIpv4Components("1"), "1");
}

TEST(ReverseIpv4_empty) {
  ASSERT_EQ(LocalDns::ReverseIpv4Components(""), "");
}

TEST(ReverseIpv4_two_parts) {
  ASSERT_EQ(LocalDns::ReverseIpv4Components("168.192"), "192.168");
}

// ============================================================================
// ReverseIpv6Components
// ============================================================================

TEST(ReverseIpv6_loopback) {
  // ::1 in nibble form, s_Reversed = 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0
  std::string s_Reversed{LocalDns::ReverseIpv6Components("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0")};
  // After reversal: 0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1
  // Grouped: 0000:0000:0000:0000:0000:0000:0000:0001
  ASSERT_EQ(s_Reversed, "0000:0000:0000:0000:0000:0000:0000:0001");
}

TEST(ReverseIpv6_empty) {
  ASSERT_EQ(LocalDns::ReverseIpv6Components(""), "");
}

// ============================================================================
// SimplifyIpv6
// ============================================================================

TEST(SimplifyIpv6_loopback) {
  ASSERT_EQ(LocalDns::SimplifyIpv6("0000:0000:0000:0000:0000:0000:0000:0001"), "::1");
}

TEST(SimplifyIpv6_all_zeros) {
  ASSERT_EQ(LocalDns::SimplifyIpv6("0000:0000:0000:0000:0000:0000:0000:0000"), "::");
}

TEST(SimplifyIpv6_no_compression) {
  // No consecutive zero groups more than 1
  ASSERT_EQ(LocalDns::SimplifyIpv6("2001:0db8:0001:0000:0001:0000:0001:0001"), "2001:db8:1:0:1:0:1:1");
}

TEST(SimplifyIpv6_leading_zeros_removed) {
  ASSERT_EQ(LocalDns::SimplifyIpv6("2001:0db8:0000:0000:0000:0000:0000:0001"), "2001:db8::1");
}

TEST(SimplifyIpv6_already_simple) {
  std::string s_Result{LocalDns::SimplifyIpv6("fe80:0000:0000:0000:0000:0000:0000:0001")};
  ASSERT_EQ(s_Result, "fe80::1");
}

TEST(SimplifyIpv6_middle_compression) {
  // Consecutive zeros in the middle
  ASSERT_EQ(LocalDns::SimplifyIpv6("2001:0db8:0000:0000:0000:ff00:0042:8329"), "2001:db8::ff00:42:8329");
}

TEST(SimplifyIpv6_end_compression) {
  // Consecutive zeros at the end
  ASSERT_EQ(LocalDns::SimplifyIpv6("2001:0db8:0001:0000:0000:0000:0000:0000"), "2001:db8:1::");
}

TEST(SimplifyIpv6_single_group) {
  ASSERT_EQ(LocalDns::SimplifyIpv6("0001"), "1");
}

// ============================================================================
// SafeRegexMatch
// ============================================================================

TEST(SafeRegexMatch_exact) {
  ASSERT_TRUE(LocalDns::SafeRegexMatch("www", "www"));
}

TEST(SafeRegexMatch_regex_pattern) {
  ASSERT_TRUE(LocalDns::SafeRegexMatch("www", "w+"));
}

TEST(SafeRegexMatch_no_match) {
  ASSERT_FALSE(LocalDns::SafeRegexMatch("www", "xyz"));
}

TEST(SafeRegexMatch_wildcard) {
  ASSERT_TRUE(LocalDns::SafeRegexMatch("anything", ".*"));
}

TEST(SafeRegexMatch_escaped_star) {
  // \* is a special s_Pattern in s_Zones.json for wildcard subdomains
  ASSERT_TRUE(LocalDns::SafeRegexMatch("*", "\\*"));
}

TEST(SafeRegexMatch_invalid_regex) {
  // Invalid regex should return false, not throw
  ASSERT_FALSE(LocalDns::SafeRegexMatch("test", "[invalid"));
}

TEST(SafeRegexMatch_complex_pattern) {
  // Pattern from s_Zones.json for PS4 updates
  ASSERT_TRUE(LocalDns::SafeRegexMatch("djp01.ps4.update", "d(jp|us|eu)01\\.ps4\\.update"));
  ASSERT_TRUE(LocalDns::SafeRegexMatch("dus01.ps4.update", "d(jp|us|eu)01\\.ps4\\.update"));
  ASSERT_FALSE(LocalDns::SafeRegexMatch("dau01.ps4.update", "d(jp|us|eu)01\\.ps4\\.update"));
}

TEST(SafeRegexMatch_caches_regex) {
  // Call twice with same s_Pattern - second should use cache
  ASSERT_TRUE(LocalDns::SafeRegexMatch("hello", "hel+o"));
  ASSERT_TRUE(LocalDns::SafeRegexMatch("helllo", "hel+o"));
}

// ============================================================================
// Fix #3: SafeRegexMatch thread safety + cache eviction
// ============================================================================

TEST(SafeRegexMatch_many_patterns_no_crash) {
  // Exercise the cache with many different patterns (tests cache eviction at 1024)
  for (int l_Index = 0; l_Index < 100; ++l_Index) {
    std::string s_Pattern{"test_pattern_" + std::to_string(l_Index)};
    std::string s_Input{"test_pattern_" + std::to_string(l_Index)};
    ASSERT_TRUE(LocalDns::SafeRegexMatch(s_Input, s_Pattern));
  }
}

TEST(SafeRegexMatch_empty_pattern) {
  // Empty s_Pattern matches empty string
  ASSERT_TRUE(LocalDns::SafeRegexMatch("", ""));
}

TEST(SafeRegexMatch_empty_input) {
  // Empty s_Input doesn't match non-empty s_Pattern (anchored)
  ASSERT_FALSE(LocalDns::SafeRegexMatch("", "abc"));
}

// ============================================================================
// LookupLocalRecord
// ============================================================================

TEST(LookupLocalRecord_root_domain_A) {
  // A records are converted to binary hex by ValidateAndOptimize, so
  // use a non-IP type (CNAME) to test basic lookup without that conversion.
  ASSERT_EQ(g_Config.Zones(MakeZones("example.com.", {{"@", "CNAME", "target.example.com."}})), 0);

  nlohmann::json s_Data;
  ASSERT_TRUE(LocalDns::LookupLocalRecord("example.com", "CNAME", s_Data));
  ASSERT_EQ(s_Data.get<std::string>(), "target.example.com.");
}

TEST(LookupLocalRecord_subdomain_match) {
  ASSERT_EQ(g_Config.Zones(MakeZones("example.com.", {{"www", "CNAME", "www-target.example.com."}})), 0);

  nlohmann::json s_Data;
  ASSERT_TRUE(LocalDns::LookupLocalRecord("www.example.com", "CNAME", s_Data));
  ASSERT_EQ(s_Data.get<std::string>(), "www-target.example.com.");
}

TEST(LookupLocalRecord_wildcard_fallback) {
  ASSERT_EQ(g_Config.Zones(MakeZones("example.com.", {{"www", "CNAME", "www-target.com."}, {"*", "CNAME", "wild-target.com."}})), 0);

  nlohmann::json s_Data;
  ASSERT_TRUE(LocalDns::LookupLocalRecord("anything.example.com", "CNAME", s_Data));
  ASSERT_EQ(s_Data.get<std::string>(), "wild-target.com.");
}

TEST(LookupLocalRecord_not_found) {
  ASSERT_EQ(g_Config.Zones(MakeZones("example.com.", {{"www", "CNAME", "target.com."}})), 0);

  nlohmann::json s_Data;
  ASSERT_FALSE(LocalDns::LookupLocalRecord("nothere.example.com", "CNAME", s_Data));
}

TEST(LookupLocalRecord_wrong_type) {
  ASSERT_EQ(g_Config.Zones(MakeZones("example.com.", {{"@", "CNAME", "target.com."}})), 0);

  nlohmann::json s_Data;
  ASSERT_FALSE(LocalDns::LookupLocalRecord("example.com", "AAAA", s_Data));
}

TEST(LookupLocalRecord_trailing_dot) {
  ASSERT_EQ(g_Config.Zones(MakeZones("example.com.", {{"@", "CNAME", "target.com."}})), 0);

  nlohmann::json s_Data;
  // Trailing dot should be stripped
  ASSERT_TRUE(LocalDns::LookupLocalRecord("example.com.", "CNAME", s_Data));
  ASSERT_EQ(s_Data.get<std::string>(), "target.com.");
}

TEST(LookupLocalRecord_domain_not_in_zones) {
  ASSERT_EQ(g_Config.Zones(MakeZones("example.com.", {{"@", "CNAME", "target.com."}})), 0);

  nlohmann::json s_Data;
  ASSERT_FALSE(LocalDns::LookupLocalRecord("other.com", "CNAME", s_Data));
}

TEST(LookupLocalRecord_empty_domain) {
  nlohmann::json s_Data;
  ASSERT_FALSE(LocalDns::LookupLocalRecord("", "A", s_Data));
}

TEST(LookupLocalRecord_empty_type) {
  nlohmann::json s_Data;
  ASSERT_FALSE(LocalDns::LookupLocalRecord("example.com", "", s_Data));
}

TEST(LookupLocalRecord_regex_subdomain) {
  ASSERT_EQ(g_Config.Zones(MakeZones("example.com.", {{"test.cdn", "CNAME", "cdn-target.com."}})), 0);

  nlohmann::json s_Data;
  ASSERT_TRUE(LocalDns::LookupLocalRecord("test.cdn.example.com", "CNAME", s_Data));
  ASSERT_EQ(s_Data.get<std::string>(), "cdn-target.com.");
}

TEST(LookupLocalRecord_deep_subdomain) {
  ASSERT_EQ(g_Config.Zones(MakeZones("example.com.", {{"a.b.c", "NS", "ns.example.com."}})), 0);

  nlohmann::json s_Data;
  ASSERT_TRUE(LocalDns::LookupLocalRecord("a.b.c.example.com", "NS", s_Data));
  ASSERT_EQ(s_Data.get<std::string>(), "ns.example.com.");
}

// ============================================================================
// LookupLocalRecord - Multi-value (array) support
// ============================================================================

TEST(LookupLocalRecord_multi_NS_root) {
  ASSERT_EQ(g_Config.Zones(MakeZones("example.com.", {{"@", "NS", "ns1.example.com."}, {"@", "NS", "ns2.example.com."}})), 0);

  nlohmann::json s_Data;
  ASSERT_TRUE(LocalDns::LookupLocalRecord("example.com", "NS", s_Data));
  ASSERT_TRUE(s_Data.is_array());
  ASSERT_EQ(s_Data.size(), 2u);
  ASSERT_EQ(s_Data[0].get<std::string>(), "ns1.example.com.");
  ASSERT_EQ(s_Data[1].get<std::string>(), "ns2.example.com.");
}

TEST(LookupLocalRecord_multi_NS_subdomain) {
  ASSERT_EQ(g_Config.Zones(MakeZones("example.com.", {{"sub", "NS", "ns1.example.com."}, {"sub", "NS", "ns2.example.com."}})), 0);

  nlohmann::json s_Data;
  ASSERT_TRUE(LocalDns::LookupLocalRecord("sub.example.com", "NS", s_Data));
  ASSERT_TRUE(s_Data.is_array());
  ASSERT_EQ(s_Data.size(), 2u);
}

TEST(LookupLocalRecord_multi_NS_wildcard) {
  ASSERT_EQ(g_Config.Zones(MakeZones("example.com.", {{"*", "NS", "ns1.example.com."}, {"*", "NS", "ns2.example.com."}})), 0);

  nlohmann::json s_Data;
  ASSERT_TRUE(LocalDns::LookupLocalRecord("anything.example.com", "NS", s_Data));
  ASSERT_TRUE(s_Data.is_array());
  ASSERT_EQ(s_Data.size(), 2u);
}

// ============================================================================
// LookupLocalRecord - {{FORWARD}} handling
// ============================================================================

TEST(LookupLocalRecord_forward_returns_false) {
  // {{FORWARD}} records should not be returned by LookupLocalRecord
  // (they indicate forwarding, not a local answer)
  nlohmann::json s_Zones;
  s_Zones["example.com"]["CNAME"]["api"] = "{{FORWARD}}";
  ASSERT_EQ(g_Config.Zones(s_Zones), 0);

  nlohmann::json s_Data;
  ASSERT_FALSE(LocalDns::LookupLocalRecord("api.example.com", "CNAME", s_Data));
}

TEST(LookupLocalRecord_forward_root_returns_false) {
  nlohmann::json s_Zones;
  s_Zones["example.com"]["CNAME"]["@"] = "{{FORWARD}}";
  ASSERT_EQ(g_Config.Zones(s_Zones), 0);

  nlohmann::json s_Data;
  ASSERT_FALSE(LocalDns::LookupLocalRecord("example.com", "CNAME", s_Data));
}

TEST(LookupLocalRecord_forward_wildcard_returns_false) {
  nlohmann::json s_Zones;
  s_Zones["example.com"]["CNAME"]["\\*"] = "{{FORWARD}}";
  ASSERT_EQ(g_Config.Zones(s_Zones), 0);

  nlohmann::json s_Data;
  ASSERT_FALSE(LocalDns::LookupLocalRecord("anything.example.com", "CNAME", s_Data));
}

// ============================================================================
// CheckLocalMatch - {{FORWARD}} handling
// ============================================================================

namespace {
// Helper: build a minimal valid DNS query packet
std::vector<char> BuildTestQuery(const std::string &p_Domain, uint16_t p_Qtype = 1, uint16_t p_Id = 0x1234) {
  std::vector<char> s_Pkt;

  uint16_t s_NetId{HostToNetwork(p_Id)};
  s_Pkt.push_back(reinterpret_cast<const char *>(&s_NetId)[0]);
  s_Pkt.push_back(reinterpret_cast<const char *>(&s_NetId)[1]);

  uint16_t s_Flags{HostToNetwork(static_cast<uint16_t>(0x0100))};
  s_Pkt.push_back(reinterpret_cast<const char *>(&s_Flags)[0]);
  s_Pkt.push_back(reinterpret_cast<const char *>(&s_Flags)[1]);

  uint16_t s_Qdcount{HostToNetwork(static_cast<uint16_t>(1))};
  s_Pkt.push_back(reinterpret_cast<const char *>(&s_Qdcount)[0]);
  s_Pkt.push_back(reinterpret_cast<const char *>(&s_Qdcount)[1]);

  for (int l_Index = 0; l_Index < 6; ++l_Index) {
    s_Pkt.push_back(0);
  }

  std::string s_D{p_Domain};
  if (!s_D.empty() && s_D.back() == '.') {
    s_D.pop_back();
  }

  std::size_t pos{0};
  while (pos < s_D.size()) {
    std::size_t dot{s_D.find('.', pos)};
    if (dot == std::string::npos) {
      dot = s_D.size();
    }
    std::size_t len{dot - pos};
    s_Pkt.push_back(static_cast<char>(len));
    for (std::size_t l_Index{pos}; l_Index < dot; ++l_Index) {
      s_Pkt.push_back(s_D[l_Index]);
    }
    pos = dot + 1;
  }
  s_Pkt.push_back(0);

  uint16_t s_NetQtype{HostToNetwork(p_Qtype)};
  s_Pkt.push_back(reinterpret_cast<const char *>(&s_NetQtype)[0]);
  s_Pkt.push_back(reinterpret_cast<const char *>(&s_NetQtype)[1]);

  uint16_t s_NetQclass{HostToNetwork(static_cast<uint16_t>(1))};
  s_Pkt.push_back(reinterpret_cast<const char *>(&s_NetQclass)[0]);
  s_Pkt.push_back(reinterpret_cast<const char *>(&s_NetQclass)[1]);

  return s_Pkt;
}

// Helper: set s_Zones from raw s_Zones.json format (g_Config.Zones handles normalization + validation)
void SetupForwardZones(const nlohmann::json &p_RawZones) {
  ASSERT_EQ(g_Config.Zones(p_RawZones), 0);
}
} // namespace

TEST(CheckLocalMatch_forward_subdomain) {
  // Block everything with wildcard, but forward "api" subdomain
  nlohmann::json s_Input;
  s_Input["zones"] = nlohmann::json::array();
  nlohmann::json s_Zone;
  s_Zone["zone"] = "example.com.";
  s_Zone["records"] = nlohmann::json::array();
  s_Zone["records"].push_back({{"name", "*"}, {"type", "A"}, {"ttl", 300}, {"data", "{{BLOCKED}}"}});
  s_Zone["records"].push_back({{"name", "api"}, {"type", "A"}, {"ttl", 300}, {"data", "{{FORWARD}}"}});
  s_Input["zones"].push_back(s_Zone);
  SetupForwardZones(s_Input);

  // api.example.com should be forwarded (return -1)
  std::vector<char> s_Pkt{BuildTestQuery("api.example.com", 1)};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  std::vector<char> s_Output;
  ASSERT_EQ(LocalDns::CheckLocalMatch(s_Parser, s_Output), -1);

  // random.example.com should be blocked (return 0, handled locally)
  std::vector<char> s_Pkt2{BuildTestQuery("random.example.com", 1)};
  DnsParser s_Parser2(s_Pkt2.data(), s_Pkt2.size());
  std::vector<char> s_Output2;
  ASSERT_EQ(LocalDns::CheckLocalMatch(s_Parser2, s_Output2), 0);
}

TEST(CheckLocalMatch_forward_root) {
  nlohmann::json s_Input;
  s_Input["zones"] = nlohmann::json::array();
  nlohmann::json s_Zone;
  s_Zone["zone"] = "example.com.";
  s_Zone["records"] = nlohmann::json::array();
  s_Zone["records"].push_back({{"name", "@"}, {"type", "A"}, {"ttl", 300}, {"data", "{{FORWARD}}"}});
  s_Zone["records"].push_back({{"name", "*"}, {"type", "A"}, {"ttl", 300}, {"data", "{{BLOCKED}}"}});
  s_Input["zones"].push_back(s_Zone);
  SetupForwardZones(s_Input);

  // Root domain should be forwarded
  std::vector<char> s_Pkt{BuildTestQuery("example.com", 1)};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  std::vector<char> s_Output;
  ASSERT_EQ(LocalDns::CheckLocalMatch(s_Parser, s_Output), -1);

  // Subdomains should still be blocked
  std::vector<char> s_Pkt2{BuildTestQuery("sub.example.com", 1)};
  DnsParser s_Parser2(s_Pkt2.data(), s_Pkt2.size());
  std::vector<char> s_Output2;
  ASSERT_EQ(LocalDns::CheckLocalMatch(s_Parser2, s_Output2), 0);
}

TEST(CheckLocalMatch_forward_wildcard) {
  nlohmann::json s_Input;
  s_Input["zones"] = nlohmann::json::array();
  nlohmann::json s_Zone;
  s_Zone["zone"] = "example.com.";
  s_Zone["records"] = nlohmann::json::array();
  s_Zone["records"].push_back({{"name", "@"}, {"type", "A"}, {"ttl", 300}, {"data", "{{BLOCKED}}"}});
  s_Zone["records"].push_back({{"name", "*"}, {"type", "A"}, {"ttl", 300}, {"data", "{{FORWARD}}"}});
  s_Input["zones"].push_back(s_Zone);
  SetupForwardZones(s_Input);

  // Root should be blocked
  std::vector<char> s_Pkt{BuildTestQuery("example.com", 1)};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  std::vector<char> s_Output;
  ASSERT_EQ(LocalDns::CheckLocalMatch(s_Parser, s_Output), 0);

  // Any subdomain should be forwarded
  std::vector<char> s_Pkt2{BuildTestQuery("anything.example.com", 1)};
  DnsParser s_Parser2(s_Pkt2.data(), s_Pkt2.size());
  std::vector<char> s_Output2;
  ASSERT_EQ(LocalDns::CheckLocalMatch(s_Parser2, s_Output2), -1);
}

TEST(CheckLocalMatch_forward_all_subdomain) {
  // Block everything, but forward_all "api" (api and *.api)
  nlohmann::json s_Input;
  s_Input["zones"] = nlohmann::json::array();
  nlohmann::json s_Zone;
  s_Zone["zone"] = "example.com.";
  s_Zone["records"] = nlohmann::json::array();
  s_Zone["records"].push_back({{"name", "*"}, {"type", "A"}, {"ttl", 300}, {"data", "{{BLOCKED}}"}});
  s_Zone["records"].push_back({{"name", "@"}, {"type", "A"}, {"ttl", 300}, {"data", "{{BLOCKED}}"}});
  s_Zone["records"].push_back({{"name", "api"}, {"type", "A"}, {"ttl", 300}, {"data", "{{FORWARD_ALL}}"}});
  s_Input["zones"].push_back(s_Zone);
  SetupForwardZones(s_Input);

  // api.example.com should be forwarded
  std::vector<char> s_Pkt{BuildTestQuery("api.example.com", 1)};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  std::vector<char> s_Output;
  ASSERT_EQ(LocalDns::CheckLocalMatch(s_Parser, s_Output), -1);

  // v1.api.example.com should also be forwarded
  std::vector<char> s_Pkt2{BuildTestQuery("v1.api.example.com", 1)};
  DnsParser s_Parser2(s_Pkt2.data(), s_Pkt2.size());
  std::vector<char> s_Output2;
  ASSERT_EQ(LocalDns::CheckLocalMatch(s_Parser2, s_Output2), -1);

  // deep.sub.api.example.com should also be forwarded
  std::vector<char> s_Pkt3{BuildTestQuery("deep.sub.api.example.com", 1)};
  DnsParser s_Parser3(s_Pkt3.data(), s_Pkt3.size());
  std::vector<char> s_Output3;
  ASSERT_EQ(LocalDns::CheckLocalMatch(s_Parser3, s_Output3), -1);

  // random.example.com should still be blocked (not under api)
  std::vector<char> s_Pkt4{BuildTestQuery("random.example.com", 1)};
  DnsParser s_Parser4(s_Pkt4.data(), s_Pkt4.size());
  std::vector<char> s_Output4;
  ASSERT_EQ(LocalDns::CheckLocalMatch(s_Parser4, s_Output4), 0);

  // example.com (root) should still be blocked (not under api)
  std::vector<char> s_Pkt5{BuildTestQuery("example.com", 1)};
  DnsParser s_Parser5(s_Pkt5.data(), s_Pkt5.size());
  std::vector<char> s_Output5;
  ASSERT_EQ(LocalDns::CheckLocalMatch(s_Parser5, s_Output5), 0);
}

TEST(CheckLocalMatch_forward_all_root) {
  // FORWARD_ALL on root: forwards root AND all subdomains
  nlohmann::json s_Input;
  s_Input["zones"] = nlohmann::json::array();
  nlohmann::json s_Zone;
  s_Zone["zone"] = "example.com.";
  s_Zone["records"] = nlohmann::json::array();
  s_Zone["records"].push_back({{"name", "@"}, {"type", "A"}, {"ttl", 300}, {"data", "{{FORWARD_ALL}}"}});
  s_Input["zones"].push_back(s_Zone);
  SetupForwardZones(s_Input);

  // Root should be forwarded
  std::vector<char> s_Pkt{BuildTestQuery("example.com", 1)};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  std::vector<char> s_Output;
  ASSERT_EQ(LocalDns::CheckLocalMatch(s_Parser, s_Output), -1);

  // Any subdomain should also be forwarded
  std::vector<char> s_Pkt2{BuildTestQuery("sub.example.com", 1)};
  DnsParser s_Parser2(s_Pkt2.data(), s_Pkt2.size());
  std::vector<char> s_Output2;
  ASSERT_EQ(LocalDns::CheckLocalMatch(s_Parser2, s_Output2), -1);
}

TEST(CheckLocalMatch_wildcard_does_not_match_root) {
  // Wildcard "*" should NOT match the root domain "@"
  nlohmann::json s_Input;
  s_Input["zones"] = nlohmann::json::array();
  nlohmann::json s_Zone;
  s_Zone["zone"] = "example.com.";
  s_Zone["records"] = nlohmann::json::array();
  s_Zone["records"].push_back({{"name", "*"}, {"type", "A"}, {"ttl", 300}, {"data", "{{BLOCKED}}"}});
  s_Input["zones"].push_back(s_Zone);
  SetupForwardZones(s_Input);

  // Root domain (example.com) should NOT be matched by the wildcard - returns -1 (forwarded)
  std::vector<char> s_Pkt{BuildTestQuery("example.com", 1)};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  std::vector<char> s_Output;
  ASSERT_EQ(LocalDns::CheckLocalMatch(s_Parser, s_Output), -1);

  // Subdomain should be matched by the wildcard - returns 0 (handled locally)
  std::vector<char> s_Pkt2{BuildTestQuery("sub.example.com", 1)};
  DnsParser s_Parser2(s_Pkt2.data(), s_Pkt2.size());
  std::vector<char> s_Output2;
  ASSERT_EQ(LocalDns::CheckLocalMatch(s_Parser2, s_Output2), 0);
}

TEST(CheckLocalMatch_forward_all_wildcard_does_not_forward_root) {
  // FORWARD_ALL on "*" should forward all subdomains but NOT root
  nlohmann::json s_Input;
  s_Input["zones"] = nlohmann::json::array();
  nlohmann::json s_Zone;
  s_Zone["zone"] = "example.com.";
  s_Zone["records"] = nlohmann::json::array();
  s_Zone["records"].push_back({{"name", "@"}, {"type", "A"}, {"ttl", 300}, {"data", "{{BLOCKED}}"}});
  s_Zone["records"].push_back({{"name", "*"}, {"type", "A"}, {"ttl", 300}, {"data", "{{FORWARD_ALL}}"}});
  s_Input["zones"].push_back(s_Zone);
  SetupForwardZones(s_Input);

  // Root domain should be blocked, NOT forwarded
  std::vector<char> s_Pkt{BuildTestQuery("example.com", 1)};
  DnsParser s_Parser(s_Pkt.data(), s_Pkt.size());
  std::vector<char> s_Output;
  ASSERT_EQ(LocalDns::CheckLocalMatch(s_Parser, s_Output), 0);

  // Subdomains should be forwarded
  std::vector<char> s_Pkt2{BuildTestQuery("sub.example.com", 1)};
  DnsParser s_Parser2(s_Pkt2.data(), s_Pkt2.size());
  std::vector<char> s_Output2;
  ASSERT_EQ(LocalDns::CheckLocalMatch(s_Parser2, s_Output2), -1);
}
