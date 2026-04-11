// Unit tests for DnsOverHttps
#include "test_framework.h"

#include "dns_over_https.h"

#include <string>
#include <utility> // std::move
#include <vector>

// ============================================================================
// Constructor tests
// ============================================================================

TEST(DnsOverHttps_constructor_valid) {
  DnsOverHttps s_Doh("test-agent", {"https://1.1.1.1/dns-query"});
  ASSERT_EQ(s_Doh.Useragent(), "test-agent");
  ASSERT_EQ(s_Doh.Resolvers().size(), static_cast<std::size_t>(1));
  ASSERT_EQ(s_Doh.Method(), DnsOverHttps::HttpMethod::POST);
}

TEST(DnsOverHttps_constructor_multiple_resolvers) {
  std::vector<std::string> s_Resolvers{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"};
  DnsOverHttps s_Doh("test-agent", s_Resolvers);
  ASSERT_EQ(s_Doh.Resolvers().size(), static_cast<std::size_t>(2));
}

TEST(DnsOverHttps_constructor_empty_useragent_throws) {
  ASSERT_THROW(DnsOverHttps("", {"https://1.1.1.1/dns-query"}), std::invalid_argument);
}

TEST(DnsOverHttps_constructor_empty_resolvers_throws) {
  ASSERT_THROW(DnsOverHttps("test-agent", {}), std::invalid_argument);
}

// ============================================================================
// Setter tests
// ============================================================================

TEST(DnsOverHttps_set_useragent) {
  DnsOverHttps s_Doh("original", {"https://1.1.1.1/dns-query"});
  s_Doh.Useragent("updated");
  ASSERT_EQ(s_Doh.Useragent(), "updated");
}

TEST(DnsOverHttps_set_useragent_empty_throws) {
  DnsOverHttps s_Doh("test-agent", {"https://1.1.1.1/dns-query"});
  ASSERT_THROW(s_Doh.Useragent(""), std::invalid_argument);
}

TEST(DnsOverHttps_set_resolvers) {
  DnsOverHttps s_Doh("test-agent", {"https://1.1.1.1/dns-query"});
  s_Doh.Resolvers({"https://8.8.8.8/dns-query", "https://9.9.9.9/dns-query"});
  ASSERT_EQ(s_Doh.Resolvers().size(), static_cast<std::size_t>(2));
}

TEST(DnsOverHttps_set_resolvers_empty_throws) {
  DnsOverHttps s_Doh("test-agent", {"https://1.1.1.1/dns-query"});
  ASSERT_THROW(s_Doh.Resolvers({}), std::invalid_argument);
}

TEST(DnsOverHttps_set_method_get) {
  DnsOverHttps s_Doh("test-agent", {"https://1.1.1.1/dns-query"});
  s_Doh.Method(DnsOverHttps::HttpMethod::GET);
  ASSERT_EQ(s_Doh.Method(), DnsOverHttps::HttpMethod::GET);
}

TEST(DnsOverHttps_set_method_post) {
  DnsOverHttps s_Doh("test-agent", {"https://1.1.1.1/dns-query"});
  s_Doh.Method(DnsOverHttps::HttpMethod::GET);
  s_Doh.Method(DnsOverHttps::HttpMethod::POST);
  ASSERT_EQ(s_Doh.Method(), DnsOverHttps::HttpMethod::POST);
}

// ============================================================================
// Resolve input validation tests
// ============================================================================

TEST(DnsOverHttps_resolve_null_data) {
  DnsOverHttps s_Doh("test-agent", {"https://1.1.1.1/dns-query"});
  std::vector<char> s_Output;
  ASSERT_EQ(s_Doh.Resolve(nullptr, 10, s_Output), DnsOverHttps::ResolveResult::InvalidInput);
}

TEST(DnsOverHttps_resolve_zero_length) {
  DnsOverHttps s_Doh("test-agent", {"https://1.1.1.1/dns-query"});
  char s_Data[] = "test";
  std::vector<char> s_Output;
  ASSERT_EQ(s_Doh.Resolve(s_Data, 0, s_Output), DnsOverHttps::ResolveResult::InvalidInput);
}

// ============================================================================
// Base64UrlEncode tests
// ============================================================================

TEST(DnsOverHttps_base64url_empty) {
  std::string s_Result{DnsOverHttps::Base64UrlEncode("", 0)};
  ASSERT_EQ(s_Result, "");
}

TEST(DnsOverHttps_base64url_one_byte) {
  // 'f' (0x66) -> Zg (no padding)
  std::string s_Result{DnsOverHttps::Base64UrlEncode("f", 1)};
  ASSERT_EQ(s_Result, "Zg");
}

TEST(DnsOverHttps_base64url_two_bytes) {
  // 'fo' -> Zm8 (no padding)
  std::string s_Result{DnsOverHttps::Base64UrlEncode("fo", 2)};
  ASSERT_EQ(s_Result, "Zm8");
}

TEST(DnsOverHttps_base64url_three_bytes) {
  // 'foo' -> Zm9v (exactly 3 bytes = no padding needed even in standard base64)
  std::string s_Result{DnsOverHttps::Base64UrlEncode("foo", 3)};
  ASSERT_EQ(s_Result, "Zm9v");
}

TEST(DnsOverHttps_base64url_url_safe_chars) {
  // Bytes 0xFB 0xFF 0xFE would produce +//+ in standard base64
  // base64url uses - and _ instead: -__-
  const char s_Data[] = {'\xFB', '\xFF', '\xFE'};
  std::string s_Result{DnsOverHttps::Base64UrlEncode(s_Data, 3)};
  ASSERT_EQ(s_Result, "-__-");
}

TEST(DnsOverHttps_base64url_no_padding) {
  // Standard base64("a") = "YQ==" but base64url has no padding
  std::string s_Result{DnsOverHttps::Base64UrlEncode("a", 1)};
  ASSERT_EQ(s_Result, "YQ");
  // Standard base64("ab") = "YWI=" but base64url has no padding
  s_Result = DnsOverHttps::Base64UrlEncode("ab", 2);
  ASSERT_EQ(s_Result, "YWI");
}

TEST(DnsOverHttps_base64url_rfc8484_example) {
  // RFC 8484 §4.1.1 example: DNS query for example.com type A
  // Expected base64url: AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE
  const unsigned char raw[] = {
      0x00, 0x00, // Transaction ID
      0x01, 0x00, // Flags (RD=1)
      0x00, 0x01, // QDCOUNT = 1
      0x00, 0x00, // ANCOUNT = 0
      0x00, 0x00, // NSCOUNT = 0
      0x00, 0x00, // ARCOUNT = 0
      0x07, 'e',  'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', // example.com
      0x00,       // root label
      0x00, 0x01, // QTYPE = A
      0x00, 0x01  // QCLASS = IN
  };
  std::string s_Result{DnsOverHttps::Base64UrlEncode(reinterpret_cast<const char *>(raw), sizeof(raw))};
  ASSERT_EQ(s_Result, "AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE");
}

TEST(DnsOverHttps_base64url_longer_input) {
  // "Hello, World!" -> SGVsbG8sIFdvcmxkIQ
  std::string s_Result{DnsOverHttps::Base64UrlEncode("Hello, World!", 13)};
  ASSERT_EQ(s_Result, "SGVsbG8sIFdvcmxkIQ");
}

TEST(DnsOverHttps_base64url_all_zeros) {
  const char s_Data[] = {'\0', '\0', '\0'};
  std::string s_Result{DnsOverHttps::Base64UrlEncode(s_Data, 3)};
  ASSERT_EQ(s_Result, "AAAA");
}

TEST(DnsOverHttps_base64url_all_ones) {
  const char s_Data[] = {'\xFF', '\xFF', '\xFF'};
  std::string s_Result{DnsOverHttps::Base64UrlEncode(s_Data, 3)};
  ASSERT_EQ(s_Result, "____");
}

// ============================================================================
// Move semantics tests
// ============================================================================

TEST(DnsOverHttps_move_constructor) {
  DnsOverHttps s_Doh1("test-agent", {"https://1.1.1.1/dns-query"});
  s_Doh1.Method(DnsOverHttps::HttpMethod::GET);
  DnsOverHttps s_Doh2(std::move(s_Doh1));
  ASSERT_EQ(s_Doh2.Useragent(), "test-agent");
  ASSERT_EQ(s_Doh2.Resolvers().size(), static_cast<std::size_t>(1));
  ASSERT_EQ(s_Doh2.Method(), DnsOverHttps::HttpMethod::GET);
}

TEST(DnsOverHttps_move_assignment) {
  DnsOverHttps s_Doh1("agent-1", {"https://1.1.1.1/dns-query"});
  DnsOverHttps s_Doh2("agent-2", {"https://8.8.8.8/dns-query", "https://9.9.9.9/dns-query"});
  s_Doh1.Method(DnsOverHttps::HttpMethod::GET);
  s_Doh2 = std::move(s_Doh1);
  ASSERT_EQ(s_Doh2.Useragent(), "agent-1");
  ASSERT_EQ(s_Doh2.Resolvers().size(), static_cast<std::size_t>(1));
  ASSERT_EQ(s_Doh2.Method(), DnsOverHttps::HttpMethod::GET);
}

TEST(DnsOverHttps_moved_from_resolve_returns_error) {
  DnsOverHttps s_Doh1("test-agent", {"https://1.1.1.1/dns-query"});
  DnsOverHttps s_Doh2(std::move(s_Doh1));
  // The moved-from object has a null multi handle - Resolve should fail gracefully
  char s_Data[] = "test";
  std::vector<char> s_Output;
  ASSERT_EQ(s_Doh1.Resolve(s_Data, 4, s_Output), DnsOverHttps::ResolveResult::CurlError); // NOLINT
}

// ============================================================================
// CacertPath tests
// ============================================================================

TEST(DnsOverHttps_cacert_path_default_empty) {
  DnsOverHttps s_Doh("test-agent", {"https://1.1.1.1/dns-query"});
  ASSERT_TRUE(s_Doh.CacertPath().empty());
}

TEST(DnsOverHttps_cacert_path_set_valid_file) {
  DnsOverHttps s_Doh("test-agent", {"https://1.1.1.1/dns-query"});
  // /etc/hosts is a regular file present on all Linux systems
  s_Doh.CacertPath("/etc/hosts");
  ASSERT_EQ(s_Doh.CacertPath(), "/etc/hosts");
}

TEST(DnsOverHttps_cacert_path_nonexistent_falls_back) {
  DnsOverHttps s_Doh("test-agent", {"https://1.1.1.1/dns-query"});
  s_Doh.CacertPath("/nonexistent/cacert.pem");
  // Should fall back to empty (platform default) since file doesn't exist
  ASSERT_TRUE(s_Doh.CacertPath().empty());
}

TEST(DnsOverHttps_cacert_path_set_empty_clears) {
  DnsOverHttps s_Doh("test-agent", {"https://1.1.1.1/dns-query"});
  s_Doh.CacertPath("/etc/hosts");
  ASSERT_FALSE(s_Doh.CacertPath().empty());
  s_Doh.CacertPath("");
  ASSERT_TRUE(s_Doh.CacertPath().empty());
}

TEST(DnsOverHttps_cacert_path_preserved_on_move) {
  DnsOverHttps s_Doh1("test-agent", {"https://1.1.1.1/dns-query"});
  s_Doh1.CacertPath("/etc/hosts");
  DnsOverHttps s_Doh2(std::move(s_Doh1));
  ASSERT_EQ(s_Doh2.CacertPath(), "/etc/hosts");
}

TEST(DnsOverHttps_cacert_path_preserved_on_move_assignment) {
  DnsOverHttps s_Doh1("agent-1", {"https://1.1.1.1/dns-query"});
  DnsOverHttps s_Doh2("agent-2", {"https://8.8.8.8/dns-query"});
  s_Doh1.CacertPath("/etc/hosts");
  s_Doh2 = std::move(s_Doh1);
  ASSERT_EQ(s_Doh2.CacertPath(), "/etc/hosts");
}

// ============================================================================
// DohTimeoutMs tests
// ============================================================================

TEST(DnsOverHttps_doh_timeout_default) {
  DnsOverHttps s_Doh("test-agent", {"https://1.1.1.1/dns-query"});
  ASSERT_EQ(s_Doh.DohTimeoutMs(), 15000);
}

TEST(DnsOverHttps_doh_timeout_set_valid) {
  DnsOverHttps s_Doh("test-agent", {"https://1.1.1.1/dns-query"});
  s_Doh.DohTimeoutMs(5000);
  ASSERT_EQ(s_Doh.DohTimeoutMs(), 5000);
}

TEST(DnsOverHttps_doh_timeout_clamp_low) {
  DnsOverHttps s_Doh("test-agent", {"https://1.1.1.1/dns-query"});
  s_Doh.DohTimeoutMs(10);
  ASSERT_EQ(s_Doh.DohTimeoutMs(), 100); // Clamped to minimum
}

TEST(DnsOverHttps_doh_timeout_clamp_high) {
  DnsOverHttps s_Doh("test-agent", {"https://1.1.1.1/dns-query"});
  s_Doh.DohTimeoutMs(100000);
  ASSERT_EQ(s_Doh.DohTimeoutMs(), 60000); // Clamped to maximum
}

TEST(DnsOverHttps_doh_timeout_constructor_param) {
  DnsOverHttps s_Doh("test-agent", {"https://1.1.1.1/dns-query"}, "", 8000);
  ASSERT_EQ(s_Doh.DohTimeoutMs(), 8000);
}

TEST(DnsOverHttps_doh_timeout_preserved_on_move) {
  DnsOverHttps s_Doh1("test-agent", {"https://1.1.1.1/dns-query"}, "", 7000);
  DnsOverHttps s_Doh2(std::move(s_Doh1));
  ASSERT_EQ(s_Doh2.DohTimeoutMs(), 7000);
}

TEST(DnsOverHttps_doh_timeout_preserved_on_move_assignment) {
  DnsOverHttps s_Doh1("agent-1", {"https://1.1.1.1/dns-query"}, "", 9000);
  DnsOverHttps s_Doh2("agent-2", {"https://8.8.8.8/dns-query"});
  s_Doh2 = std::move(s_Doh1);
  ASSERT_EQ(s_Doh2.DohTimeoutMs(), 9000);
}
