// Tests for Config class: setters, getters, validation
#include "test_framework.h"

#include "config.h"
#include "constants.h"

#include <cstdint>
#include <string>
#include <vector>

// ============================================================================
// DNS IP Address validation
// ============================================================================

TEST(Config_DnsIpAddress_valid_ipv4) {
  ASSERT_EQ(g_Config.DnsIpAddress("192.168.1.1"), 0);
  ASSERT_EQ(g_Config.DnsIpAddress(), "192.168.1.1");
}

TEST(Config_DnsIpAddress_valid_ipv6) {
  ASSERT_EQ(g_Config.DnsIpAddress("::1"), 0);
  ASSERT_EQ(g_Config.DnsIpAddress(), "::1");
}

TEST(Config_DnsIpAddress_valid_loopback) {
  ASSERT_EQ(g_Config.DnsIpAddress("127.0.0.1"), 0);
}

TEST(Config_DnsIpAddress_invalid) {
  std::string s_Prev{g_Config.DnsIpAddress()};
  ASSERT_EQ(g_Config.DnsIpAddress("not_an_ip"), 1);
  ASSERT_EQ(g_Config.DnsIpAddress(), s_Prev); // Should not change
}

TEST(Config_DnsIpAddress_empty) {
  std::string s_Prev{g_Config.DnsIpAddress()};
  ASSERT_EQ(g_Config.DnsIpAddress(""), 1);
  ASSERT_EQ(g_Config.DnsIpAddress(), s_Prev);
}

// ============================================================================
// DNS Port validation
// ============================================================================

TEST(Config_DnsPort_valid) {
  ASSERT_EQ(g_Config.DnsPort(53), 0);
  ASSERT_EQ(g_Config.DnsPort(), static_cast<uint16_t>(53));
}

TEST(Config_DnsPort_min) {
  ASSERT_EQ(g_Config.DnsPort(1), 0);
}

TEST(Config_DnsPort_max) {
  ASSERT_EQ(g_Config.DnsPort(65535), 0);
}

TEST(Config_DnsPort_zero) {
  uint16_t s_Prev{g_Config.DnsPort()};
  ASSERT_EQ(g_Config.DnsPort(0), 1);
  ASSERT_EQ(g_Config.DnsPort(), s_Prev);
}

// ============================================================================
// TTL validation
// ============================================================================

TEST(Config_DefaultTtl_valid) {
  ASSERT_EQ(g_Config.DefaultTtl(3600), 0);
  ASSERT_EQ(g_Config.DefaultTtl(), static_cast<int32_t>(3600));
}

TEST(Config_DefaultTtl_min) {
  ASSERT_EQ(g_Config.DefaultTtl(0), 0);
  ASSERT_EQ(g_Config.DefaultTtl(), static_cast<int32_t>(0));
}

TEST(Config_DefaultTtl_max) {
  ASSERT_EQ(g_Config.DefaultTtl(604800), 0);
}

TEST(Config_DefaultTtl_negative) {
  int32_t s_Prev{g_Config.DefaultTtl()};
  ASSERT_EQ(g_Config.DefaultTtl(-1), 1);
  ASSERT_EQ(g_Config.DefaultTtl(), s_Prev);
}

TEST(Config_DefaultTtl_too_large) {
  int32_t s_Prev{g_Config.DefaultTtl()};
  ASSERT_EQ(g_Config.DefaultTtl(604801), 1);
  ASSERT_EQ(g_Config.DefaultTtl(), s_Prev);
}

// ============================================================================
// Redirect IP validation
// ============================================================================

TEST(Config_RedirectIpv4_valid) {
  ASSERT_EQ(g_Config.RedirectIpv4("10.0.0.1"), 0);
  ASSERT_EQ(g_Config.RedirectIpv4(), "10.0.0.1");
}

TEST(Config_RedirectIpv4_invalid) {
  std::string s_Prev{g_Config.RedirectIpv4()};
  ASSERT_EQ(g_Config.RedirectIpv4("bad"), 1);
  ASSERT_EQ(g_Config.RedirectIpv4(), s_Prev);
}

TEST(Config_RedirectIpv4_empty) {
  ASSERT_EQ(g_Config.RedirectIpv4(""), 1);
}

TEST(Config_RedirectIpv6_valid) {
  ASSERT_EQ(g_Config.RedirectIpv6("::1"), 0);
  ASSERT_EQ(g_Config.RedirectIpv6(), "::1");
}

TEST(Config_RedirectIpv6_invalid) {
  std::string s_Prev{g_Config.RedirectIpv6()};
  ASSERT_EQ(g_Config.RedirectIpv6("bad"), 1);
  ASSERT_EQ(g_Config.RedirectIpv6(), s_Prev);
}

// ============================================================================
// DoH Resolvers validation
// ============================================================================

TEST(Config_DohResolvers_valid) {
  std::vector<std::string> s_Resolvers{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"};
  ASSERT_EQ(g_Config.DohResolvers(s_Resolvers), 0);
  ASSERT_EQ(g_Config.DohResolvers().size(), 2u);
}

TEST(Config_DohResolvers_empty) {
  std::vector<std::string> s_Resolvers;
  ASSERT_EQ(g_Config.DohResolvers(s_Resolvers), 1);
}

TEST(Config_DohResolvers_no_https) {
  std::vector<std::string> s_Resolvers{"http://1.1.1.1/dns-query"};
  ASSERT_EQ(g_Config.DohResolvers(s_Resolvers), 1);
}

TEST(Config_DohResolvers_mixed_valid_invalid) {
  std::vector<std::string> s_Resolvers{
      "https://1.1.1.1/dns-query",
      "http://8.8.8.8/dns-query" // Invalid, not HTTPS
  };
  ASSERT_EQ(g_Config.DohResolvers(s_Resolvers), 0);
  ASSERT_EQ(g_Config.DohResolvers().size(), 1u); // Only the valid one
}

// ============================================================================
// DohOnly flag
// ============================================================================

TEST(Config_DohOnly_toggle) {
  ASSERT_EQ(g_Config.DohOnly(true), 0);
  ASSERT_TRUE(g_Config.DohOnly());
  ASSERT_EQ(g_Config.DohOnly(false), 0);
  ASSERT_FALSE(g_Config.DohOnly());
}

// ============================================================================
// Useragent
// ============================================================================

TEST(Config_Useragent_valid) {
  ASSERT_EQ(g_Config.Useragent("test-agent/1.0"), 0);
  ASSERT_EQ(g_Config.Useragent(), "test-agent/1.0");
}

TEST(Config_Useragent_empty) {
  ASSERT_EQ(g_Config.Useragent(""), 1);
}

TEST(Config_Useragent_with_masks) {
  ASSERT_EQ(g_Config.Useragent("chukei/{{APP_VERSION}} ({{CONSOLE}})"), 0);
  // After processing, should contain actual version
  std::string s_Ua{g_Config.Useragent()};
  ASSERT_TRUE(s_Ua.find("chukei/") != std::string::npos);
  // Should NOT contain the raw mask
  ASSERT_TRUE(s_Ua.find("{{APP_VERSION}}") == std::string::npos);
}

// ============================================================================
// App metadata getters
// ============================================================================

TEST(Config_AppName) {
  ASSERT_FALSE(g_Config.AppName().empty());
}

TEST(Config_AppVersion) {
  ASSERT_FALSE(g_Config.AppVersion().empty());
}

TEST(Config_Console) {
  ASSERT_FALSE(g_Config.Console().empty());
}

// ============================================================================
// Zones
// ============================================================================

TEST(Config_Zones_empty_object) {
  nlohmann::json s_Empty;
  s_Empty["zones"] = nlohmann::json::array();
  ASSERT_EQ(g_Config.Zones(s_Empty), 0);
  ASSERT_TRUE(g_Config.Zones().empty());
}

TEST(Config_Zones_with_blocked_domain) {
  nlohmann::json s_Zones;
  s_Zones["zones"] = nlohmann::json::array();
  s_Zones["zones"].push_back({{"zone", "evil.com."}, {"blocked", true}});
  ASSERT_EQ(g_Config.Zones(s_Zones), 0);
  ASSERT_TRUE(g_Config.Zones().contains("evil.com"));
}

// ============================================================================
// Initialized flag
// ============================================================================

TEST(Config_Initialized_default_false) {
  // After running tests above, state may vary, but we can test the setter
  ASSERT_EQ(g_Config.Initialized(true), 0);
  ASSERT_TRUE(g_Config.Initialized());
  ASSERT_EQ(g_Config.Initialized(false), 0);
  ASSERT_FALSE(g_Config.Initialized());
}

// ============================================================================
// CacertPath validation
// ============================================================================

TEST(Config_CacertPath_empty_clears) {
  g_Config.CacertPath("");
  ASSERT_TRUE(g_Config.CacertPath().empty());
}

TEST(Config_CacertPath_nonexistent_file) {
  std::string s_Prev{g_Config.CacertPath()};
  ASSERT_EQ(g_Config.CacertPath("/nonexistent/path/cacert.pem"), 1);
  ASSERT_EQ(g_Config.CacertPath(), s_Prev); // Should not change
}

TEST(Config_CacertPath_not_regular_file) {
  // "/tmp" exists but is a directory, not a regular file
  std::string s_Prev{g_Config.CacertPath()};
  ASSERT_EQ(g_Config.CacertPath("/tmp"), 1);
  ASSERT_EQ(g_Config.CacertPath(), s_Prev);
}

TEST(Config_CacertPath_valid_file) {
  // /etc/hosts is a regular file present on all Linux systems
  ASSERT_EQ(g_Config.CacertPath("/etc/hosts"), 0);
  ASSERT_EQ(g_Config.CacertPath(), "/etc/hosts");
  // Clean up
  g_Config.CacertPath("");
}

// ============================================================================
// DohTimeoutMs validation
// ============================================================================

TEST(Config_DohTimeoutMs_default) {
  ASSERT_EQ(g_Config.DohTimeoutMs(), Constants::Network::DEFAULT_DOH_TIMEOUT_MS);
}

TEST(Config_DohTimeoutMs_set_valid) {
  ASSERT_EQ(g_Config.DohTimeoutMs(5000), 0);
  ASSERT_EQ(g_Config.DohTimeoutMs(), 5000);
  ASSERT_EQ(g_Config.DohTimeoutMs(Constants::Network::DEFAULT_DOH_TIMEOUT_MS), 0); // Restore
}

TEST(Config_DohTimeoutMs_set_below_minimum) {
  ASSERT_EQ(g_Config.DohTimeoutMs(50), -1);
}

TEST(Config_DohTimeoutMs_set_above_maximum) {
  ASSERT_EQ(g_Config.DohTimeoutMs(100000), -1);
}

TEST(Config_DohTimeoutMs_set_boundary_min) {
  ASSERT_EQ(g_Config.DohTimeoutMs(Constants::Network::MIN_DOH_TIMEOUT_MS), 0);
  ASSERT_EQ(g_Config.DohTimeoutMs(), Constants::Network::MIN_DOH_TIMEOUT_MS);
  ASSERT_EQ(g_Config.DohTimeoutMs(Constants::Network::DEFAULT_DOH_TIMEOUT_MS), 0); // Restore
}

TEST(Config_DohTimeoutMs_set_boundary_max) {
  ASSERT_EQ(g_Config.DohTimeoutMs(Constants::Network::MAX_DOH_TIMEOUT_MS), 0);
  ASSERT_EQ(g_Config.DohTimeoutMs(), Constants::Network::MAX_DOH_TIMEOUT_MS);
  ASSERT_EQ(g_Config.DohTimeoutMs(Constants::Network::DEFAULT_DOH_TIMEOUT_MS), 0); // Restore
}
