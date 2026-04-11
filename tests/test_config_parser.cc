// Tests for ConfigParser: JSON parsing and validation
#include "test_framework.h"

#include "config_parser.h"
#include "constants.h"

#include <fstream>
#include <string>

#include "nlohmann/json.hpp"

// ============================================================================
// Parse
// ============================================================================

TEST(ConfigParser_Parse_nonexistent_file) {
  nlohmann::json s_Result{ConfigParser::Parse("/tmp/nonexistent_zones_test_file.json")};
  ASSERT_TRUE(s_Result.empty());
}

TEST(ConfigParser_Parse_empty_path) {
  nlohmann::json s_Result{ConfigParser::Parse("")};
  ASSERT_TRUE(s_Result.empty());
}

TEST(ConfigParser_Parse_valid_file) {
  // Create a temporary valid s_Zones file
  const char *path = "/tmp/chukei_test_zones.json";
  {
    std::ofstream f(path);
    f << R"({"example.com": "{{BLOCKED}}"})";
  }
  nlohmann::json s_Result{ConfigParser::Parse(path)};
  ASSERT_FALSE(s_Result.empty());
  ASSERT_TRUE(s_Result.contains("example.com"));
  std::remove(path);
}

TEST(ConfigParser_Parse_invalid_json) {
  const char *path = "/tmp/chukei_test_bad.json";
  {
    std::ofstream f(path);
    f << "not valid json {{{";
  }
  nlohmann::json s_Result{ConfigParser::Parse(path)};
  ASSERT_TRUE(s_Result.empty());
  std::remove(path);
}

TEST(ConfigParser_Parse_directory) {
  nlohmann::json s_Result{ConfigParser::Parse("/tmp")};
  ASSERT_TRUE(s_Result.empty());
}

// ============================================================================
// LoadDefault
// ============================================================================

TEST(ConfigParser_LoadDefault_succeeds) {
  nlohmann::json s_Result{ConfigParser::LoadDefault()};
  ASSERT_FALSE(s_Result.empty());
}

TEST(ConfigParser_LoadDefault_has_expected_domains) {
  nlohmann::json s_Result{ConfigParser::LoadDefault()};
  // Should contain Nintendo and/or PlayStation domains
  bool s_HasDomains{false};
  for (const auto &[l_Key, l_Val] : s_Result.items()) {
    if (!l_Key.empty()) {
      s_HasDomains = true;
      break;
    }
  }
  ASSERT_TRUE(s_HasDomains);
}

// ============================================================================
// ValidateAndOptimize
// ============================================================================

TEST(ConfigParser_ValidateAndOptimize_blocked) {
  nlohmann::json s_Zones;
  s_Zones["evil.com"] = "{{BLOCKED}}";
  nlohmann::json s_Result{ConfigParser::ValidateAndOptimize(s_Zones, "0.0.0.0", "::")};
  ASSERT_EQ(s_Result["evil.com"], "{{BLOCKED}}");
}

TEST(ConfigParser_ValidateAndOptimize_A_record) {
  nlohmann::json s_Zones;
  s_Zones["example.com"]["A"]["@"] = "192.168.1.1";
  nlohmann::json s_Result{ConfigParser::ValidateAndOptimize(s_Zones, "0.0.0.0", "::")};
  // The value should now be 4-byte binary
  std::string s_Val{s_Result["example.com"]["A"]["@"]};
  ASSERT_EQ(s_Val.size(), 4u);
}

TEST(ConfigParser_ValidateAndOptimize_AAAA_record) {
  nlohmann::json s_Zones;
  s_Zones["example.com"]["AAAA"]["@"] = "::1";
  nlohmann::json s_Result{ConfigParser::ValidateAndOptimize(s_Zones, "0.0.0.0", "::")};
  std::string s_Val{s_Result["example.com"]["AAAA"]["@"]};
  ASSERT_EQ(s_Val.size(), 16u);
}

TEST(ConfigParser_ValidateAndOptimize_SELF_ipv4) {
  nlohmann::json s_Zones;
  s_Zones["example.com"]["A"]["@"] = "{{SELF}}";
  nlohmann::json s_Result{ConfigParser::ValidateAndOptimize(s_Zones, "10.0.0.1", "::")};
  std::string s_Val{s_Result["example.com"]["A"]["@"]};
  ASSERT_EQ(s_Val.size(), 4u);
  // First byte should be 10
  ASSERT_EQ(static_cast<unsigned char>(s_Val[0]), 10u);
}

TEST(ConfigParser_ValidateAndOptimize_SELF_ipv6) {
  nlohmann::json s_Zones;
  s_Zones["example.com"]["AAAA"]["@"] = "{{SELF}}";
  nlohmann::json s_Result{ConfigParser::ValidateAndOptimize(s_Zones, "0.0.0.0", "::1")};
  std::string s_Val{s_Result["example.com"]["AAAA"]["@"]};
  ASSERT_EQ(s_Val.size(), 16u);
  ASSERT_EQ(static_cast<unsigned char>(s_Val[15]), 1u);
}

TEST(ConfigParser_ValidateAndOptimize_invalid_ipv4) {
  nlohmann::json s_Zones;
  s_Zones["example.com"]["A"]["@"] = "999.999.999.999";
  ASSERT_THROW(ConfigParser::ValidateAndOptimize(s_Zones, "0.0.0.0", "::"), std::runtime_error);
}

TEST(ConfigParser_ValidateAndOptimize_BLOCKED_ipv4) {
  nlohmann::json s_Zones;
  s_Zones["example.com"]["A"]["@"] = "{{BLOCKED}}";
  nlohmann::json s_Result{ConfigParser::ValidateAndOptimize(s_Zones, "10.0.0.1", "::")};
  std::string s_Val{s_Result["example.com"]["A"]["@"]};
  ASSERT_EQ(s_Val.size(), 4u);
  // Should resolve to 0.0.0.0 (all zero bytes)
  ASSERT_EQ(static_cast<unsigned char>(s_Val[0]), 0u);
  ASSERT_EQ(static_cast<unsigned char>(s_Val[1]), 0u);
  ASSERT_EQ(static_cast<unsigned char>(s_Val[2]), 0u);
  ASSERT_EQ(static_cast<unsigned char>(s_Val[3]), 0u);
}

TEST(ConfigParser_ValidateAndOptimize_BLOCKED_ipv6) {
  nlohmann::json s_Zones;
  s_Zones["example.com"]["AAAA"]["@"] = "{{BLOCKED}}";
  nlohmann::json s_Result{ConfigParser::ValidateAndOptimize(s_Zones, "0.0.0.0", "::1")};
  std::string s_Val{s_Result["example.com"]["AAAA"]["@"]};
  ASSERT_EQ(s_Val.size(), 16u);
  // Should resolve to :: (all zero bytes)
  for (int l_Index = 0; l_Index < 16; ++l_Index) {
    ASSERT_EQ(static_cast<unsigned char>(s_Val[l_Index]), 0u);
  }
}

TEST(ConfigParser_ValidateAndOptimize_CNAME_passthrough) {
  nlohmann::json s_Zones;
  s_Zones["example.com"]["CNAME"]["www"] = "other.example.com.";
  nlohmann::json s_Result{ConfigParser::ValidateAndOptimize(s_Zones, "0.0.0.0", "::")};
  // CNAME should pass through unchanged
  ASSERT_EQ(s_Result["example.com"]["CNAME"]["www"], "other.example.com.");
}

TEST(ConfigParser_ValidateAndOptimize_preserves_structure) {
  nlohmann::json s_Zones;
  s_Zones["example.com"]["A"]["@"] = "1.2.3.4";
  s_Zones["example.com"]["A"]["www"] = "1.2.3.4";
  s_Zones["example.com"]["CNAME"]["cdn"] = "cdn.example.com.";
  nlohmann::json s_Result{ConfigParser::ValidateAndOptimize(s_Zones, "0.0.0.0", "::")};

  ASSERT_TRUE(s_Result.contains("example.com"));
  ASSERT_TRUE(s_Result["example.com"].contains("A"));
  ASSERT_TRUE(s_Result["example.com"].contains("CNAME"));
  ASSERT_TRUE(s_Result["example.com"]["A"].contains("@"));
  ASSERT_TRUE(s_Result["example.com"]["A"].contains("www"));
}

// ============================================================================
// ValidateAndOptimize - Multi-value (array) support
// ============================================================================

TEST(ConfigParser_ValidateAndOptimize_A_array) {
  nlohmann::json s_Zones;
  s_Zones["example.com"]["A"]["@"] = nlohmann::json::array({"192.168.1.1", "192.168.1.2"});
  nlohmann::json s_Result{ConfigParser::ValidateAndOptimize(s_Zones, "0.0.0.0", "::")};
  ASSERT_TRUE(s_Result["example.com"]["A"]["@"].is_array());
  ASSERT_EQ(s_Result["example.com"]["A"]["@"].size(), 2u);
  // Each element should be 4-byte binary
  ASSERT_EQ(s_Result["example.com"]["A"]["@"][0].get<std::string>().size(), 4u);
  ASSERT_EQ(s_Result["example.com"]["A"]["@"][1].get<std::string>().size(), 4u);
}

TEST(ConfigParser_ValidateAndOptimize_AAAA_array) {
  nlohmann::json s_Zones;
  s_Zones["example.com"]["AAAA"]["@"] = nlohmann::json::array({"::1", "::2"});
  nlohmann::json s_Result{ConfigParser::ValidateAndOptimize(s_Zones, "0.0.0.0", "::")};
  ASSERT_TRUE(s_Result["example.com"]["AAAA"]["@"].is_array());
  ASSERT_EQ(s_Result["example.com"]["AAAA"]["@"].size(), 2u);
  ASSERT_EQ(s_Result["example.com"]["AAAA"]["@"][0].get<std::string>().size(), 16u);
  ASSERT_EQ(s_Result["example.com"]["AAAA"]["@"][1].get<std::string>().size(), 16u);
}

TEST(ConfigParser_ValidateAndOptimize_A_array_with_SELF) {
  nlohmann::json s_Zones;
  s_Zones["example.com"]["A"]["@"] = nlohmann::json::array({"{{SELF}}", "10.0.0.1"});
  nlohmann::json s_Result{ConfigParser::ValidateAndOptimize(s_Zones, "192.168.1.100", "::")};
  ASSERT_TRUE(s_Result["example.com"]["A"]["@"].is_array());
  ASSERT_EQ(s_Result["example.com"]["A"]["@"].size(), 2u);
  // First should be redirect IP (192.168.1.100)
  std::string s_First{s_Result["example.com"]["A"]["@"][0].get<std::string>()};
  ASSERT_EQ(static_cast<unsigned char>(s_First[0]), 192u);
  ASSERT_EQ(static_cast<unsigned char>(s_First[1]), 168u);
}

TEST(ConfigParser_ValidateAndOptimize_A_array_invalid) {
  nlohmann::json s_Zones;
  s_Zones["example.com"]["A"]["@"] = nlohmann::json::array({"1.2.3.4", "999.999.999.999"});
  ASSERT_THROW(ConfigParser::ValidateAndOptimize(s_Zones, "0.0.0.0", "::"), std::runtime_error);
}

TEST(ConfigParser_ValidateAndOptimize_single_still_works) {
  // Ensure backwards compatibility: single values still produce strings (not arrays)
  nlohmann::json s_Zones;
  s_Zones["example.com"]["A"]["@"] = "1.2.3.4";
  nlohmann::json s_Result{ConfigParser::ValidateAndOptimize(s_Zones, "0.0.0.0", "::")};
  ASSERT_TRUE(s_Result["example.com"]["A"]["@"].is_string());
  ASSERT_EQ(s_Result["example.com"]["A"]["@"].get<std::string>().size(), 4u);
}

// ============================================================================
// NormalizeZones
// ============================================================================

TEST(ConfigParser_NormalizeZones_rejects_flat_format) {
  nlohmann::json s_Flat;
  s_Flat["example.com"]["A"]["@"] = "1.2.3.4";
  nlohmann::json s_Result{ConfigParser::NormalizeZones(s_Flat)};
  ASSERT_TRUE(s_Result.empty());
}

TEST(ConfigParser_NormalizeZones_blocked) {
  nlohmann::json s_Input;
  s_Input["zones"] = nlohmann::json::array();
  s_Input["zones"].push_back({{"zone", "evil.com."}, {"blocked", true}});
  nlohmann::json s_Result{ConfigParser::NormalizeZones(s_Input)};
  ASSERT_EQ(s_Result["evil.com"], "{{BLOCKED}}");
}

TEST(ConfigParser_NormalizeZones_root_record) {
  nlohmann::json s_Input;
  s_Input["zones"] = nlohmann::json::array();
  nlohmann::json s_Zone;
  s_Zone["zone"] = "example.com.";
  s_Zone["records"] = nlohmann::json::array();
  s_Zone["records"].push_back({{"name", "@"}, {"type", "A"}, {"ttl", 300}, {"data", "1.2.3.4"}});
  s_Input["zones"].push_back(s_Zone);

  nlohmann::json s_Result{ConfigParser::NormalizeZones(s_Input)};
  ASSERT_EQ(s_Result["example.com"]["A"]["@"], "1.2.3.4");
}

TEST(ConfigParser_NormalizeZones_wildcard) {
  nlohmann::json s_Input;
  s_Input["zones"] = nlohmann::json::array();
  nlohmann::json s_Zone;
  s_Zone["zone"] = "example.com.";
  s_Zone["records"] = nlohmann::json::array();
  s_Zone["records"].push_back({{"name", "*"}, {"type", "A"}, {"ttl", 300}, {"data", "0.0.0.0"}});
  s_Input["zones"].push_back(s_Zone);

  nlohmann::json s_Result{ConfigParser::NormalizeZones(s_Input)};
  ASSERT_EQ(s_Result["example.com"]["A"]["\\*"], "0.0.0.0");
}

TEST(ConfigParser_NormalizeZones_subdomain) {
  nlohmann::json s_Input;
  s_Input["zones"] = nlohmann::json::array();
  nlohmann::json s_Zone;
  s_Zone["zone"] = "example.com.";
  s_Zone["records"] = nlohmann::json::array();
  s_Zone["records"].push_back({{"name", "www"}, {"type", "A"}, {"ttl", 300}, {"data", "{{SELF}}"}});
  s_Input["zones"].push_back(s_Zone);

  nlohmann::json s_Result{ConfigParser::NormalizeZones(s_Input)};
  ASSERT_EQ(s_Result["example.com"]["A"]["www"], "{{SELF}}");
}

TEST(ConfigParser_NormalizeZones_dotted_subdomain) {
  nlohmann::json s_Input;
  s_Input["zones"] = nlohmann::json::array();
  nlohmann::json s_Zone;
  s_Zone["zone"] = "example.com.";
  s_Zone["records"] = nlohmann::json::array();
  s_Zone["records"].push_back({{"name", "ctest.cdn"}, {"type", "A"}, {"ttl", 300}, {"data", "1.2.3.4"}});
  s_Input["zones"].push_back(s_Zone);

  nlohmann::json s_Result{ConfigParser::NormalizeZones(s_Input)};
  // Dots should be escaped for regex matching
  ASSERT_EQ(s_Result["example.com"]["A"]["ctest\\.cdn"], "1.2.3.4");
}

TEST(ConfigParser_NormalizeZones_regex_record) {
  nlohmann::json s_Input;
  s_Input["zones"] = nlohmann::json::array();
  nlohmann::json s_Zone;
  s_Zone["zone"] = "example.com.";
  s_Zone["records"] = nlohmann::json::array();
  s_Zone["records"].push_back({{"name", "d(jp|us)01\\.update"}, {"regex", true}, {"type", "A"}, {"ttl", 300}, {"data", "{{SELF}}"}});
  s_Input["zones"].push_back(s_Zone);

  nlohmann::json s_Result{ConfigParser::NormalizeZones(s_Input)};
  // Regex patterns should be used as-is
  ASSERT_EQ(s_Result["example.com"]["A"]["d(jp|us)01\\.update"], "{{SELF}}");
}

TEST(ConfigParser_NormalizeZones_multiple_same_type) {
  // Multiple records with same type+name should be grouped into array
  nlohmann::json s_Input;
  s_Input["zones"] = nlohmann::json::array();
  nlohmann::json s_Zone;
  s_Zone["zone"] = "example.com.";
  s_Zone["records"] = nlohmann::json::array();
  s_Zone["records"].push_back({{"name", "@"}, {"type", "A"}, {"ttl", 300}, {"data", "1.2.3.4"}});
  s_Zone["records"].push_back({{"name", "@"}, {"type", "A"}, {"ttl", 300}, {"data", "5.6.7.8"}});
  s_Input["zones"].push_back(s_Zone);

  nlohmann::json s_Result{ConfigParser::NormalizeZones(s_Input)};
  ASSERT_TRUE(s_Result["example.com"]["A"]["@"].is_array());
  ASSERT_EQ(s_Result["example.com"]["A"]["@"].size(), 2u);
  ASSERT_EQ(s_Result["example.com"]["A"]["@"][0], "1.2.3.4");
  ASSERT_EQ(s_Result["example.com"]["A"]["@"][1], "5.6.7.8");
}

TEST(ConfigParser_NormalizeZones_cname) {
  nlohmann::json s_Input;
  s_Input["zones"] = nlohmann::json::array();
  nlohmann::json s_Zone;
  s_Zone["zone"] = "example.com.";
  s_Zone["records"] = nlohmann::json::array();
  s_Zone["records"].push_back({{"name", "cdn.sub"}, {"type", "CNAME"}, {"ttl", 300}, {"data", "target.cdn.net."}});
  s_Input["zones"].push_back(s_Zone);

  nlohmann::json s_Result{ConfigParser::NormalizeZones(s_Input)};
  ASSERT_EQ(s_Result["example.com"]["CNAME"]["cdn\\.sub"], "target.cdn.net.");
}

TEST(ConfigParser_NormalizeZones_default_loads) {
  // The embedded default (from s_Zones.json) should normalize and validate
  nlohmann::json defaults{ConfigParser::LoadDefault()};
  ASSERT_FALSE(defaults.empty());
  // After normalization + validation, should contain expected domains
  nlohmann::json normalized{ConfigParser::NormalizeZones(defaults)};
  ASSERT_TRUE(normalized.contains("nintendo.net"));
  ASSERT_TRUE(normalized.contains("playstation.net"));
  ASSERT_EQ(normalized["nintendo.com"], "{{BLOCKED}}");
}

// ============================================================================
// NormalizeZones - {{FORWARD}} / {{FORWARD_ALL}}
// ============================================================================

TEST(ConfigParser_NormalizeZones_forward_preserved) {
  nlohmann::json s_Input;
  s_Input["zones"] = nlohmann::json::array();
  nlohmann::json s_Zone;
  s_Zone["zone"] = "example.com.";
  s_Zone["records"] = nlohmann::json::array();
  s_Zone["records"].push_back({{"name", "api"}, {"type", "A"}, {"ttl", 300}, {"data", "{{FORWARD}}"}});
  s_Input["zones"].push_back(s_Zone);

  nlohmann::json s_Result{ConfigParser::NormalizeZones(s_Input)};
  ASSERT_EQ(s_Result["example.com"]["A"]["api"], "{{FORWARD}}");
}

TEST(ConfigParser_NormalizeZones_forward_all_subdomain) {
  nlohmann::json s_Input;
  s_Input["zones"] = nlohmann::json::array();
  nlohmann::json s_Zone;
  s_Zone["zone"] = "example.com.";
  s_Zone["records"] = nlohmann::json::array();
  s_Zone["records"].push_back({{"name", "api"}, {"type", "A"}, {"ttl", 300}, {"data", "{{FORWARD_ALL}}"}});
  s_Input["zones"].push_back(s_Zone);

  nlohmann::json s_Result{ConfigParser::NormalizeZones(s_Input)};
  // Key should be transformed to regex that matches subdomain and sub-subdomains
  ASSERT_TRUE(s_Result["example.com"]["A"].contains("(.*\\.)?api"));
  ASSERT_EQ(s_Result["example.com"]["A"]["(.*\\.)?api"], "{{FORWARD}}");
}

TEST(ConfigParser_NormalizeZones_forward_all_dotted_subdomain) {
  nlohmann::json s_Input;
  s_Input["zones"] = nlohmann::json::array();
  nlohmann::json s_Zone;
  s_Zone["zone"] = "example.com.";
  s_Zone["records"] = nlohmann::json::array();
  s_Zone["records"].push_back({{"name", "cdn.api"}, {"type", "AAAA"}, {"ttl", 300}, {"data", "{{FORWARD_ALL}}"}});
  s_Input["zones"].push_back(s_Zone);

  nlohmann::json s_Result{ConfigParser::NormalizeZones(s_Input)};
  ASSERT_TRUE(s_Result["example.com"]["AAAA"].contains("(.*\\.)?cdn\\.api"));
  ASSERT_EQ(s_Result["example.com"]["AAAA"]["(.*\\.)?cdn\\.api"], "{{FORWARD}}");
}

TEST(ConfigParser_NormalizeZones_forward_all_root) {
  nlohmann::json s_Input;
  s_Input["zones"] = nlohmann::json::array();
  nlohmann::json s_Zone;
  s_Zone["zone"] = "example.com.";
  s_Zone["records"] = nlohmann::json::array();
  s_Zone["records"].push_back({{"name", "@"}, {"type", "A"}, {"ttl", 300}, {"data", "{{FORWARD_ALL}}"}});
  s_Input["zones"].push_back(s_Zone);

  nlohmann::json s_Result{ConfigParser::NormalizeZones(s_Input)};
  // Root domain itself should be forwarded
  ASSERT_EQ(s_Result["example.com"]["A"]["@"], "{{FORWARD}}");
  // All subdomains should also be forwarded via .* wildcard
  ASSERT_TRUE(s_Result["example.com"]["A"].contains(".*"));
  ASSERT_EQ(s_Result["example.com"]["A"][".*"], "{{FORWARD}}");
}

TEST(ConfigParser_NormalizeZones_forward_all_wildcard) {
  nlohmann::json s_Input;
  s_Input["zones"] = nlohmann::json::array();
  nlohmann::json s_Zone;
  s_Zone["zone"] = "example.com.";
  s_Zone["records"] = nlohmann::json::array();
  s_Zone["records"].push_back({{"name", "*"}, {"type", "A"}, {"ttl", 300}, {"data", "{{FORWARD_ALL}}"}});
  s_Input["zones"].push_back(s_Zone);

  nlohmann::json s_Result{ConfigParser::NormalizeZones(s_Input)};
  // Wildcard should be forwarded
  ASSERT_EQ(s_Result["example.com"]["A"]["\\*"], "{{FORWARD}}");
  // Root should NOT be forwarded - "*" never matches root
  ASSERT_FALSE(s_Result["example.com"]["A"].contains("@"));
}

TEST(ConfigParser_NormalizeZones_forward_all_regex) {
  nlohmann::json s_Input;
  s_Input["zones"] = nlohmann::json::array();
  nlohmann::json s_Zone;
  s_Zone["zone"] = "example.com.";
  s_Zone["records"] = nlohmann::json::array();
  s_Zone["records"].push_back({{"name", "api[0-9]+"}, {"regex", true}, {"type", "A"}, {"ttl", 300}, {"data", "{{FORWARD_ALL}}"}});
  s_Input["zones"].push_back(s_Zone);

  nlohmann::json s_Result{ConfigParser::NormalizeZones(s_Input)};
  ASSERT_TRUE(s_Result["example.com"]["A"].contains("(.*\\.)?api[0-9]+"));
  ASSERT_EQ(s_Result["example.com"]["A"]["(.*\\.)?api[0-9]+"], "{{FORWARD}}");
}

// ============================================================================
// ValidateAndOptimize - {{FORWARD}} skipping
// ============================================================================

TEST(ConfigParser_ValidateAndOptimize_forward_skipped) {
  // FORWARD values should not be converted to binary hex
  nlohmann::json s_Zones;
  s_Zones["example.com"]["A"]["api"] = "{{FORWARD}}";
  s_Zones["example.com"]["AAAA"]["api"] = "{{FORWARD}}";

  nlohmann::json s_Result{ConfigParser::ValidateAndOptimize(s_Zones, "0.0.0.0", "::")};
  ASSERT_EQ(s_Result["example.com"]["A"]["api"], "{{FORWARD}}");
  ASSERT_EQ(s_Result["example.com"]["AAAA"]["api"], "{{FORWARD}}");
}
