// Self
#include "config_parser.h"

// C
#include <sys/stat.h> // stat, S_ISREG

// C++
#include <exception>  // std::exception
#include <fstream>    // std::ifstream
#include <ios>        // std::ios::in
#include <sstream>    // std::ostringstream
#include <stdexcept>  // std::runtime_error
#include <string>     // std::string
#include <vector>     // std::vector

// Other libraries
#include "nlohmann/json.hpp"

// This Project's
#include "constants.h"
#include "default_json.h" // cppcheck-suppress missingInclude
#include "utils.h"

// Logging
#include "libLog.h"

// Banned
#include "banned.h"

nlohmann::json ConfigParser::Parse(const std::string &p_Path) {
  if (p_Path.empty()) {
    logKernel(LL_Warn, "Zones path cannot be empty");
    return nlohmann::json::object(); // Return empty on error
  }
  struct stat s_Stat {};
  if (stat(p_Path.c_str(), &s_Stat) != 0) {
    logKernel(LL_Error, "Zones path does not exist: %s", p_Path.c_str());
    return nlohmann::json::object();
  }
  if (!S_ISREG(s_Stat.st_mode)) {
    logKernel(LL_Error, "Zones path is not a regular file: %s", p_Path.c_str());
    return nlohmann::json::object();
  }

  std::ifstream s_InputFile(p_Path, std::ios::in); // No need to explicitly close - RAII handles it
  if (!s_InputFile.is_open()) {
    logKernel(LL_Error, "Zones file could not be opened: %s", p_Path.c_str());
    return nlohmann::json::object();
  }

  nlohmann::json s_Zones{nlohmann::json::object()};
  try {
    s_Zones = nlohmann::json::parse(s_InputFile); // or `s_InputFile >> s_Zones;`
  } catch (const nlohmann::json::parse_error &e) {
    logKernel(LL_Error, "Error parsing zones file: %s - %s", p_Path.c_str(), e.what());
    s_Zones = nlohmann::json::object();
  } catch (const std::exception &e) {
    logKernel(LL_Error, "Unexpected error parsing zones file: %s - %s", p_Path.c_str(), e.what());
    s_Zones = nlohmann::json::object();
  }

  return s_Zones;
}

nlohmann::json ConfigParser::LoadDefault() {
  try {
    nlohmann::json s_DefaultZones{nlohmann::json::parse(g_DefaultJson)};
    logKernel(LL_Info, "Default rules loaded and processed successfully");
    return s_DefaultZones;
  } catch (const nlohmann::json::parse_error &e) {
    // This should never happen - indicates build/compilation issue
    logKernel(LL_Fatal, "Critical error: Default JSON is malformed: %s", e.what());
    throw std::runtime_error("Internal default rules are corrupted");
  } catch (const std::runtime_error &e) {
    // This indicates configuration issue (bad redirect IPs, etc.)
    logKernel(LL_Fatal, "Critical error: Default rules validation failed: %s", e.what());
    throw; // Re-throw to caller
  } catch (const std::exception &e) {
    logKernel(LL_Fatal, "Unexpected error loading default rules: %s", e.what());
    throw std::runtime_error("Failed to load internal default rules");
  }
}

nlohmann::json ConfigParser::NormalizeZones(const nlohmann::json &p_Zones) {
  if (!p_Zones.contains("zones") || !p_Zones["zones"].is_array()) {
    logKernel(LL_Error, "Zones JSON missing required 'zones' array");
    return nlohmann::json::object();
  }

  nlohmann::json s_Result{nlohmann::json::object()};

  for (const nlohmann::json &l_Zone : p_Zones["zones"]) {
    if (!l_Zone.is_object() || !l_Zone.contains("zone")) {
      continue;
    }

    std::string s_ZoneName{l_Zone["zone"].get<std::string>()};
    // Strip trailing dot
    if (!s_ZoneName.empty() && s_ZoneName.back() == '.') {
      s_ZoneName.pop_back();
    }
    if (s_ZoneName.empty()) {
      continue;
    }

    // Blocked zones
    if (l_Zone.value("blocked", false)) {
      s_Result[s_ZoneName] = "{{BLOCKED}}";
      continue;
    }

    if (!l_Zone.contains("records") || !l_Zone["records"].is_array()) {
      continue;
    }

    s_Result[s_ZoneName] = nlohmann::json::object();

    // Group records by (type, subdomain_key) to support multiple values
    // Use ordered insertion: first encounter creates the value, subsequent ones convert to array
    for (const nlohmann::json &l_Record : l_Zone["records"]) {
      if (!l_Record.is_object() || !l_Record.contains("name") || !l_Record.contains("type") || !l_Record.contains("data")) {
        continue;
      }

      const std::string s_Type{l_Record["type"].get<std::string>()};
      std::string s_Name{l_Record["name"].get<std::string>()};
      const bool s_IsRegex{l_Record.value("regex", false)};

      // Strip trailing dot from name
      if (!s_Name.empty() && s_Name.back() == '.') {
        s_Name.pop_back();
      }

      // Check if record data is a {{FORWARD_ALL}} value.
      // {{FORWARD_ALL}} is expanded into {{FORWARD}} with a regex key that also matches any sub-subdomains of the specified name.
      const bool s_IsForwardAll{l_Record["data"].is_string() && l_Record["data"].get<std::string>() == "{{FORWARD_ALL}}"};
      const nlohmann::json s_DataValue{s_IsForwardAll ? nlohmann::json("{{FORWARD}}") : l_Record["data"]};

      // Determine the subdomain key for the internal flat format.
      // Record names are zone-relative: "@" = root, "*" = wildcard, otherwise a subdomain (e.g., "www" or "ctest.cdn").
      std::string s_SubKey{};
      if (s_IsRegex) {
        // Regex records: name is the regex pattern for subdomain matching
        s_SubKey = s_IsForwardAll ? "(.*\\.)?" + s_Name : s_Name;
      } else if (s_Name == "@") {
        // Root domain
        s_SubKey = "@";
      } else if (s_Name == "*") {
        // Wildcard
        s_SubKey = "\\*";
      } else {
        // Subdomain: escape dots for regex matching in the internal format
        std::string s_Escaped{};
        for (char c : s_Name) {
          if (c == '.') {
            s_Escaped += "\\.";
          } else {
            s_Escaped += c;
          }
        }
        s_SubKey = s_IsForwardAll ? "(.*\\.)?" + s_Escaped : s_Escaped;
      }

      if (!s_Result[s_ZoneName].contains(s_Type)) {
        s_Result[s_ZoneName][s_Type] = nlohmann::json::object();
      }

      // Handle multiple records with the same type+subdomain -> array
      if (s_Result[s_ZoneName][s_Type].contains(s_SubKey)) {
        nlohmann::json &s_Existing{s_Result[s_ZoneName][s_Type][s_SubKey]};
        if (s_Existing.is_array()) {
          s_Existing.push_back(s_DataValue);
        } else {
          // Convert single value to array
          nlohmann::json s_Array{nlohmann::json::array({s_Existing, s_DataValue})};
          s_Existing = s_Array;
        }
      } else {
        s_Result[s_ZoneName][s_Type][s_SubKey] = s_DataValue;
      }

      // {{FORWARD_ALL}} on "@" also forwards all subdomains
      // Users should just not have the domain listed if they want everything forwarded, but this is an explicit behavior in case they do this by mistake or want the root to be listed for clarity.
      if (s_IsForwardAll && s_Name == "@") {
        s_Result[s_ZoneName][s_Type][".*"] = "{{FORWARD}}";
      }
    }
  }

  return s_Result;
}

nlohmann::json ConfigParser::ValidateAndOptimize(const nlohmann::json &p_Zones, const std::string &p_Ipv4Redirect, const std::string &p_Ipv6Redirect) {
  std::ostringstream s_ExceptionString{};
  nlohmann::json s_NewZones{p_Zones};

  for (const auto &[l_RootDomain, l_Records] : p_Zones.items()) {
    if (l_Records == "{{BLOCKED}}") {
      continue;
    }

    for (const auto &[l_RecordType, l_Subdomains] : l_Records.items()) {
      if (l_RecordType == "A" || l_RecordType == "AAAA") {
        for (const auto &[l_Subdomain, l_Value] : l_Subdomains.items()) {
          // Build context string for better error reporting
          const std::string s_Context{l_RootDomain + " -> " + l_RecordType + " -> " + l_Subdomain};

          // Skip {{FORWARD}} values - they are not IP addresses and must be preserved as-is
          if (l_Value.is_string() && l_Value.get<std::string>() == "{{FORWARD}}") {
            continue;
          }
          if (l_Value.is_array()) {
            bool s_HasForward{false};
            for (const nlohmann::json &el : l_Value) {
              if (el.is_string() && el.get<std::string>() == "{{FORWARD}}") {
                s_HasForward = true;
                break;
              }
            }
            if (s_HasForward) {
              continue;
            }
          }

          // Helper: validate and convert a single IP value to binary hex
          auto convertSingleValue = [&s_ExceptionString, &p_Ipv4Redirect, &p_Ipv6Redirect](const nlohmann::json &p_Val, const std::string &p_Ctx, const std::string &p_RecType) -> std::string {
            std::vector<char> s_Hex{};
            if (p_RecType == "A") {
              s_Hex.resize(Constants::Network::IPV4_BINARY_SIZE);
            } else {
              s_Hex.resize(Constants::Network::IPV6_BINARY_SIZE);
            }

            if (p_Val == "{{SELF}}") {
              if (p_RecType == "A" && Ipv4ToHex(p_Ipv4Redirect, s_Hex) != 0) {
                s_ExceptionString << "Rule '" << p_Ctx << "': Invalid IPv4 redirect address '" << p_Ipv4Redirect << "' for {{SELF}} substitution";
              } else if (p_RecType == "AAAA" && Ipv6ToHex(p_Ipv6Redirect, s_Hex) != 0) {
                s_ExceptionString << "Rule '" << p_Ctx << "': Invalid IPv6 redirect address '" << p_Ipv6Redirect << "' for {{SELF}} substitution";
              }
            } else if (p_Val == "{{BLOCKED}}") {
              // {{BLOCKED}} resolves to sinkhole addresses (0.0.0.0 / ::)
              if (p_RecType == "A") {
                Ipv4ToHex("0.0.0.0", s_Hex);
              } else {
                Ipv6ToHex("::", s_Hex);
              }
            } else {
              if (!p_Val.is_string()) {
                s_ExceptionString << "Rule '" << p_Ctx << "': Value must be a string, got " << p_Val.dump();
              } else if (p_RecType == "A" && Ipv4ToHex(p_Val, s_Hex) != 0) {
                s_ExceptionString << "Rule '" << p_Ctx << "': Invalid IPv4 address '" << p_Val.dump() << "'";
              } else if (p_RecType == "AAAA" && Ipv6ToHex(p_Val, s_Hex) != 0) {
                s_ExceptionString << "Rule '" << p_Ctx << "': Invalid IPv6 address '" << p_Val.dump() << "'";
              }
            }

            if (!s_ExceptionString.str().empty()) {
              throw std::runtime_error(s_ExceptionString.str());
            }

            return std::string(s_Hex.begin(), s_Hex.end()); };

          if (l_Value.is_array()) {
            // Multiple values for the same record (e.g., multiple A records)
            nlohmann::json s_HexArray{nlohmann::json::array()};
            for (std::size_t i{0}; i < l_Value.size(); ++i) {
              s_HexArray.push_back(convertSingleValue(l_Value[i], s_Context + "[" + std::to_string(i) + "]", l_RecordType));
            }
            s_NewZones[l_RootDomain][l_RecordType][l_Subdomain] = s_HexArray;
          } else {
            // Single value (existing behavior)
            s_NewZones[l_RootDomain][l_RecordType][l_Subdomain] = convertSingleValue(l_Value, s_Context, l_RecordType);
          }
        }
      }
    }
  }

  return s_NewZones;
}
