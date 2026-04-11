// Self
#include "local_dns.h"

// C

// C++
#include <algorithm> // std::reverse
#include <memory>    // std::make_unique
#include <mutex>     // std::lock_guard, std::mutex
#include <regex>     // std::regex, std::regex_error, std::regex_match
#include <string>    // std::string
#include <vector>    // std::vector

// Other libraries

// This Project's
#include "config.h"
#include "constants.h"
#include "dns_parser.h"
#include "dns_response.h"

// Logging
#include "libLog.h"

// Banned
#include "banned.h"

std::unordered_map<std::string, std::unique_ptr<std::regex>> LocalDns::m_RegexCache_;
std::mutex LocalDns::m_RegexCacheMutex_;

namespace {
// Check if a JSON value represents a {{FORWARD}} directive.
bool IsForwardValue(const nlohmann::json &p_Value) {
  return p_Value.is_string() && p_Value.get<std::string>() == "{{FORWARD}}";
}

// Expand a looked-up record value into AnswerRecords.
// If p_Data is an array, each element becomes a separate answer (multiple records).
// Otherwise, the single value becomes one answer.
void ExpandAnswerRecords(const std::string &p_Type, const nlohmann::json &p_Data, const std::string &p_Name, std::vector<DnsResponse::AnswerRecord> &p_Answers) {
  if (p_Data.is_array()) {
    for (const nlohmann::json &l_Element : p_Data) {
      p_Answers.push_back({p_Type, l_Element, p_Name});
    }
  } else {
    p_Answers.push_back({p_Type, p_Data, p_Name});
  }
}

// Build and send a response for data that may be a single value or an array.
// Returns 0 on success, -1 on failure.
int DispatchSingleOrMulti(const std::string &p_RecordType, const DnsRequestPacket &p_Packet, const nlohmann::json &p_Data, std::vector<char> &p_Output) {
  if (p_Data.is_array()) {
    std::vector<DnsResponse::AnswerRecord> s_Answers{};
    for (const nlohmann::json &l_Element : p_Data) {
      s_Answers.push_back({p_RecordType, l_Element, ""});
    }
    return DnsResponse::MultiAnswer(p_Packet, s_Answers, p_Output);
  }
  return DnsResponse::CallResponseFunction(p_RecordType, p_Packet, p_Data, p_Output);
}
} // namespace

bool LocalDns::SafeRegexMatch(const std::string &p_Input, const std::string &p_Pattern) {
  try {
    std::lock_guard<std::mutex> s_Lock(m_RegexCacheMutex_);

    // Evict cache if it grows too large (prevent unbounded growth)
    if (m_RegexCache_.size() >= Constants::Dns::DNS_REGEX_CACHE_SIZE) {
      m_RegexCache_.clear();
    }

    auto [s_Iterator, s_Inserted] = m_RegexCache_.try_emplace(p_Pattern, nullptr);
    if (s_Inserted) {
      s_Iterator->second = std::make_unique<std::regex>(p_Pattern);
    }
    return std::regex_match(p_Input, *(s_Iterator->second));
  } catch (const std::regex_error &e) {
    logKernel(LL_Error, "Invalid regex pattern '%s': %s", p_Pattern.c_str(), e.what());
    return false;
  }
}

std::string LocalDns::ReverseIpv4Components(const std::string &p_Input) {
  if (p_Input.empty()) {
    return "";
  }

  std::vector<std::string> s_Parts{};
  std::size_t s_Start{0};
  std::size_t s_Pos{0};

  while ((s_Pos = p_Input.find('.', s_Start)) != std::string::npos) {
    s_Parts.push_back(p_Input.substr(s_Start, s_Pos - s_Start));
    s_Start = s_Pos + 1;
  }
  if (s_Start <= p_Input.size()) {
    s_Parts.push_back(p_Input.substr(s_Start));
  }

  std::string s_Reversed{};
  for (std::vector<std::string>::reverse_iterator l_Index{s_Parts.rbegin()}; l_Index != s_Parts.rend(); ++l_Index) {
    if (!s_Reversed.empty()) {
      s_Reversed += ".";
    }
    s_Reversed += *l_Index;
  }

  return s_Reversed;
}

std::string LocalDns::ReverseIpv6Components(const std::string &p_Input) {
  if (p_Input.empty()) {
    return "";
  }

  // Split by dots and reverse the order
  std::vector<std::string> s_Parts{};
  std::size_t s_Start{0};
  std::size_t s_Pos{0};

  while ((s_Pos = p_Input.find('.', s_Start)) != std::string::npos) {
    s_Parts.push_back(p_Input.substr(s_Start, s_Pos - s_Start));
    s_Start = s_Pos + 1;
  }
  if (s_Start <= p_Input.size()) {
    s_Parts.push_back(p_Input.substr(s_Start));
  }

  // Reverse the parts to get correct IPv6 order
  std::reverse(s_Parts.begin(), s_Parts.end());

  // Group every 4 hex digits into IPv6 groups (each group is 4 hex digits)
  std::vector<std::string> s_Groups{};
  for (std::size_t l_Index{0}; l_Index < s_Parts.size(); l_Index += 4) {
    std::string s_Group{};
    for (std::size_t l_Inner{0}; l_Inner < 4 && (l_Index + l_Inner) < s_Parts.size(); ++l_Inner) {
      s_Group += s_Parts[l_Index + l_Inner];
    }
    s_Groups.push_back(s_Group);
  }

  // Join with colons to form IPv6 address
  std::string s_Ipv6{};
  for (std::size_t l_Index{0}; l_Index < s_Groups.size(); ++l_Index) {
    if (l_Index > 0) {
      s_Ipv6 += ":";
    }
    s_Ipv6 += s_Groups[l_Index];
  }

  return s_Ipv6;
}

std::string LocalDns::SimplifyIpv6(const std::string &p_Input) {
  // Split by ':' and strip leading zeros in each group
  std::vector<std::string> s_Groups{};
  std::size_t s_Start{0};
  std::size_t s_Pos{0};

  while ((s_Pos = p_Input.find(':', s_Start)) != std::string::npos) {
    std::string s_Group{p_Input.substr(s_Start, s_Pos - s_Start)};
    std::size_t s_FirstNonZero{s_Group.find_first_not_of('0')};
    s_Groups.push_back(s_FirstNonZero == std::string::npos ? "0" : s_Group.substr(s_FirstNonZero));
    s_Start = s_Pos + 1;
  }
  if (s_Start <= p_Input.size()) {
    std::string s_Group{p_Input.substr(s_Start)};
    std::size_t s_FirstNonZero{s_Group.find_first_not_of('0')};
    s_Groups.push_back(s_FirstNonZero == std::string::npos ? "0" : s_Group.substr(s_FirstNonZero));
  }

  // Find the longest sequence of consecutive "0" groups
  std::size_t s_MaxZeroStart{0}, s_MaxZeroLength{0};
  std::size_t s_CurrentZeroStart{0}, s_CurrentZeroLength{0};

  for (std::size_t l_Index{0}; l_Index < s_Groups.size(); ++l_Index) {
    if (s_Groups[l_Index] == "0") {
      if (s_CurrentZeroLength == 0) {
        s_CurrentZeroStart = l_Index;
      }
      s_CurrentZeroLength++;
    } else {
      if (s_CurrentZeroLength > s_MaxZeroLength) {
        s_MaxZeroStart = s_CurrentZeroStart;
        s_MaxZeroLength = s_CurrentZeroLength;
      }
      s_CurrentZeroLength = 0;
    }
  }
  if (s_CurrentZeroLength > s_MaxZeroLength) {
    s_MaxZeroStart = s_CurrentZeroStart;
    s_MaxZeroLength = s_CurrentZeroLength;
  }

  // Build output: compress longest zero run (>= 2) with ::
  if (s_MaxZeroLength < 2) {
    std::string s_Result{};
    for (std::size_t l_Index{0}; l_Index < s_Groups.size(); ++l_Index) {
      if (l_Index > 0) {
        s_Result += ":";
      }
      s_Result += s_Groups[l_Index];
    }
    return s_Result;
  }

  std::string s_Result{};
  for (std::size_t l_Index{0}; l_Index < s_Groups.size(); ++l_Index) {
    if (l_Index == s_MaxZeroStart) {
      s_Result += "::";
      l_Index += s_MaxZeroLength - 1;
    } else {
      if (!s_Result.empty() && !(s_Result.size() >= 2 && s_Result[s_Result.size() - 1] == ':' && s_Result[s_Result.size() - 2] == ':')) {
        s_Result += ":";
      }
      s_Result += s_Groups[l_Index];
    }
  }

  return s_Result;
}

bool LocalDns::LookupLocalRecord(const std::string &p_Domain, const std::string &p_RecordType, nlohmann::json &p_Data) {
  if (p_Domain.empty() || p_RecordType.empty()) {
    return false;
  }

  // Strip trailing dot if present
  std::string s_Domain{p_Domain};
  if (!s_Domain.empty() && s_Domain.back() == '.') {
    s_Domain.pop_back();
  }
  if (s_Domain.empty()) {
    return false;
  }

  // Split domain into root domain (last two parts) and subdomain (rest)
  std::string s_RootDomain{};
  std::string s_SubDomain{};
  {
    std::vector<std::string> s_Parts{};
    std::size_t s_Start{0};
    std::size_t s_Pos{0};
    while ((s_Pos = s_Domain.find('.', s_Start)) != std::string::npos) {
      s_Parts.push_back(s_Domain.substr(s_Start, s_Pos - s_Start));
      s_Start = s_Pos + 1;
    }
    if (s_Start <= s_Domain.size()) {
      s_Parts.push_back(s_Domain.substr(s_Start));
    }
    if (s_Parts.size() < 2) {
      return false;
    }
    s_RootDomain = s_Parts[s_Parts.size() - 2] + "." + s_Parts[s_Parts.size() - 1];
    for (std::size_t l_Index{0}; l_Index + 2 < s_Parts.size(); ++l_Index) {
      if (!s_SubDomain.empty()) {
        s_SubDomain += ".";
      }
      s_SubDomain += s_Parts[l_Index];
    }
  }

  const nlohmann::json &s_Zones{g_Config.Zones()};
  if (s_Zones.find(s_RootDomain) == s_Zones.end()) {
    return false;
  }

  const nlohmann::json &s_DomainConfig{s_Zones[s_RootDomain]};
  if (!s_DomainConfig.is_object() || !s_DomainConfig.contains(p_RecordType)) {
    return false;
  }
  if (!s_DomainConfig[p_RecordType].is_object()) {
    return false;
  }

  const nlohmann::json &s_Records{s_DomainConfig[p_RecordType]};

  if (s_SubDomain.empty()) {
    if (s_Records.contains("@")) {
      if (IsForwardValue(s_Records["@"])) {
        return false;
      }
      p_Data = s_Records["@"];
      return true;
    }
    return false;
  }

  // Check subdomains via regex match
  for (const auto &[l_Key, l_Value] : s_Records.items()) {
    if (SafeRegexMatch(s_SubDomain, l_Key)) {
      if (IsForwardValue(l_Value)) {
        return false;
      }
      p_Data = l_Value;
      return true;
    }
  }

  // Wildcard fallback
  if (s_Records.contains("\\*")) {
    if (IsForwardValue(s_Records["\\*"])) {
      return false;
    }
    p_Data = s_Records["\\*"];
    return true;
  }

  return false;
}

int LocalDns::CheckLocalMatch(const DnsParser &p_Parser, std::vector<char> &p_Output) {
  try {
    const std::string &s_RootDomain{p_Parser.RootDomain()};
    const std::string &s_SubDomain{p_Parser.SubDomain()};
    const std::string &s_RecordType{p_Parser.RecordType()};

    if (s_RootDomain.empty()) {
      logKernel(LL_Debug, "Empty root domain, cannot process");
      return -1;
    }

    if (s_RecordType.empty()) {
      logKernel(LL_Debug, "Empty record type, cannot process");
      return -1;
    }

    const nlohmann::json &s_Zones{g_Config.Zones()};
    if (s_Zones.find(s_RootDomain) == s_Zones.end()) {
      logKernel(LL_Debug, "No local record found (Domain not present)");
      return -1;
    }

    const nlohmann::json &s_DomainConfig{s_Zones[s_RootDomain]};

    // Check if entire domain is blocked *first*
    // The domain being completely blocked should overrule everything
    if (s_DomainConfig.is_string() && s_DomainConfig == "{{BLOCKED}}") {
      DnsResponse::CallResponseFunction("NXDOMAIN", p_Parser.Packet(), s_RootDomain, p_Output);
      logKernel(LL_Debug, "Entire domain blocked (NXDOMAIN)");
      return 0;
    }

    if (!s_DomainConfig.is_object()) {
      logKernel(LL_Error, "Invalid domain configuration format");
      return -1;
    }

    // Check if the request has a PTR entry
    // This is the IP to domain name lookup, we'll handle it before the rest because of how we do it
    if (s_RecordType == "PTR") {
      std::string s_FormattedSubDomain{};
      if (s_RootDomain == "in-addr.arpa") {
        s_FormattedSubDomain = ReverseIpv4Components(s_SubDomain);
      } else if (s_RootDomain == "ip6.arpa") {
        s_FormattedSubDomain = SimplifyIpv6(ReverseIpv6Components(s_SubDomain));
      } else {
        // Not a reverse lookup zone - fall through to DoH forwarding
        logKernel(LL_Debug, "PTR query for non-arpa domain, forwarding");
        return -1;
      }

      if (s_DomainConfig.contains(s_FormattedSubDomain)) {
        DnsResponse::CallResponseFunction("PTR", p_Parser.Packet(), s_DomainConfig[s_FormattedSubDomain], p_Output);
        logKernel(LL_Debug, "Found record (PTR)");
        return 0;
      } else {
        // No matching PTR record, forward the request
        logKernel(LL_Debug, "No local record found (PTR)");
        return -1;
      }
    }

    // Check if the request has a CNAME entry
    // CNAMEs "redirect" a domain to another name.
    // Per RFC 1034 §3.6.2, CNAME responses should include the resolved record
    // for the canonical name when available locally (recursive CNAME resolution).
    // Skip CNAME lookup when the query is specifically for CNAME records.
    if (s_RecordType != "CNAME" && s_DomainConfig.contains("CNAME")) {
      const nlohmann::json &s_CnameObj{s_DomainConfig["CNAME"]};
      nlohmann::json s_CnameTarget{};
      bool s_CnameFound{false};

      // Check root domain CNAME
      if (s_SubDomain.empty()) {
        if (s_CnameObj.contains("@") && !IsForwardValue(s_CnameObj["@"])) {
          s_CnameTarget = s_CnameObj["@"];
          s_CnameFound = true;
        }
      } else {
        // Check subdomain via regex match
        for (const auto &[l_Key, l_Value] : s_CnameObj.items()) {
          if (!IsForwardValue(l_Value) && SafeRegexMatch(s_SubDomain, l_Key)) {
            s_CnameTarget = l_Value;
            s_CnameFound = true;
            break;
          }
        }
        // Wildcard CNAME fallback
        if (!s_CnameFound && s_CnameObj.contains("\\*") && !IsForwardValue(s_CnameObj["\\*"])) {
          s_CnameTarget = s_CnameObj["\\*"];
          s_CnameFound = true;
        }
      }

      if (s_CnameFound) {
        // Follow CNAME chain and resolve to the queried record type if possible.
        // RFC 1034 limits chain depth; we use 8 to prevent infinite loops.
        std::vector<DnsResponse::AnswerRecord> s_Answers{};
        std::string s_CurrentTarget{s_CnameTarget.get<std::string>()};

        // Add the initial CNAME answer (NAME = question pointer)
        s_Answers.push_back({"CNAME", s_CnameTarget, ""});

        for (int s_Depth{0}; s_Depth < Constants::Dns::DNS_MAX_CNAME_DEPTH; ++s_Depth) {
          // Check if target has a CNAME (chain)
          nlohmann::json s_ChainData{};
          if (LookupLocalRecord(s_CurrentTarget, "CNAME", s_ChainData)) {
            s_Answers.push_back({"CNAME", s_ChainData, s_CurrentTarget});
            s_CurrentTarget = s_ChainData.get<std::string>();
            continue;
          }

          // Try to resolve the final target to the originally queried type
          if (s_RecordType != "*") {
            nlohmann::json s_ResolvedData{};
            if (LookupLocalRecord(s_CurrentTarget, s_RecordType, s_ResolvedData)) {
              ExpandAnswerRecords(s_RecordType, s_ResolvedData, s_CurrentTarget, s_Answers);
            }
          }
          break;
        }

        DnsResponse::MultiAnswer(p_Parser.Packet(), s_Answers, p_Output);
        logKernel(LL_Debug, "Found record (CNAME chain, %zu answers)", s_Answers.size());
        return 0;
      }
    }

    // ANY (type *) query: return ALL matching record types for this domain.
    if (s_RecordType == "*") {
      static const std::vector<std::string> s_AnyTypes{"A", "AAAA", "CNAME", "NS", "MX", "TXT", "SRV", "SOA"};
      std::vector<DnsResponse::AnswerRecord> s_Answers{};

      for (const std::string &l_Type : s_AnyTypes) {
        if (!s_DomainConfig.contains(l_Type) || !s_DomainConfig[l_Type].is_object()) {
          continue;
        }
        const nlohmann::json &s_Records{s_DomainConfig[l_Type]};

        if (s_SubDomain.empty()) {
          if (s_Records.contains("@") && !IsForwardValue(s_Records["@"])) {
            ExpandAnswerRecords(l_Type, s_Records["@"], "", s_Answers);
          }
        } else {
          bool s_Found{false};
          for (const auto &[l_Key, l_Value] : s_Records.items()) {
            if (SafeRegexMatch(s_SubDomain, l_Key)) {
              if (!IsForwardValue(l_Value)) {
                ExpandAnswerRecords(l_Type, l_Value, "", s_Answers);
              }
              s_Found = true;
              break;
            }
          }
          if (!s_Found && s_Records.contains("\\*") && !IsForwardValue(s_Records["\\*"])) {
            ExpandAnswerRecords(l_Type, s_Records["\\*"], "", s_Answers);
          }
        }
      }

      if (s_Answers.empty()) {
        logKernel(LL_Debug, "No local records found for ANY query");
        return -1;
      }

      DnsResponse::MultiAnswer(p_Parser.Packet(), s_Answers, p_Output);
      logKernel(LL_Debug, "Found %zu records for ANY query", s_Answers.size());
      return 0;
    }

    if (!s_DomainConfig.contains(s_RecordType)) {
      logKernel(LL_Debug, "No record type '%s' found", s_RecordType.c_str());
      return -1;
    }
    if (!s_DomainConfig[s_RecordType].is_object()) {
      logKernel(LL_Debug, "Record type '%s' is not an object", s_RecordType.c_str());
      return -1;
    }

    // Check if the request is for the root domain
    if (s_SubDomain.empty()) {
      if (s_DomainConfig[s_RecordType].contains("@")) {
        if (IsForwardValue(s_DomainConfig[s_RecordType]["@"])) {
          logKernel(LL_Debug, "Forwarding root domain ({{FORWARD}})");
          return -1;
        }
        // Bare root domain is set and has a value, use it
        DispatchSingleOrMulti(s_RecordType, p_Parser.Packet(), s_DomainConfig[s_RecordType]["@"], p_Output);
        logKernel(LL_Debug, "Found record (Root domain)");
        return 0;
      } else {
        // Bare root domain is NOT set, forward the request
        logKernel(LL_Debug, "No local record found (Root domain)");
        return -1;
      }
    }

    // Check subdomains for a match (Should exclude PTR/CNAME matches as they are checked above)
    const nlohmann::json &s_SubdomainArray{s_DomainConfig[s_RecordType]};
    for (const auto &[l_Key, l_Value] : s_SubdomainArray.items()) {
      // logKernel(LL_Debug, "subdomain regex: %s", l_Key.c_str());
      if (SafeRegexMatch(s_SubDomain, l_Key)) {
        if (IsForwardValue(l_Value)) {
          logKernel(LL_Debug, "Forwarding subdomain ({{FORWARD}})");
          return -1;
        }
        DispatchSingleOrMulti(s_RecordType, p_Parser.Packet(), l_Value, p_Output);
        logKernel(LL_Debug, "Found record (Subdomain)");
        return 0;
      }
    }

    // Wildcard subdomain fallback
    if (s_SubdomainArray.contains("\\*")) {
      if (IsForwardValue(s_SubdomainArray["\\*"])) {
        logKernel(LL_Debug, "Forwarding wildcard ({{FORWARD}})");
        return -1;
      }
      DispatchSingleOrMulti(s_RecordType, p_Parser.Packet(), s_SubdomainArray["\\*"], p_Output);
      logKernel(LL_Debug, "Found record (Wildcard)");
      return 0;
    }

    logKernel(LL_Debug, "No local record found (Default)");
    return -1;
  } catch (const nlohmann::json::exception &e) {
    logKernel(LL_Error, "JSON error in CheckLocalMatch: %s", e.what());
    return -1;
  } catch (const std::exception &e) {
    logKernel(LL_Error, "Exception in CheckLocalMatch: %s", e.what());
    return -1;
  }
}
