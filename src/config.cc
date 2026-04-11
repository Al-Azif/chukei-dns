// Self
#include "config.h"

// C
#include <arpa/inet.h>  // inet_pton
#include <netinet/in.h> // INET_ADDRSTRLEN, INET6_ADDRSTRLEN
#include <sys/socket.h> // AF_INET, AF_INET
#include <sys/stat.h>   // stat, S_ISREG

// C++
#include <cstddef>    // std::size_t
#include <cstdint>    // int32_t, uint16_t
#include <exception>  // std::exception
#include <string>     // std::string
#include <vector>     // std::vector

// Other libraries
#include "nlohmann/json.hpp"

// This Project's
#include "cmake_vars.h" // cppcheck-suppress missingInclude
#include "config_parser.h"
#include "constants.h"
#include "utils.h"

// Logging
#include "libLog.h"

// Banned
#include "banned.h"

// Global config object
Config g_Config;

void Config::Initialize(const std::string &p_ZonesPath) {
  if (FirmwareVersion().empty()) {
    (void)Useragent(Constants::App::USERAGENT_TEMPLATE_SIMPLE);
  } else {
    (void)Useragent(Constants::App::USERAGENT_TEMPLATE_FULL);
  }

  nlohmann::json s_Zones{nlohmann::json::object()};
  if (ZonesPath(p_ZonesPath) == 0) {
    s_Zones = ConfigParser::Parse(ZonesPath());
  }

  if (s_Zones.empty()) {
    ResetZonesPath();
    try {
      s_Zones = ConfigParser::LoadDefault();
    } catch (const std::exception &e) {
      logKernel(LL_Fatal, "Critical error: Built-in default JSON is corrupted: %s", e.what());
      logKernel(LL_Fatal, "This indicates a build/compilation problem");
      if (!DohOnly()) {
        return;
      }
      s_Zones = nlohmann::json::object();
    }
  }

  if (Zones(s_Zones) != 0 && !DohOnly()) {
    return;
  }

  Initialized(true);
}

///////////////////////////////////////////////////////////////////////////////
// Setters
///////////////////////////////////////////////////////////////////////////////

int Config::DnsIpAddress(const std::string &p_Input) {
  if (p_Input.empty()) {
    logKernel(LL_Warn, "DNS IP address cannot be empty");
    return 1;
  }

  char s_Buffer[Constants::Network::IPV4_BINARY_SIZE]; // Flawfinder: ignore
  char s_Buffer6[Constants::Network::IPV6_BINARY_SIZE]; // Flawfinder: ignore
  // Validate format only - ASIO checks the address family at bind time
  if (inet_pton(AF_INET, p_Input.c_str(), s_Buffer) != 1 && inet_pton(AF_INET6, p_Input.c_str(), s_Buffer6) != 1) {
    logKernel(LL_Warn, "Invalid IP address format: %s", p_Input.c_str());
    return 1;
  }

  m_DnsIpAddress_ = p_Input;
  return 0;
}

int Config::DnsPort(uint16_t p_Input) {
  if (p_Input < Constants::Network::MIN_DNS_PORT || p_Input > Constants::Network::MAX_DNS_PORT) {
    logKernel(LL_Warn, "Invalid DNS port: %u (valid range: %u-%u)", p_Input, Constants::Network::MIN_DNS_PORT, Constants::Network::MAX_DNS_PORT);
    return 1;
  }

  m_DnsPort_ = p_Input;
  return 0;
}

int Config::DohResolvers(const std::vector<std::string> &p_Input) {
  if (p_Input.empty()) {
    logKernel(LL_Warn, "DoH resolvers list cannot be empty");
    return 1;
  }

  std::vector<std::string> s_ValidResolvers;

  // DoH requires HTTPS
  const std::string s_HttpsPrefix{"https://"};
  for (const std::string &l_Resolver : p_Input) {
    if (l_Resolver.length() < s_HttpsPrefix.length() || l_Resolver.compare(0, s_HttpsPrefix.length(), s_HttpsPrefix) != 0) {
      logKernel(LL_Warn, "DoH resolver must use HTTPS: %s", l_Resolver.c_str());
      continue;
    }

    // Extract the host part from the URL
    std::string s_Host;
    std::size_t s_Start{s_HttpsPrefix.length()};
    std::size_t s_End{l_Resolver.find('/', s_Start)};
    if (s_End == std::string::npos) {
      s_Host = l_Resolver.substr(s_Start);
    } else {
      s_Host = l_Resolver.substr(s_Start, s_End - s_Start);
    }

    // Remove port if present
    std::size_t s_Colon{s_Host.find(':')};
    if (s_Colon != std::string::npos) {
      s_Host = s_Host.substr(0, s_Colon);
    }

    // Check if s_Host is IPv4 or IPv6
    char s_Buffer[Constants::Network::IPV4_BINARY_SIZE]; // Flawfinder: ignore
    char s_Buffer6[Constants::Network::IPV6_BINARY_SIZE]; // Flawfinder: ignore
    if (inet_pton(AF_INET, s_Host.c_str(), s_Buffer) != 1 && inet_pton(AF_INET6, s_Host.c_str(), s_Buffer6) != 1) {
      logKernel(LL_Warn, "DoH resolver host is not a valid IPv4 or IPv6 address: %s", s_Host.c_str());
      continue;
    }

    s_ValidResolvers.push_back(l_Resolver);
  }

  if (s_ValidResolvers.empty()) {
    logKernel(LL_Warn, "No valid DoH resolvers provided after validation");
    return 1;
  }

  m_DohResolvers_ = s_ValidResolvers;
  return 0;
}

int Config::Useragent(const std::string &p_Input) {
  if (p_Input.empty()) {
    logKernel(LL_Warn, "User agent cannot be empty");
    return 1;
  }

  std::string s_ProcessedUseragent{ProcessUseragentMask(p_Input)};
  if (s_ProcessedUseragent.empty()) {
    logKernel(LL_Warn, "User agent became empty after processing");
    return 1;
  }

  m_Useragent_ = s_ProcessedUseragent;
  return 0;
}

int Config::DohOnly(bool p_Input) {
  m_DohOnly_ = p_Input;
  return 0;
}

int Config::RedirectIpv4(const std::string &p_Input) {
  if (p_Input.empty() || p_Input.length() > Constants::Network::MAX_IPV4_STRING_LENGTH) {
    logKernel(LL_Warn, "Invalid IPv4 address length: %zu (max: %zu)", p_Input.length(), Constants::Network::MAX_IPV4_STRING_LENGTH);
    return 1;
  }

  char s_Buffer[Constants::Network::IPV4_BINARY_SIZE]; // Flawfinder: ignore
  if (inet_pton(AF_INET, p_Input.c_str(), s_Buffer) != 1) {
    logKernel(LL_Warn, "Invalid IPv4 address format: %s", p_Input.c_str());
    return 1;
  }

  m_RedirectIpv4_ = p_Input;
  return 0;
}

int Config::RedirectIpv6(const std::string &p_Input) {
  if (p_Input.empty() || p_Input.length() > Constants::Network::MAX_IPV6_STRING_LENGTH) {
    logKernel(LL_Warn, "Invalid IPv6 address length: %zu (max: %zu)", p_Input.length(), Constants::Network::MAX_IPV6_STRING_LENGTH);
    return 1;
  }

  char s_Buffer[Constants::Network::IPV6_BINARY_SIZE]; // Flawfinder: ignore
  if (inet_pton(AF_INET6, p_Input.c_str(), s_Buffer) != 1) {
    logKernel(LL_Warn, "Invalid IPv6 address format: %s", p_Input.c_str());
    return 1;
  }

  m_RedirectIpv6_ = p_Input;
  return 0;
}

int Config::DefaultTtl(int32_t p_Input) {
  if (p_Input < Constants::Network::MIN_TTL || p_Input > Constants::Network::MAX_TTL) {
    logKernel(LL_Warn, "Invalid TTL value: %d (valid range: %d-%d)", p_Input, Constants::Network::MIN_TTL, Constants::Network::MAX_TTL);
    return 1;
  }

  m_DefaultTtl_ = p_Input;
  return 0;
}

int Config::ZonesPath(const std::string &p_Input) {
  if (p_Input.empty()) {
    logKernel(LL_Warn, "Zones path cannot be empty");
    return 1;
  }
  struct stat s_Stat {};
  if (stat(p_Input.c_str(), &s_Stat) != 0) {
    logKernel(LL_Warn, "Zones path does not exist: %s", p_Input.c_str());
    return 1;
  }
  if (!S_ISREG(s_Stat.st_mode)) {
    logKernel(LL_Warn, "Zones path is not a regular file: %s", p_Input.c_str());
    return 1;
  }
  m_ZonesPath_ = p_Input;
  return 0;
}

int Config::ResetZonesPath() {
  m_ZonesPath_ = "";
  return 0;
}

int Config::Zones(const nlohmann::json &p_Input) {
  try {
    nlohmann::json s_Normalized{ConfigParser::NormalizeZones(p_Input)};
    m_Zones_ = ConfigParser::ValidateAndOptimize(s_Normalized, RedirectIpv4(), RedirectIpv6());
  } catch (const std::exception &e) {
    logKernel(LL_Error, "Invalid zones configuration: %s", e.what());
    m_Zones_ = nlohmann::json::object();
    return 1;
  }
  return 0;
}

int Config::Initialized(bool p_Input) {
  m_Initialized_ = p_Input;
  return 0;
}

int Config::CacertPath(const std::string &p_Input) {
  if (p_Input.empty()) {
    m_CacertPath_.clear();
    return 0;
  }

  struct stat s_Stat {};
  if (stat(p_Input.c_str(), &s_Stat) != 0) {
    logKernel(LL_Warn, "CA cert path does not exist: %s - will use platform default", p_Input.c_str());
    return 1;
  }
  if (!S_ISREG(s_Stat.st_mode)) {
    logKernel(LL_Warn, "CA cert path is not a regular file: %s - will use platform default", p_Input.c_str());
    return 1;
  }

  m_CacertPath_ = p_Input;
  return 0;
}

int Config::DohTimeoutMs(int p_Input) {
  if (p_Input < Constants::Network::MIN_DOH_TIMEOUT_MS || p_Input > Constants::Network::MAX_DOH_TIMEOUT_MS) {
    logKernel(LL_Warn, "Invalid DoH timeout value: %d (valid range: %d-%d)", p_Input, Constants::Network::MIN_DOH_TIMEOUT_MS, Constants::Network::MAX_DOH_TIMEOUT_MS);
    return -1;
  }
  m_DohTimeoutMs_ = p_Input;
  return 0;
}

///////////////////////////////////////////////////////////////////////////////
// Getters
///////////////////////////////////////////////////////////////////////////////

const std::string &Config::AppName() const {
  return g_AppName;
}

const std::string &Config::AppAuthor() const {
  return g_AppAuthor;
}

const std::string &Config::AppLicense() const {
  return g_AppLicense;
}

const std::string &Config::AppBuildType() const {
  return g_AppBuildType;
}

const std::string &Config::AppVersion() const {
  return g_AppVersion;
}

const std::string &Config::AppDescription() const {
  return g_AppDescription;
}

const std::string &Config::AppHomepage() const {
  return g_AppHomepage;
}

const std::string &Config::DnsIpAddress() const {
  return m_DnsIpAddress_;
}

uint16_t Config::DnsPort() const {
  return m_DnsPort_;
}

const std::vector<std::string> &Config::DohResolvers() const {
  return m_DohResolvers_;
}

std::string Config::Console() const {
#if defined(__ORBIS__)
  return "PlayStation 4";
#elif defined(__PROSPERO__)
  return "PlayStation 5";
#elif defined(_WIN32)
  return "Windows";
#elif defined(__APPLE__) && defined(__MACH__)
  return "macOS";
#elif defined(__linux__)
  return GetLinuxDistro();
#elif defined(__unix__)
  return "Unix";
#else
  return "Unknown";
#endif
}

std::string Config::FirmwareVersion() const {
#if defined(__ORBIS__)
  return GetOrbisVersion();
#elif defined(__PROSPERO__)
  return GetProsperoVersion();
#elif defined(_WIN32)
  return GetWindowsVersion();
#elif defined(__APPLE__) && defined(__MACH__)
  return GetMacOSVersion();
#elif defined(__linux__)
  return GetLinuxVersion();
#elif defined(__unix__)
  return "";
#else
  return "";
#endif
}

const std::string &Config::Useragent() const {
  return m_Useragent_;
}

bool Config::DohOnly() const {
  return m_DohOnly_;
}

const std::string &Config::RedirectIpv4() const {
  return m_RedirectIpv4_;
}

const std::string &Config::RedirectIpv6() const {
  return m_RedirectIpv6_;
}

int32_t Config::DefaultTtl() const {
  return m_DefaultTtl_;
}

const std::string &Config::ZonesPath() const {
  return m_ZonesPath_;
}

const nlohmann::json &Config::Zones() const {
  return m_Zones_;
}

bool Config::Initialized() const {
  return m_Initialized_;
}

const std::string &Config::CacertPath() const {
  return m_CacertPath_;
}

int Config::DohTimeoutMs() const {
  return m_DohTimeoutMs_;
}

///////////////////////////////////////////////////////////////////////////////
// Functions
///////////////////////////////////////////////////////////////////////////////

std::string Config::ProcessUseragentMask(const std::string &p_Input) const {
  std::string s_Result{p_Input};

  // clang-format off

  // Define mask tokens and their replacements
  const std::vector<std::pair<std::string, std::string>> s_Masks{
    {"{{APP_VERSION}}", AppVersion()},
    {"{{APP_DESCRIPTION}}", AppDescription()},
    {"{{APP_HOMEPAGE}}", AppHomepage()},
    {"{{CONSOLE}}", Console()},
    {"{{FIRMWARE_VERSION}}", FirmwareVersion()}
  };

  // clang-format on

  // Replace all mask tokens
  for (const auto &[l_Token, l_Value] : s_Masks) {
    std::size_t s_Pos{0};
    while ((s_Pos = s_Result.find(l_Token, s_Pos)) != std::string::npos) {
      s_Result.replace(s_Pos, l_Token.length(), l_Value);
      s_Pos += l_Value.length();
    }
  }

  return s_Result;
}
