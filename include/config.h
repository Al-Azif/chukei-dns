/** @file config.h
 *  @brief Global application configuration class managing DNS server settings, DoH resolvers, and zone data.
 */

#ifndef CONFIG_H_
#define CONFIG_H_

#include <netinet/in.h> // INET_ADDRSTRLEN, INET6_ADDRSTRLEN

#include <cstdint> // int32_t, uint16_t
#include <string>  // std::string
#include <vector>  // std::vector

#include "nlohmann/json.hpp"

#include "constants.h"

/**
 * @brief Global runtime configuration for the DNS relay server
 *
 * Holds DNS listen address/port, DoH resolver URLs, user-agent string,
 * redirect addresses, TTL, zones data, and application metadata.
 * A single global instance (g_Config) is initialized at startup and
 * treated as read-only for the lifetime of the server.
 */
class Config {
public:
  /**
   * @brief Initialize the configuration by loading and validating zone data
   * @param p_ZonesPath Filesystem path to the zones JSON file.
   */
  void Initialize(const std::string &p_ZonesPath);

  // Setters

  /**
   * @brief Set the DNS server listen IP address
   * @param p_Input IPv4 or IPv6 address string.
   * @return 0 on success, non-zero on invalid input.
   */
  [[nodiscard]] int DnsIpAddress(const std::string &p_Input);

  /**
   * @brief Set the DNS server listen port
   * @param p_Input Port number in the valid range.
   * @return 0 on success, non-zero on invalid input.
   */
  [[nodiscard]] int DnsPort(uint16_t p_Input);

  /**
   * @brief Set the list of DNS-over-HTTPS resolver URLs
   * @param p_Input Vector of HTTPS URLs; only valid entries are kept.
   * @return 0 on success, non-zero if no valid resolvers remain.
   */
  [[nodiscard]] int DohResolvers(const std::vector<std::string> &p_Input);

  /**
   * @brief Set the HTTP User-Agent string used for DoH requests
   * @param p_Input Raw or template user-agent string.
   * @return 0 on success, non-zero on invalid input.
   */
  [[nodiscard]] int Useragent(const std::string &p_Input);

  /**
   * @brief Enable or disable DoH-only mode (no local zone responses)
   * @param p_Input true to enable DoH-only mode.
   * @return Always returns 0.
   */
  int DohOnly(bool p_Input);

  /**
   * @brief Set the IPv4 redirect (sinkhole) address for matched domains
   * @param p_Input Valid IPv4 address string.
   * @return 0 on success, non-zero on invalid input.
   */
  [[nodiscard]] int RedirectIpv4(const std::string &p_Input);

  /**
   * @brief Set the IPv6 redirect (sinkhole) address for matched domains
   * @param p_Input Valid IPv6 address string.
   * @return 0 on success, non-zero on invalid input.
   */
  [[nodiscard]] int RedirectIpv6(const std::string &p_Input);

  /**
   * @brief Set the default TTL for locally-generated DNS responses
   * @param p_Input TTL value in seconds within the valid range.
   * @return 0 on success, non-zero on invalid input.
   */
  [[nodiscard]] int DefaultTtl(int32_t p_Input);

  /**
   * @brief Set the filesystem path to the zones JSON file
   * @param p_Input Path to an existing regular file.
   * @return 0 on success, non-zero if the path is invalid.
   */
  [[nodiscard]] int ZonesPath(const std::string &p_Input);

  /**
   * @brief Reset the zones path to an empty string
   * @return Always returns 0.
   */
  int ResetZonesPath();

  /**
   * @brief Set the zones configuration from parsed JSON
   * @param p_Input JSON object containing zone definitions.
   * @return 0 on success, non-zero if normalization or validation fails.
   */
  [[nodiscard]] int Zones(const nlohmann::json &p_Input);

  /**
   * @brief Mark the configuration as fully initialized
   * @param p_Input true if initialization succeeded.
   * @return Always returns 0.
   */
  int Initialized(bool p_Input);

  /**
   * @brief Set the filesystem path to the CA certificate bundle for TLS verification
   * @param p_Input Path to a PEM-format CA certificate file, or empty to use platform defaults.
   * @return Always returns 0.
   */
  int CacertPath(const std::string &p_Input);

  /**
   * @brief Set the total timeout budget in milliseconds for DoH resolution
   * @param p_Input Timeout in milliseconds within the valid range.
   * @return 0 on success, non-zero on invalid input.
   */
  [[nodiscard]] int DohTimeoutMs(int p_Input);

  // Getters

  /** @brief Get the application display name. */
  [[nodiscard]] const std::string &AppName() const;
  /** @brief Get the application author. */
  [[nodiscard]] const std::string &AppAuthor() const;
  /** @brief Get the application license identifier. */
  [[nodiscard]] const std::string &AppLicense() const;
  /** @brief Get the build type (Debug/Release). */
  [[nodiscard]] const std::string &AppBuildType() const;
  /** @brief Get the application version string. */
  [[nodiscard]] const std::string &AppVersion() const;
  /** @brief Get the application description. */
  [[nodiscard]] const std::string &AppDescription() const;
  /** @brief Get the application homepage URL. */
  [[nodiscard]] const std::string &AppHomepage() const;

  /** @brief Get the configured DNS listen IP address. */
  [[nodiscard]] const std::string &DnsIpAddress() const;
  /** @brief Get the configured DNS listen port. */
  [[nodiscard]] uint16_t DnsPort() const;

  /** @brief Get the list of DoH resolver URLs. */
  [[nodiscard]] const std::vector<std::string> &DohResolvers() const;

  /** @brief Get the detected console/platform name. */
  [[nodiscard]] std::string Console() const;
  /** @brief Get the detected firmware/OS version string. */
  [[nodiscard]] std::string FirmwareVersion() const;
  /** @brief Get the processed User-Agent string. */
  [[nodiscard]] const std::string &Useragent() const;

  /** @brief Check if the server is in DoH-only mode. */
  [[nodiscard]] bool DohOnly() const;

  /** @brief Get the IPv4 redirect address. */
  [[nodiscard]] const std::string &RedirectIpv4() const;
  /** @brief Get the IPv6 redirect address. */
  [[nodiscard]] const std::string &RedirectIpv6() const;

  /** @brief Get the default TTL in seconds. */
  [[nodiscard]] int32_t DefaultTtl() const;

  /** @brief Get the zones JSON file path, or empty if using defaults. */
  [[nodiscard]] const std::string &ZonesPath() const;

  /** @brief Get the normalized and validated zones JSON object. */
  [[nodiscard]] const nlohmann::json &Zones() const;

  /** @brief Check if the configuration was successfully initialized. */
  [[nodiscard]] bool Initialized() const;

  /** @brief Get the CA certificate bundle path (empty string means use platform defaults). */
  [[nodiscard]] const std::string &CacertPath() const;

  /** @brief Get the total DoH timeout budget in milliseconds. */
  [[nodiscard]] int DohTimeoutMs() const;

private:
  std::string m_DnsIpAddress_{Constants::Network::DEFAULT_DNS_IP};
  uint16_t m_DnsPort_{Constants::Network::DEFAULT_DNS_PORT};

  std::vector<std::string> m_DohResolvers_{{Constants::Doh::CLOUDFLARE_DOH_PRIMARY, Constants::Doh::CLOUDFLARE_DOH_SECONDARY}};

  std::string m_Useragent_{};

  bool m_DohOnly_{false};

  std::string m_RedirectIpv4_{Constants::Network::DEFAULT_IPV4_REDIRECT};
  std::string m_RedirectIpv6_{Constants::Network::DEFAULT_IPV6_REDIRECT};

  int32_t m_DefaultTtl_{Constants::Network::DEFAULT_TTL};

  std::string m_ZonesPath_{};

  nlohmann::json m_Zones_{nlohmann::json::object()};

  bool m_Initialized_{false};

  std::string m_CacertPath_{};

  int m_DohTimeoutMs_{Constants::Network::DEFAULT_DOH_TIMEOUT_MS};

  /**
   * @brief Expand template tokens in a user-agent string
   * @param p_Input Raw user-agent string with {{TOKEN}} placeholders.
   * @return Fully expanded user-agent string.
   */
  std::string ProcessUseragentMask(const std::string &p_Input) const;
};

/**
 * @brief Global configuration singleton.
 *
 * Initialized once at startup before the server loop begins and treated
 * as read-only thereafter. No mutex is required under the current design.
 *
 * @warning If hot-reload is ever added, all read paths must be synchronized.
 */
extern Config g_Config;

#endif
