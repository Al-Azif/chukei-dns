/** @file config_parser.h
 *  @brief Utilities for parsing, normalizing, and validating DNS zone configuration files.
 */

#ifndef CONFIG_PARSER_H_
#define CONFIG_PARSER_H_

#include <string> // std::string

#include "nlohmann/json.hpp"

/** @brief Functions for loading and transforming zone configuration data. */
namespace ConfigParser {

/**
 * @brief Parse a zones JSON file from disk
 * @param path Filesystem path to the JSON file.
 * @return Parsed JSON object, or an empty object on failure.
 */
[[nodiscard]] nlohmann::json Parse(const std::string &path);

/**
 * @brief Load the compiled-in default zone configuration
 * @return Parsed JSON object from the built-in default.
 * @throws std::runtime_error if the built-in JSON is corrupted.
 */
[[nodiscard]] nlohmann::json LoadDefault();

/**
 * @brief Convert user-facing zone format into the internal flat lookup format
 *
 * Transform the "zones" array (with zone/records structure) into a
 * root-domain-keyed object with record-type sub-objects and regex keys.
 *
 * @param p_Zones Raw parsed JSON from the zones file.
 * @return Normalized JSON object, or an empty object on structural errors.
 */
[[nodiscard]] nlohmann::json NormalizeZones(const nlohmann::json &p_Zones);

/**
 * @brief Validate zone entries and pre-convert IP addresses to binary hex
 *
 * Process A/AAAA records, resolving {{SELF}} and {{BLOCKED}} placeholders
 * and converting IP strings to network-order binary.
 *
 * @param p_Zones Normalized JSON zones object.
 * @param p_Ipv4Redirect IPv4 redirect address for {{SELF}} substitution.
 * @param p_Ipv6Redirect IPv6 redirect address for {{SELF}} substitution.
 * @return Optimized zones JSON with binary IP data.
 * @throws std::runtime_error on validation failure.
 */
[[nodiscard]] nlohmann::json ValidateAndOptimize(const nlohmann::json &p_Zones, const std::string &p_Ipv4Redirect, const std::string &p_Ipv6Redirect);

} // namespace ConfigParser

#endif
