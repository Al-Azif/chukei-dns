/** @file dns_edns0.h
 *  @brief EDNS0 / OPT pseudo-RR types and constants per RFC 6891.
 */

#ifndef DNS_EDNS0_H_
#define DNS_EDNS0_H_

#include <cstdint>  // uint8_t, uint16_t
#include <optional> // std::optional
#include <vector>   // std::vector

#include "constants.h"

// clang-format off

/**
 * @brief Status of EDNS0 parsing for a request packet.
 */
enum class EdnsParseStatus : uint8_t {
  None,         ///< No OPT record present (legacy query).
  Ok,           ///< Valid EDNS0/OPT parsed successfully.
  BadVersion,   ///< EDNS version > 0.
  DuplicateOpt, ///< More than one OPT in additional section.
  Malformed,    ///< OPT record has invalid wire format.
};

// clang-format on

/**
 * @brief A single EDNS0 option from OPT RDATA (RFC 6891 §6.1.2).
 */
struct EdnsOption {
  uint16_t m_Code_{0};
  std::vector<uint8_t> m_Data_;
};

/**
 * @brief Parsed EDNS0 metadata from a request OPT pseudo-RR.
 *
 * Represents the decoded OPT record fields:
 * - CLASS -> udp_payload_size (client's advertised buffer size)
 * - TTL   -> extended_rcode (high 8 bits), version, DO bit
 * - RDATA -> list of options
 */
struct EdnsData {
  uint16_t m_UdpPayloadSize_{512};
  uint8_t m_ExtendedRcode_{0};
  uint8_t m_Version_{0};
  bool m_DoBit_{false};
  std::vector<EdnsOption> m_Options_;
};

#endif
