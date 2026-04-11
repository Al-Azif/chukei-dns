/** @file dns_response.h
 *  @brief Functions for constructing DNS wire-format responses for all supported record types.
 */

#ifndef DNS_RESPONSE_H_
#define DNS_RESPONSE_H_

#include <cstddef> // std::size_t
#include <string>  // std::string
#include <vector>  // std::vector

#include "nlohmann/json.hpp"

#include "dns_edns0.h"
#include "dns_packet.h"

/**
 * @brief DNS wire-format response packet construction for all supported record types
 *
 * Provide functions for each supported record type (A, AAAA, CNAME, etc.)
 * and error response codes (FORMERR, SERVFAIL, NXDOMAIN, etc.), as well as
 * multi-answer support for responses containing multiple resource records.
 */
namespace DnsResponse {

/**
 * @brief Encode a domain name label vector into DNS wire-format question encoding
 * @param p_Input Vector of labels (e.g., {"www", "example", "com"}).
 * @param p_Output Output vector receiving the encoded bytes.
 * @return 0 on success, -1 on error.
 */
int DomainToQuestion(const std::vector<std::string> &p_Input, std::vector<char> &p_Output);

/**
 * @brief Encode a dot-separated domain string into DNS wire-format question encoding
 * @param p_Input Domain name string (e.g., "www.example.com").
 * @param p_Output Output vector receiving the encoded bytes.
 * @return 0 on success, -1 on error.
 */
int DomainToQuestion(const std::string &p_Input, std::vector<char> &p_Output);

/**
 * @brief Construct a FORMERR (format error) response from a parsed packet
 * @param p_Packet The original request packet.
 * @param p_Output Output vector receiving the wire-format response.
 * @return 0 on success, -1 on error.
 */
int FORMERR(const DnsRequestPacket &p_Packet, std::vector<char> &p_Output);

/**
 * @brief Construct a FORMERR response from raw bytes when parsing has failed
 * @param p_RawData  Pointer to the raw query bytes (may be partially valid).
 * @param p_DataSize Length of the raw data.
 * @param p_Output   Output vector receiving the wire-format response.
 * @return 0 on success, -1 on error.
 */
int FORMERR(const char *p_RawData, std::size_t p_DataSize, std::vector<char> &p_Output);

/**
 * @brief Construct a SERVFAIL (server failure) response
 * @param p_Packet The original request packet.
 * @param p_Output Output vector receiving the wire-format response.
 * @return 0 on success, -1 on error.
 */
int SERVFAIL(const DnsRequestPacket &p_Packet, std::vector<char> &p_Output);

/**
 * @brief Construct an NXDOMAIN (non-existent domain) response
 *
 * Optionally include a synthetic SOA record in the authority section
 * for negative caching per RFC 2308.
 *
 * @param p_Packet The original request packet.
 * @param p_Output Output vector receiving the wire-format response.
 * @param p_Zone   Zone name for the SOA authority record; empty to omit.
 * @return 0 on success, -1 on error.
 */
int NXDOMAIN(const DnsRequestPacket &p_Packet, std::vector<char> &p_Output, const std::string &p_Zone = "");

/**
 * @brief Construct a NOTIMP (not implemented) response
 * @param p_Packet The original request packet.
 * @param p_Output Output vector receiving the wire-format response.
 * @return 0 on success, -1 on error.
 */
int NOTIMP(const DnsRequestPacket &p_Packet, std::vector<char> &p_Output);

/**
 * @brief Construct a REFUSED response
 * @param p_Packet The original request packet.
 * @param p_Output Output vector receiving the wire-format response.
 * @return 0 on success, -1 on error.
 */
int REFUSED(const DnsRequestPacket &p_Packet, std::vector<char> &p_Output);

/**
 * @brief Construct an A record response with an IPv4 address
 * @param p_Packet  The original request packet.
 * @param p_Ipv4Hex Four-byte binary IPv4 address.
 * @param p_Output  Output vector receiving the wire-format response.
 * @return 0 on success, -1 on error.
 */
int A(const DnsRequestPacket &p_Packet, const std::string &p_Ipv4Hex, std::vector<char> &p_Output);

/**
 * @brief Construct an NS record response
 * @param p_Packet The original request packet.
 * @param p_Domain Name server domain name.
 * @param p_Output Output vector receiving the wire-format response.
 * @return 0 on success, -1 on error.
 */
int NS(const DnsRequestPacket &p_Packet, const std::string &p_Domain, std::vector<char> &p_Output);

/**
 * @brief Construct a CNAME record response
 * @param p_Packet The original request packet.
 * @param p_Domain Canonical domain name.
 * @param p_Output Output vector receiving the wire-format response.
 * @return 0 on success, -1 on error.
 */
int CNAME(const DnsRequestPacket &p_Packet, const std::string &p_Domain, std::vector<char> &p_Output);

/**
 * @brief Construct a SOA record response
 * @param p_Packet The original request packet.
 * @param p_Data   JSON object with keys: primary, admin, serial, refresh, retry, expire, minimum.
 * @param p_Output Output vector receiving the wire-format response.
 * @return 0 on success, -1 on error.
 */
int SOA(const DnsRequestPacket &p_Packet, const nlohmann::json &p_Data, std::vector<char> &p_Output);

/**
 * @brief Construct a PTR record response
 * @param p_Packet The original request packet.
 * @param p_Domain Target domain name for the pointer record.
 * @param p_Output Output vector receiving the wire-format response.
 * @return 0 on success, -1 on error.
 */
int PTR(const DnsRequestPacket &p_Packet, const std::string &p_Domain, std::vector<char> &p_Output);

/**
 * @brief Construct an MX record response
 * @param p_Packet The original request packet.
 * @param p_Data   JSON object with keys: preference, exchange.
 * @param p_Output Output vector receiving the wire-format response.
 * @return 0 on success, -1 on error.
 */
int MX(const DnsRequestPacket &p_Packet, const nlohmann::json &p_Data, std::vector<char> &p_Output);

/**
 * @brief Construct a TXT record response
 * @param p_Packet The original request packet.
 * @param p_Data   JSON array of strings.
 * @param p_Output Output vector receiving the wire-format response.
 * @return 0 on success, -1 on error.
 */
int TXT(const DnsRequestPacket &p_Packet, const nlohmann::json &p_Data, std::vector<char> &p_Output);

/**
 * @brief Construct an AAAA record response with an IPv6 address
 * @param p_Packet  The original request packet.
 * @param p_Ipv6Hex Sixteen-byte binary IPv6 address.
 * @param p_Output  Output vector receiving the wire-format response.
 * @return 0 on success, -1 on error.
 */
int AAAA(const DnsRequestPacket &p_Packet, const std::string &p_Ipv6Hex, std::vector<char> &p_Output);

/**
 * @brief Construct an SRV record response
 * @param p_Packet The original request packet.
 * @param p_Data   JSON object with keys: priority, weight, port, target.
 * @param p_Output Output vector receiving the wire-format response.
 * @return 0 on success, -1 on error.
 */
int SRV(const DnsRequestPacket &p_Packet, const nlohmann::json &p_Data, std::vector<char> &p_Output);

/**
 * @brief Append a single answer record to an existing response buffer (no header/question)
 * @param p_RecordType Record type string ("A", "AAAA", "CNAME", etc.).
 * @param p_Packet     The original request packet.
 * @param p_Data       Record-specific data (JSON).
 * @param p_Output     Output vector to append the record to.
 * @param p_Name       Domain name for the NAME field; empty uses question pointer (0xC00C).
 * @return 0 on success, -1 on error.
 */
int AppendAnswer(const std::string &p_RecordType, const DnsRequestPacket &p_Packet, const nlohmann::json &p_Data, std::vector<char> &p_Output, const std::string &p_Name = "");

/**
 * @brief Single answer record descriptor for multi-answer responses
 */
struct AnswerRecord {
  std::string m_Type_;    ///< Record type ("A", "AAAA", "CNAME", etc.)
  nlohmann::json m_Data_; ///< Record-specific data
  std::string m_Name_;    ///< Answer NAME field; empty uses question pointer (0xC00C)
};

/**
 * @brief Build a complete response with multiple answer records
 * @param p_Packet  The original request packet.
 * @param p_Records Vector of answer records to include.
 * @param p_Output  Output vector receiving the wire-format response.
 * @return 0 on success, -1 on error.
 */
int MultiAnswer(const DnsRequestPacket &p_Packet, const std::vector<AnswerRecord> &p_Records, std::vector<char> &p_Output);

/**
 * @brief Dispatch to the appropriate response builder by record type string
 * @param p_RecordType Record type or error code string ("A", "NXDOMAIN", etc.).
 * @param p_Packet     The original request packet.
 * @param p_Data       Record-specific data (JSON).
 * @param p_Output     Output vector receiving the wire-format response.
 * @return 0 on success, -1 on error or unsupported type.
 */
int CallResponseFunction(const std::string &p_RecordType, const DnsRequestPacket &p_Packet, const nlohmann::json &p_Data, std::vector<char> &p_Output);

/**
 * @brief Dispatch to the raw-data response builder (FORMERR only)
 * @param p_RecordType Must be "FORMERR".
 * @param p_RawData    Pointer to the raw query bytes.
 * @param p_DataSize   Length of the raw data.
 * @param p_Output     Output vector receiving the wire-format response.
 * @return 0 on success, -1 on error or unsupported type.
 */
int CallResponseFunction(const std::string &p_RecordType, const char *p_RawData, std::size_t p_DataSize, std::vector<char> &p_Output);

/**
 * @brief Append an OPT pseudo-RR to a response buffer and increment ARCOUNT
 *
 * Serializes the server's OPT record per RFC 6891 §6.1.1.
 * Echoes COOKIE options from the request if present and valid.
 *
 * @param p_Output          Output vector containing a response (header already written).
 * @param p_ExtendedRcode   High 8 bits of extended RCODE for the OPT TTL.
 * @param p_RequestEdns     Request EDNS data for echoing options; nullptr if none.
 */
void AppendOpt(std::vector<char> &p_Output, uint8_t p_ExtendedRcode = 0, const EdnsData *p_RequestEdns = nullptr);

/**
 * @brief Construct a FORMERR response with OPT record included
 * @param p_Packet  The original request packet (may have partial parse).
 * @param p_Output  Output vector receiving the wire-format response.
 * @param p_RequestEdns Request EDNS data for the response OPT; nullptr if none.
 * @return 0 on success, -1 on error.
 */
int FORMERR_OPT(const DnsRequestPacket &p_Packet, std::vector<char> &p_Output, const EdnsData *p_RequestEdns = nullptr);

/**
 * @brief Construct a FORMERR response with OPT from raw bytes
 * @param p_RawData    Pointer to raw query bytes.
 * @param p_DataSize   Length of raw data.
 * @param p_Output     Output vector receiving the wire-format response.
 * @param p_RequestEdns Request EDNS data for the response OPT; nullptr if none.
 * @return 0 on success, -1 on error.
 */
int FORMERR_OPT(const char *p_RawData, std::size_t p_DataSize, std::vector<char> &p_Output, const EdnsData *p_RequestEdns = nullptr);

/**
 * @brief Construct a BADVERS response (version mismatch, RFC 6891 §6.1.3)
 *
 * Header RCODE is set to 0 (NOERROR), extended RCODE in OPT = 1,
 * yielding full RCODE = 16 (BADVERS).
 *
 * @param p_Packet      The original request packet.
 * @param p_Output      Output vector receiving the wire-format response.
 * @param p_RequestEdns Request EDNS data; nullptr if none.
 * @return 0 on success, -1 on error.
 */
int BADVERS(const DnsRequestPacket &p_Packet, std::vector<char> &p_Output, const EdnsData *p_RequestEdns = nullptr);

} // namespace DnsResponse

#endif
