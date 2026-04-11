// Self
#include "dns_parser.h"

// C

// C++
#include <cstddef>       // std::size_t
#include <cstdint>       // UINT16_MAX, uint16_t
#include <memory>        // std::make_unique, std::unique_ptr
#include <mutex>         // std::call_once, std::once_flag
#include <regex>         // std::regex, std::smatch, std::regex_search
#include <stdexcept>     // std::out_of_range, std::runtime_error
#include <string>        // std::string
#include <unordered_map> // std::unordered_map

// Other libraries

// This Project's
#include "constants.h"

// Logging
#include "libLog.h"

// Banned
#include "banned.h"

std::once_flag DnsParser::m_RootPatternInitFlag_{};
std::once_flag DnsParser::m_SubPatternInitFlag_{};
std::unique_ptr<std::regex> DnsParser::m_RootDomainPattern_{};
std::unique_ptr<std::regex> DnsParser::m_SubDomainPattern_{};

DnsParser::DnsParser(const char *p_Data, std::size_t p_DataLength) {
  if (p_DataLength < DnsHeader::HeaderSize) {
    throw std::out_of_range("p_Data is too small to be a properly formatted DNS request");
  }

  if (p_DataLength > UINT16_MAX) {
    throw std::out_of_range("DNS packet too large");
  }

  if (!p_Data) {
    throw std::invalid_argument("Input data pointer is null");
  }

  // DnsRequestPacket handles wire parsing with portable bitmask operations
  try {
    m_ParsedPacket_ = DnsRequestPacket(p_Data, p_DataLength);
  } catch (const std::invalid_argument &) {
    throw std::runtime_error("Failed to parse DNS packet");
  }

  if (m_ParsedPacket_.Header().Qdcount() != 1) {
    throw std::runtime_error(m_ParsedPacket_.Header().Qdcount() == 0 ? "No questions in DNS packet" : "Too many questions in DNS packet");
  }

  CacheDomainParts();
  PrintPacketDebug();
}

void DnsParser::CacheDomainParts() {
  if (m_ParsedPacket_.Questions().empty()) {
    return;
  }
  m_Domain_ = m_ParsedPacket_.Questions()[0].QnameAsString();

  std::smatch s_Match{};
  if (std::regex_search(m_Domain_, s_Match, RootDomainPattern())) {
    m_RootDomain_ = s_Match.str(2);
  } else {
    m_RootDomain_ = m_Domain_;
  }

  if (std::regex_search(m_Domain_, s_Match, SubDomainPattern())) {
    m_SubDomain_ = s_Match.str(1);
  }
}

const std::string &DnsParser::Domain() const {
  return m_Domain_;
}

const std::string &DnsParser::RootDomain() const {
  return m_RootDomain_;
}

const std::string &DnsParser::SubDomain() const {
  return m_SubDomain_;
}

const DnsRequestPacket &DnsParser::Packet() const {
  return m_ParsedPacket_;
}

// Thread-safe lazy initialization of root domain pattern
const std::regex &DnsParser::RootDomainPattern() {
  std::call_once(m_RootPatternInitFlag_, []() { m_RootDomainPattern_ = std::make_unique<std::regex>(Constants::Dns::ROOT_DOMAIN_PATTERN); });
  return *m_RootDomainPattern_;
}

// Thread-safe lazy initialization of subdomain pattern
const std::regex &DnsParser::SubDomainPattern() {
  std::call_once(m_SubPatternInitFlag_, []() { m_SubDomainPattern_ = std::make_unique<std::regex>(Constants::Dns::SUB_DOMAIN_PATTERN); });
  return *m_SubDomainPattern_;
}

  // clang-format off

std::string DnsParser::RecordType() const {
  // https://en.wikipedia.org/wiki/List_of_DNS_record_types
  static const std::unordered_map<uint16_t, std::string> s_RecordTypes{
    // Resource records
    {1, "A"},
    {28, "AAAA"},
    {18, "AFSDB"},
    {42, "APL"},
    {257, "CAA"},
    {60, "CDNSKEY"},
    {59, "CDS"},
    {37, "CERT"},
    {5, "CNAME"},
    {62, "CSYNC"},
    {49, "DHCID"},
    {32769, "DLV"},
    {39, "DNAME"},
    {48, "DNSKEY"},
    {43, "DS"},
    {108, "EUI48"},
    {109, "EUI64"},
    {13, "HINFO"},
    {55, "HIP"},
    {65, "HTTPS"},
    {45, "IPSECKEY"},
    {25, "KEY"},
    {36, "KX"},
    {29, "LOC"},
    {15, "MX"},
    {35, "NAPTR"},
    {2, "NS"},
    {47, "NSEC"},
    {50, "NSEC3"},
    {51, "NSEC3PARAM"},
    {61, "OPENPGPKEY"},
    {12, "PTR"},
    {46, "RRSIG"},
    {17, "RP"},
    {24, "SIG"},
    {53, "SMIMEA"},
    {6, "SOA"},
    {33, "SRV"},
    {44, "SSHFP"},
    {64, "SVCB"},
    {32768, "TA"},
    {249, "TKEY"},
    {52, "TLSA"},
    {250, "TSIG"},
    {16, "TXT"},
    {256, "URI"},
    {63, "ZONEMD"},

    // Other types and pseudo-RRs
    {255, "*"},
    {252, "AXFR"},
    {251, "IXFR"},
    {41, "OPT"},

    // Obsolete record types
    {3, "MD"},
    {4, "MF"},
    {254, "MAILA"},
    {7, "MB"},
    {8, "MG"},
    {9, "MR"},
    {14, "MINFO"},
    {253, "MAILB"},
    {11, "WKS"},
    {32, "NB"},
    // {33, "NBSTAT"},
    {10, "NULL"},
    {38, "A6"},
    {30, "NXT"},
    // {25, "KEY"},
    // {24, "SIG"},
    // {13, "HINFO"},
    // {17, "RP"},
    {19, "X25"},
    {20, "ISDN"},
    {21, "RT"},
    {22, "NSAP"},
    {23, "NSAP-PTR"},
    {26, "PX"},
    {31, "EID"},
    // {32, "NIMLOC"},
    {34, "ATMA"},
    // {42, "APL"},
    {40, "SINK"},
    {27, "GPOS"},
    {100, "UINFO"},
    {101, "UID"},
    {102, "GID"},
    {103, "UNSPEC"},
    {99, "SPF"},
    {56, "NINFO"},
    {57, "RKEY"},
    {58, "TALINK"},
    {104, "NID"},
    {105, "L32"},
    {106, "L64"},
    {107, "LP"},
    {259, "DOA"}
  };

  // clang-format on

  if (m_ParsedPacket_.Questions().empty()) {
    return "Unknown";
  }

  std::unordered_map<uint16_t, std::string>::const_iterator s_Iterator{s_RecordTypes.find(m_ParsedPacket_.Questions()[0].Qtype())};
  return (s_Iterator != s_RecordTypes.end()) ? s_Iterator->second : "Unknown";
}

void DnsParser::PrintPacketDebug() const {
  const DnsHeader &hdr{m_ParsedPacket_.Header()};
  logKernel(LL_Debug, "id:       0x%04x", hdr.Id());
  logKernel(LL_Debug, "flags:    0x%04x", hdr.Flags());
  logKernel(LL_Debug, "  qr:       %d", hdr.Qr());
  logKernel(LL_Debug, "  opcode:   %d", hdr.Opcode());
  logKernel(LL_Debug, "  aa:       %d", hdr.Aa());
  logKernel(LL_Debug, "  tc:       %d", hdr.Tc());
  logKernel(LL_Debug, "  rd:       %d", hdr.Rd());
  logKernel(LL_Debug, "  ra:       %d", hdr.Ra());
  logKernel(LL_Debug, "  z:        %d", hdr.Z());
  logKernel(LL_Debug, "  ad:       %d", hdr.Ad());
  logKernel(LL_Debug, "  cd:       %d", hdr.Cd());
  logKernel(LL_Debug, "  rcode:    %d", hdr.Rcode());
  logKernel(LL_Debug, "qdcount:  0x%04x", hdr.Qdcount());
  logKernel(LL_Debug, "ancount:  0x%04x", hdr.Ancount());
  logKernel(LL_Debug, "nscount:  0x%04x", hdr.Nscount());
  logKernel(LL_Debug, "arcount:  0x%04x", hdr.Arcount());

  logKernel(LL_Debug, "Question:");
  logKernel(LL_Debug, "  Domain:      %s", Domain().c_str());
  logKernel(LL_Debug, "  Subdomain:   %s", SubDomain().c_str());
  logKernel(LL_Debug, "  Root Domain: %s", RootDomain().c_str());
  logKernel(LL_Debug, "  Record Type: %s", RecordType().c_str());

  if (m_ParsedPacket_.HasEdns()) {
    const EdnsData &e{*m_ParsedPacket_.Edns()};
    logKernel(LL_Debug, "EDNS0:");
    logKernel(LL_Debug, "  UDP Payload: %u", e.m_UdpPayloadSize_);
    logKernel(LL_Debug, "  Version:     %u", e.m_Version_);
    logKernel(LL_Debug, "  DO bit:      %d", e.m_DoBit_ ? 1 : 0);
    logKernel(LL_Debug, "  Ext RCODE:   %u", e.m_ExtendedRcode_);
    logKernel(LL_Debug, "  Options:     %zu", e.m_Options_.size());
  }
}
