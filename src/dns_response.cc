// Self
#include "dns_response.h"

// C

// C++
#include <algorithm> // std::copy
#include <cassert>   // assert
#include <cstddef>   // std::size_t
#include <cstdint>   // int32_t, uint16_t, UINT16_MAX
#include <string>    // std::string
#include <vector>    // std::vector

// Other libraries

// This Project's
#include "config.h"
#include "constants.h"
#include "dns_packet.h"
#include "utils.h"

// Other libraries
#include "nlohmann/json.hpp"

// Logging
#include "libLog.h"

// Banned
#include "banned.h"

namespace {
void WriteUint16(std::vector<char> &p_Output, std::size_t p_Offset, uint16_t p_Value) {
  assert(p_Offset + 1 < p_Output.size());
  uint16_t s_NetworkValue{HostToNetwork(p_Value)};
  p_Output[p_Offset] = reinterpret_cast<const char *>(&s_NetworkValue)[0];
  p_Output[p_Offset + 1] = reinterpret_cast<const char *>(&s_NetworkValue)[1];
}

// void WriteUint32(std::vector<char> &p_Output, std::size_t p_Offset, uint32_t p_Value) {
//   assert(p_Offset + 3 < p_Output.size());
//   uint32_t s_NetworkValue{HostToNetwork(p_Value)};
//   p_Output[p_Offset] = reinterpret_cast<const char *>(&s_NetworkValue)[0];
//   p_Output[p_Offset + 1] = reinterpret_cast<const char *>(&s_NetworkValue)[1];
//   p_Output[p_Offset + 2] = reinterpret_cast<const char *>(&s_NetworkValue)[2];
//   p_Output[p_Offset + 3] = reinterpret_cast<const char *>(&s_NetworkValue)[3];
// }

void AppendUint16(std::vector<char> &p_Output, uint16_t p_Value) {
  uint16_t s_NetworkValue{HostToNetwork(p_Value)};
  const char *s_Bytes{reinterpret_cast<const char *>(&s_NetworkValue)};
  p_Output.push_back(s_Bytes[0]);
  p_Output.push_back(s_Bytes[1]);
}

void AppendUint32(std::vector<char> &p_Output, uint32_t p_Value) {
  uint32_t s_NetworkValue{HostToNetwork(p_Value)};
  const char *s_Bytes{reinterpret_cast<const char *>(&s_NetworkValue)};
  p_Output.push_back(s_Bytes[0]);
  p_Output.push_back(s_Bytes[1]);
  p_Output.push_back(s_Bytes[2]);
  p_Output.push_back(s_Bytes[3]);
}

void WriteStandardHeader(std::vector<char> &p_Output, const DnsRequestPacket &p_Packet, uint16_t p_Rcode, uint16_t p_Ancount = 1, uint16_t p_Nscount = 0, uint16_t p_Arcount = 0, bool p_Authoritative = false) {
  p_Output.clear();
  p_Output.reserve(Constants::Dns::DEFAULT_DNS_PACKET_SIZE); // Reserve typical max DNS packet size
  p_Output.resize(DnsHeader::HeaderSize, '\0');
  WriteUint16(p_Output, 0, p_Packet.Header().Id());

  // Build response flags per RFC 1035 §4.1.1: QR=1, echo RD from query, set RA=1
  uint16_t flags{static_cast<uint16_t>(0x8000 | 0x0080 | (p_Rcode & 0x000F))}; // QR=1, RA=1, RCODE
  if (p_Packet.Header().Rd()) {
    flags |= 0x0100; // Echo RD bit from query
  }
  if (p_Authoritative) {
    flags |= 0x0400; // AA=1: server is authoritative for this zone
  }
  WriteUint16(p_Output, 2, flags);
  WriteUint16(p_Output, 4, 1);          // QDCOUNT
  WriteUint16(p_Output, 6, p_Ancount);  // ANCOUNT
  WriteUint16(p_Output, 8, p_Nscount);  // NSCOUNT
  WriteUint16(p_Output, 10, p_Arcount); // ARCOUNT
}

bool WriteQuestion(std::vector<char> &p_Output, const DnsRequestPacket &p_Packet) {
  if (p_Packet.Questions().empty()) {
    return false;
  }
  const DnsQuestion &q{p_Packet.Questions()[0]};
  std::vector<char> s_Domain{};
  if (DnsResponse::DomainToQuestion(q.Qname(), s_Domain) == -1) {
    return false;
  }
  p_Output.insert(p_Output.end(), s_Domain.begin(), s_Domain.end());
  AppendUint16(p_Output, q.Qtype());
  AppendUint16(p_Output, q.Qclass());
  return true;
}

bool IsValidDnsName(const std::string &p_Name) {
  if (p_Name.empty() || p_Name.length() > Constants::Dns::MAX_DNS_NAME_LENGTH) {
    return false;
  }

  // CNAME ones have trailing dots...
  // Check for consecutive dots, leading/trailing dots
  // if (p_Name.front() == '.' || p_Name.back() == '.' || p_Name.find("..") != std::string::npos) {
  //   return false;
  // }

  // More checks could happen here

  return true;
}

  // Write the answer NAME field: either a pointer to the question (0xC00C) or a full domain name.
int WriteAnswerName(std::vector<char> &p_Output, const std::string &p_Name) {
  if (p_Name.empty()) {
    AppendUint16(p_Output, Constants::Dns::DNS_QUESTION_POINTER);
  } else {
    std::vector<char> s_NameWire;
    if (DnsResponse::DomainToQuestion(p_Name, s_NameWire) == -1) {
      return -1;
    }
    p_Output.insert(p_Output.end(), s_NameWire.begin(), s_NameWire.end());
  }
  return 0;
}

// Append a single answer record for each record type (no header/question).
int AppendAnswerA(std::vector<char> &p_Output, uint16_t p_Qclass, const std::string &p_Ipv4Hex, const std::string &p_Name) {
  if (p_Ipv4Hex.size() != 4) {
    return -1;
  }
  if (WriteAnswerName(p_Output, p_Name) != 0) {
    return -1;
  }
  AppendUint16(p_Output, Constants::Dns::DNS_TYPE_A);
  AppendUint16(p_Output, p_Qclass);
  AppendUint32(p_Output, static_cast<uint32_t>(g_Config.DefaultTtl()));
  AppendUint16(p_Output, 4);
  p_Output.insert(p_Output.end(), p_Ipv4Hex.begin(), p_Ipv4Hex.end());
  return 0;
}

int AppendAnswerAAAA(std::vector<char> &p_Output, uint16_t p_Qclass, const std::string &p_Ipv6Hex, const std::string &p_Name) {
  if (p_Ipv6Hex.size() != 16) {
    return -1;
  }
  if (WriteAnswerName(p_Output, p_Name) != 0) {
    return -1;
  }
  AppendUint16(p_Output, Constants::Dns::DNS_TYPE_AAAA);
  AppendUint16(p_Output, p_Qclass);
  AppendUint32(p_Output, static_cast<uint32_t>(g_Config.DefaultTtl()));
  AppendUint16(p_Output, 16);
  p_Output.insert(p_Output.end(), p_Ipv6Hex.begin(), p_Ipv6Hex.end());
  return 0;
}

int AppendAnswerDomain(std::vector<char> &p_Output, uint16_t p_Qclass, uint16_t p_Type, const std::string &p_Domain, const std::string &p_Name) {
  if (p_Domain.empty() || !IsValidDnsName(p_Domain)) {
    return -1;
  }
  std::vector<char> s_Wire;
  if (DnsResponse::DomainToQuestion(p_Domain, s_Wire) == -1) {
    return -1;
  }
  if (s_Wire.size() > UINT16_MAX) {
    return -1;
  }
  if (WriteAnswerName(p_Output, p_Name) != 0) {
    return -1;
  }
  AppendUint16(p_Output, p_Type);
  AppendUint16(p_Output, p_Qclass);
  AppendUint32(p_Output, static_cast<uint32_t>(g_Config.DefaultTtl()));
  AppendUint16(p_Output, static_cast<uint16_t>(s_Wire.size()));
  p_Output.insert(p_Output.end(), s_Wire.begin(), s_Wire.end());
  return 0;
}

int AppendAnswerSOA(std::vector<char> &p_Output, uint16_t p_Qclass, const nlohmann::json &p_Data, const std::string &p_Name) {
  if (!p_Data.is_object()) {
    return -1;
  }
  static const std::vector<std::string> s_Required{"primary", "admin", "serial", "refresh", "retry", "expire", "minimum"};
  for (const std::string &f : s_Required) {
    if (!p_Data.contains(f)) {
      return -1;
    }
  }
  const std::string &s_Primary{p_Data["primary"].get_ref<const std::string &>()};
  const std::string &s_Admin{p_Data["admin"].get_ref<const std::string &>()};
  if (!IsValidDnsName(s_Primary) || !IsValidDnsName(s_Admin)) {
    return -1;
  }
  std::vector<char> s_PrimaryWire, s_AdminWire;
  if (DnsResponse::DomainToQuestion(s_Primary, s_PrimaryWire) == -1) {
    return -1;
  }
  if (DnsResponse::DomainToQuestion(s_Admin, s_AdminWire) == -1) {
    return -1;
  }
  std::size_t s_RdataLen{s_PrimaryWire.size() + s_AdminWire.size() + 20};
  if (s_RdataLen > UINT16_MAX) {
    return -1;
  }
  if (WriteAnswerName(p_Output, p_Name) != 0) {
    return -1;
  }
  AppendUint16(p_Output, Constants::Dns::DNS_TYPE_SOA);
  AppendUint16(p_Output, p_Qclass);
  AppendUint32(p_Output, static_cast<uint32_t>(g_Config.DefaultTtl()));
  AppendUint16(p_Output, static_cast<uint16_t>(s_RdataLen));
  p_Output.insert(p_Output.end(), s_PrimaryWire.begin(), s_PrimaryWire.end());
  p_Output.insert(p_Output.end(), s_AdminWire.begin(), s_AdminWire.end());
  AppendUint32(p_Output, p_Data["serial"].get<uint32_t>());
  AppendUint32(p_Output, p_Data["refresh"].get<uint32_t>());
  AppendUint32(p_Output, p_Data["retry"].get<uint32_t>());
  AppendUint32(p_Output, p_Data["expire"].get<uint32_t>());
  AppendUint32(p_Output, p_Data["minimum"].get<uint32_t>());
  return 0;
}

int AppendAnswerMX(std::vector<char> &p_Output, uint16_t p_Qclass, const nlohmann::json &p_Data, const std::string &p_Name) {
  if (!p_Data.is_object() || !p_Data.contains("preference") || !p_Data.contains("exchange")) {
    return -1;
  }
  const std::string &s_Exchange{p_Data["exchange"].get_ref<const std::string &>()};
  if (!IsValidDnsName(s_Exchange)) {
    return -1;
  }
  std::vector<char> s_Wire;
  if (DnsResponse::DomainToQuestion(s_Exchange, s_Wire) == -1) {
    return -1;
  }
  std::size_t s_RdataLen{2 + s_Wire.size()};
  if (s_RdataLen > UINT16_MAX) {
    return -1;
  }
  if (WriteAnswerName(p_Output, p_Name) != 0) {
    return -1;
  }
  AppendUint16(p_Output, Constants::Dns::DNS_TYPE_MX);
  AppendUint16(p_Output, p_Qclass);
  AppendUint32(p_Output, static_cast<uint32_t>(g_Config.DefaultTtl()));
  AppendUint16(p_Output, static_cast<uint16_t>(s_RdataLen));
  AppendUint16(p_Output, p_Data["preference"].get<uint16_t>());
  p_Output.insert(p_Output.end(), s_Wire.begin(), s_Wire.end());
  return 0;
}

int AppendAnswerTXT(std::vector<char> &p_Output, uint16_t p_Qclass, const nlohmann::json &p_Data, const std::string &p_Name) {
  if (!p_Data.is_array() || p_Data.empty()) {
    return -1;
  }
  std::vector<char> s_Rdata;
  for (const nlohmann::json &e : p_Data) {
    if (!e.is_string()) {
      return -1;
    }
    const std::string &s{e.get_ref<const std::string &>()};
    if (s.size() > Constants::Dns::MAX_TXT_STRING_LENGTH) {
      return -1;
    }
    s_Rdata.push_back(static_cast<char>(s.size()));
    s_Rdata.insert(s_Rdata.end(), s.begin(), s.end());
  }
  if (s_Rdata.size() > UINT16_MAX) {
    return -1;
  }
  if (WriteAnswerName(p_Output, p_Name) != 0) {
    return -1;
  }
  AppendUint16(p_Output, Constants::Dns::DNS_TYPE_TXT);
  AppendUint16(p_Output, p_Qclass);
  AppendUint32(p_Output, static_cast<uint32_t>(g_Config.DefaultTtl()));
  AppendUint16(p_Output, static_cast<uint16_t>(s_Rdata.size()));
  p_Output.insert(p_Output.end(), s_Rdata.begin(), s_Rdata.end());
  return 0;
}

int AppendAnswerSRV(std::vector<char> &p_Output, uint16_t p_Qclass, const nlohmann::json &p_Data, const std::string &p_Name) {
  if (!p_Data.is_object()) {
    return -1;
  }
  static const std::vector<std::string> s_Required{"priority", "weight", "port", "target"};
  for (const std::string &f : s_Required) {
    if (!p_Data.contains(f)) {
      return -1;
    }
  }
  const std::string &s_Target{p_Data["target"].get_ref<const std::string &>()};
  if (!IsValidDnsName(s_Target)) {
    return -1;
  }
  std::vector<char> s_Wire;
  if (DnsResponse::DomainToQuestion(s_Target, s_Wire) == -1) {
    return -1;
  }
  std::size_t s_RdataLen{6 + s_Wire.size()};
  if (s_RdataLen > UINT16_MAX) {
    return -1;
  }
  if (WriteAnswerName(p_Output, p_Name) != 0) {
    return -1;
  }
  AppendUint16(p_Output, Constants::Dns::DNS_TYPE_SRV);
  AppendUint16(p_Output, p_Qclass);
  AppendUint32(p_Output, static_cast<uint32_t>(g_Config.DefaultTtl()));
  AppendUint16(p_Output, static_cast<uint16_t>(s_RdataLen));
  AppendUint16(p_Output, p_Data["priority"].get<uint16_t>());
  AppendUint16(p_Output, p_Data["weight"].get<uint16_t>());
  AppendUint16(p_Output, p_Data["port"].get<uint16_t>());
  p_Output.insert(p_Output.end(), s_Wire.begin(), s_Wire.end());
  return 0;
}

  // Dispatcher for appending a single answer record
int DispatchAppendAnswer(const std::string &p_Type, uint16_t p_Qclass, const nlohmann::json &p_Data, std::vector<char> &p_Output, const std::string &p_Name) {
  if (p_Type == "A") {
    return AppendAnswerA(p_Output, p_Qclass, p_Data.get<std::string>(), p_Name);
  }
  if (p_Type == "AAAA") {
    return AppendAnswerAAAA(p_Output, p_Qclass, p_Data.get<std::string>(), p_Name);
  }
  if (p_Type == "CNAME") {
    return AppendAnswerDomain(p_Output, p_Qclass, Constants::Dns::DNS_TYPE_CNAME, p_Data.get<std::string>(), p_Name);
  }
  if (p_Type == "NS") {
    return AppendAnswerDomain(p_Output, p_Qclass, Constants::Dns::DNS_TYPE_NS, p_Data.get<std::string>(), p_Name);
  }
  if (p_Type == "PTR") {
    return AppendAnswerDomain(p_Output, p_Qclass, Constants::Dns::DNS_TYPE_PTR, p_Data.get<std::string>(), p_Name);
  }
  if (p_Type == "SOA") {
    return AppendAnswerSOA(p_Output, p_Qclass, p_Data, p_Name);
  }
  if (p_Type == "MX") {
    return AppendAnswerMX(p_Output, p_Qclass, p_Data, p_Name);
  }
  if (p_Type == "TXT") {
    return AppendAnswerTXT(p_Output, p_Qclass, p_Data, p_Name);
  }
  if (p_Type == "SRV") {
    return AppendAnswerSRV(p_Output, p_Qclass, p_Data, p_Name);
  }
  logKernel(LL_Error, "AppendAnswer: unsupported type: %s", p_Type.c_str());
  return -1;
}
} // namespace

int DnsResponse::DomainToQuestion(const std::vector<std::string> &p_Input, std::vector<char> &p_Output) {
  // Calculate total size needed first
  std::size_t total_size{1}; // For null terminator
  for (const std::string &l_Entry : p_Input) {
    if (l_Entry.empty()) {
      logKernel(LL_Error, "Empty DNS label not allowed");
      return -1;
    }
    if (l_Entry.length() > Constants::Dns::MAX_DNS_LABEL_LENGTH) {
      logKernel(LL_Error, "DNS label too long: %zu bytes (max %zu)", l_Entry.length(), Constants::Dns::MAX_DNS_LABEL_LENGTH);
      return -1;
    }
    total_size += l_Entry.length() + 1;
  }

  // RFC 1035 §2.3.4: total wire-format name must be <= 255 bytes
  if (total_size > 255) {
    logKernel(LL_Error, "DNS name too long in wire format: %zu bytes (max 255)", total_size);
    return -1;
  }

  // Reserve space efficiently
  p_Output.reserve(p_Output.size() + total_size);

  // Add labels
  for (const std::string &l_Entry : p_Input) {
    p_Output.push_back(static_cast<char>(l_Entry.length()));
    p_Output.insert(p_Output.end(), l_Entry.begin(), l_Entry.end());
  }
  p_Output.push_back('\0');

  return 0;
}

int DnsResponse::DomainToQuestion(const std::string &p_Input, std::vector<char> &p_Output) {
  if (p_Input.empty()) {
    p_Output.push_back('\0');
    return 0;
  }

  if (!IsValidDnsName(p_Input)) {
    logKernel(LL_Error, "Invalid DNS name format: %s", p_Input.c_str());
    return -1;
  }

  std::vector<std::string> s_Parts{};
  std::size_t s_Start{0};
  std::size_t s_Pos{0};

  while ((s_Pos = p_Input.find('.', s_Start)) != std::string::npos) {
    if (s_Pos > s_Start) {
      s_Parts.push_back(p_Input.substr(s_Start, s_Pos - s_Start));
    }
    s_Start = s_Pos + 1;
  }
  if (s_Start < p_Input.size()) {
    s_Parts.push_back(p_Input.substr(s_Start));
  }

  return DomainToQuestion(s_Parts, p_Output);
}

int DnsResponse::FORMERR(const DnsRequestPacket &p_Packet, std::vector<char> &p_Output) {
  // Check if we can include the question
  uint16_t qdcount{static_cast<uint16_t>((p_Packet.Header().Qdcount() > 0 && !p_Packet.Questions().empty()) ? 1 : 0)};
  WriteStandardHeader(p_Output, p_Packet, Constants::Dns::DNS_RCODE_FORMERR, 0, 0, 0);

  // Update QDCOUNT after header is written
  WriteUint16(p_Output, 4, qdcount);

  // Include original question if available and valid
  if (qdcount > 0) {
    if (!WriteQuestion(p_Output, p_Packet)) {
      // If WriteQuestion fails, update QDCOUNT to 0
      WriteUint16(p_Output, 4, 0);
    }
  }

  return 0;
}

int DnsResponse::FORMERR(const char *p_RawData, std::size_t p_DataSize, std::vector<char> &p_Output) {
  p_Output.resize(DnsHeader::HeaderSize, '\0');

  // Extract and write transaction ID
  uint16_t transaction_id{0};
  if (p_RawData && p_DataSize >= 2) {
    const char *s_Src{p_RawData};
    std::copy(s_Src, s_Src + sizeof(uint16_t), reinterpret_cast<char *>(&transaction_id));
    transaction_id = NetworkToHost(transaction_id);
  }
  WriteUint16(p_Output, 0, transaction_id);

  // Build response flags, echoing RD from query per RFC 1035
  uint16_t flags{0x8001}; // QR=1, RCODE=FORMERR
  flags |= 0x0080; // RA=1
  if (p_RawData && p_DataSize >= 4) {
    uint16_t original_flags{0};
    std::copy(p_RawData + 2, p_RawData + 2 + sizeof(uint16_t), reinterpret_cast<char *>(&original_flags));
    original_flags = NetworkToHost(original_flags);
    if (original_flags & 0x0100) { // Echo RD bit from query
      flags |= 0x0100;
    }
  }
  WriteUint16(p_Output, 2, flags);

  // All counts zero for malformed packet response
  WriteUint16(p_Output, 4, 0);  // QDCOUNT
  WriteUint16(p_Output, 6, 0);  // ANCOUNT
  WriteUint16(p_Output, 8, 0);  // NSCOUNT
  WriteUint16(p_Output, 10, 0); // ARCOUNT

  return 0;
}

int DnsResponse::NXDOMAIN(const DnsRequestPacket &p_Packet, std::vector<char> &p_Output, const std::string &p_Zone) {
  uint16_t s_Nscount{static_cast<uint16_t>(p_Zone.empty() ? 0 : 1)};
  WriteStandardHeader(p_Output, p_Packet, Constants::Dns::DNS_RCODE_NXDOMAIN, 0, s_Nscount, 0, true);
  if (!WriteQuestion(p_Output, p_Packet)) {
    return -1;
  }

  // RFC 2308 §2.1: include a SOA record in the authority section for negative caching
  if (!p_Zone.empty() && !p_Packet.Questions().empty()) {
    std::string s_Mname{"ns." + p_Zone + "."};
    std::string s_Rname{"hostmaster." + p_Zone + "."};

    std::vector<char> s_ZoneWire, s_MnameWire, s_RnameWire;
    if (DomainToQuestion(p_Zone, s_ZoneWire) == -1 || DomainToQuestion(s_Mname, s_MnameWire) == -1 || DomainToQuestion(s_Rname, s_RnameWire) == -1) {
      // Encoding failed - return valid NXDOMAIN without SOA
      WriteUint16(p_Output, 8, 0);
      return 0;
    }

    std::size_t s_RdataLen{s_MnameWire.size() + s_RnameWire.size() + 20};
    if (s_RdataLen > UINT16_MAX) {
      WriteUint16(p_Output, 8, 0);
      return 0;
    }

    // Authority section: SOA record for the zone
    p_Output.insert(p_Output.end(), s_ZoneWire.begin(), s_ZoneWire.end());
    AppendUint16(p_Output, Constants::Dns::DNS_TYPE_SOA);
    AppendUint16(p_Output, p_Packet.Questions()[0].Qclass());
    AppendUint32(p_Output, static_cast<uint32_t>(g_Config.DefaultTtl()));
    AppendUint16(p_Output, static_cast<uint16_t>(s_RdataLen));
    p_Output.insert(p_Output.end(), s_MnameWire.begin(), s_MnameWire.end());
    p_Output.insert(p_Output.end(), s_RnameWire.begin(), s_RnameWire.end());
    AppendUint32(p_Output, 1);                                            // Serial
    AppendUint32(p_Output, 86400);                                        // Refresh (1 day)
    AppendUint32(p_Output, 3600);                                         // Retry (1 hour)
    AppendUint32(p_Output, 604800);                                       // Expire (1 week)
    AppendUint32(p_Output, static_cast<uint32_t>(g_Config.DefaultTtl())); // Minimum (negative cache TTL)
  }

  return 0;
}

int DnsResponse::NOTIMP(const DnsRequestPacket &p_Packet, std::vector<char> &p_Output) {
  WriteStandardHeader(p_Output, p_Packet, Constants::Dns::DNS_RCODE_NOTIMP, 0, 0, 0);
  if (!WriteQuestion(p_Output, p_Packet)) {
    return -1;
  }

  return 0;
}

int DnsResponse::SERVFAIL(const DnsRequestPacket &p_Packet, std::vector<char> &p_Output) {
  WriteStandardHeader(p_Output, p_Packet, Constants::Dns::DNS_RCODE_SERVFAIL, 0, 0, 0);
  if (!WriteQuestion(p_Output, p_Packet)) {
    return -1;
  }

  return 0;
}

int DnsResponse::REFUSED(const DnsRequestPacket &p_Packet, std::vector<char> &p_Output) {
  WriteStandardHeader(p_Output, p_Packet, Constants::Dns::DNS_RCODE_REFUSED, 0, 0, 0);
  if (!WriteQuestion(p_Output, p_Packet)) {
    return -1;
  }

  return 0;
}

int DnsResponse::A(const DnsRequestPacket &p_Packet, const std::string &p_Ipv4Hex, std::vector<char> &p_Output) {
  if (p_Ipv4Hex.size() != 4) {
    logKernel(LL_Error, "Invalid IPv4 data size: %zu, expected 4", p_Ipv4Hex.size());
    return -1;
  }

  WriteStandardHeader(p_Output, p_Packet, Constants::Dns::DNS_RCODE_NOERROR, 1, 0, 0, true);
  if (!WriteQuestion(p_Output, p_Packet)) {
    return -1;
  }

  // Answer section
  AppendUint16(p_Output, Constants::Dns::DNS_QUESTION_POINTER); // Pointer to question
  AppendUint16(p_Output, Constants::Dns::DNS_TYPE_A);           // Answer Type (A)
  AppendUint16(p_Output, p_Packet.Questions()[0].Qclass());     // Answer Class
  AppendUint32(p_Output, static_cast<uint32_t>(g_Config.DefaultTtl())); // TTL

  // Data Length (4 bytes for IPv4)
  AppendUint16(p_Output, 4);

  // IPv4 address data (already in binary format)
  p_Output.insert(p_Output.end(), p_Ipv4Hex.begin(), p_Ipv4Hex.end());

  return 0;
}

int DnsResponse::NS(const DnsRequestPacket &p_Packet, const std::string &p_Domain, std::vector<char> &p_Output) {
  if (p_Domain.empty()) {
    logKernel(LL_Error, "NS domain cannot be empty");
    return -1;
  }

  if (!IsValidDnsName(p_Domain)) {
    logKernel(LL_Error, "Invalid NS domain format: %s", p_Domain.c_str());
    return -1;
  }

  WriteStandardHeader(p_Output, p_Packet, Constants::Dns::DNS_RCODE_NOERROR, 1, 0, 0, true);
  if (!WriteQuestion(p_Output, p_Packet)) {
    return -1;
  }

  // Answer section
  AppendUint16(p_Output, Constants::Dns::DNS_QUESTION_POINTER); // Pointer to question
  AppendUint16(p_Output, Constants::Dns::DNS_TYPE_NS);          // Answer Type (NS)
  AppendUint16(p_Output, p_Packet.Questions()[0].Qclass());     // Answer Class
  AppendUint32(p_Output, static_cast<uint32_t>(g_Config.DefaultTtl())); // TTL

  std::vector<char> s_NsDomain;
  if (DomainToQuestion(p_Domain, s_NsDomain) == -1) {
    return -1;
  }

  if (s_NsDomain.size() > UINT16_MAX) {
    return -1;
  }

  AppendUint16(p_Output, static_cast<uint16_t>(s_NsDomain.size())); // Data Length
  p_Output.insert(p_Output.end(), s_NsDomain.begin(), s_NsDomain.end());

  return 0;
}

int DnsResponse::CNAME(const DnsRequestPacket &p_Packet, const std::string &p_Domain, std::vector<char> &p_Output) {
  if (p_Domain.empty()) {
    logKernel(LL_Error, "CNAME domain cannot be empty");
    return -1;
  }

  if (!IsValidDnsName(p_Domain)) {
    logKernel(LL_Error, "Invalid CNAME domain format: %s", p_Domain.c_str());
    return -1;
  }

  WriteStandardHeader(p_Output, p_Packet, Constants::Dns::DNS_RCODE_NOERROR, 1, 0, 0, true);
  if (!WriteQuestion(p_Output, p_Packet)) {
    return -1;
  }

  // Answer section
  AppendUint16(p_Output, Constants::Dns::DNS_QUESTION_POINTER); // Pointer to question
  AppendUint16(p_Output, Constants::Dns::DNS_TYPE_CNAME);       // Answer Type (CNAME)
  AppendUint16(p_Output, p_Packet.Questions()[0].Qclass());     // Answer Class
  AppendUint32(p_Output, static_cast<uint32_t>(g_Config.DefaultTtl())); // TTL

  // Data
  std::vector<char> s_CnameDomain;
  if (DomainToQuestion(p_Domain, s_CnameDomain) == -1) {
    return -1;
  }

  if (s_CnameDomain.size() > UINT16_MAX) {
    return -1;
  }

  AppendUint16(p_Output, static_cast<uint16_t>(s_CnameDomain.size())); // Data Length
  p_Output.insert(p_Output.end(), s_CnameDomain.begin(), s_CnameDomain.end());

  return 0;
}

int DnsResponse::PTR(const DnsRequestPacket &p_Packet, const std::string &p_Domain, std::vector<char> &p_Output) {
  if (p_Domain.empty()) {
    logKernel(LL_Error, "PTR domain cannot be empty");
    return -1;
  }

  if (!IsValidDnsName(p_Domain)) {
    logKernel(LL_Error, "Invalid PTR domain format: %s", p_Domain.c_str());
    return -1;
  }

  WriteStandardHeader(p_Output, p_Packet, Constants::Dns::DNS_RCODE_NOERROR, 1, 0, 0, true);
  if (!WriteQuestion(p_Output, p_Packet)) {
    return -1;
  }

  // Answer section
  AppendUint16(p_Output, Constants::Dns::DNS_QUESTION_POINTER); // Pointer to question
  AppendUint16(p_Output, Constants::Dns::DNS_TYPE_PTR);         // Answer Type (PTR)
  AppendUint16(p_Output, p_Packet.Questions()[0].Qclass());     // Answer Class
  AppendUint32(p_Output, static_cast<uint32_t>(g_Config.DefaultTtl())); // TTL

  // Data
  std::vector<char> s_PtrDomain{};
  if (DomainToQuestion(p_Domain, s_PtrDomain) == -1) {
    return -1;
  }

  if (s_PtrDomain.size() > UINT16_MAX) {
    return -1;
  }

  AppendUint16(p_Output, static_cast<uint16_t>(s_PtrDomain.size())); // Data Length
  p_Output.insert(p_Output.end(), s_PtrDomain.begin(), s_PtrDomain.end());

  return 0;
}

int DnsResponse::AAAA(const DnsRequestPacket &p_Packet, const std::string &p_Ipv6Hex, std::vector<char> &p_Output) {
  if (p_Ipv6Hex.size() != 16) {
    logKernel(LL_Error, "Invalid IPv6 data size: %zu, expected 16", p_Ipv6Hex.size());
    return -1;
  }

  WriteStandardHeader(p_Output, p_Packet, Constants::Dns::DNS_RCODE_NOERROR, 1, 0, 0, true);
  if (!WriteQuestion(p_Output, p_Packet)) {
    return -1;
  }

  // Answer section
  AppendUint16(p_Output, Constants::Dns::DNS_QUESTION_POINTER); // Pointer to question
  AppendUint16(p_Output, Constants::Dns::DNS_TYPE_AAAA);        // Answer Type (AAAA)
  AppendUint16(p_Output, p_Packet.Questions()[0].Qclass());     // Answer Class
  AppendUint32(p_Output, static_cast<uint32_t>(g_Config.DefaultTtl())); // TTL

  // Data Length (16 bytes for IPv6)
  AppendUint16(p_Output, 16);

  // IPv6 address data (already in binary format)
  p_Output.insert(p_Output.end(), p_Ipv6Hex.begin(), p_Ipv6Hex.end());

  return 0;
}

int DnsResponse::SOA(const DnsRequestPacket &p_Packet, const nlohmann::json &p_Data, std::vector<char> &p_Output) {
  if (!p_Data.is_object()) {
    logKernel(LL_Error, "SOA data must be a JSON object");
    return -1;
  }

  // Validate required fields
  static const std::vector<std::string> s_RequiredFields{"primary", "admin", "serial", "refresh", "retry", "expire", "minimum"};
  for (const std::string &l_Field : s_RequiredFields) {
    if (!p_Data.contains(l_Field)) {
      logKernel(LL_Error, "SOA record missing required field: %s", l_Field.c_str());
      return -1;
    }
  }

  const std::string &s_Primary{p_Data["primary"].get_ref<const std::string &>()};
  const std::string &s_Admin{p_Data["admin"].get_ref<const std::string &>()};

  if (!IsValidDnsName(s_Primary) || !IsValidDnsName(s_Admin)) {
    logKernel(LL_Error, "SOA contains invalid DNS name");
    return -1;
  }

  // Encode MNAME and RNAME
  std::vector<char> s_PrimaryWire;
  if (DomainToQuestion(s_Primary, s_PrimaryWire) == -1) {
    return -1;
  }
  std::vector<char> s_AdminWire;
  if (DomainToQuestion(s_Admin, s_AdminWire) == -1) {
    return -1;
  }

  // RDATA length: mname + rname + 5 * uint32
  std::size_t s_RdataLen{s_PrimaryWire.size() + s_AdminWire.size() + 20};
  if (s_RdataLen > UINT16_MAX) {
    return -1;
  }

  WriteStandardHeader(p_Output, p_Packet, Constants::Dns::DNS_RCODE_NOERROR, 1, 0, 0, true);
  if (!WriteQuestion(p_Output, p_Packet)) {
    return -1;
  }

  AppendUint16(p_Output, Constants::Dns::DNS_QUESTION_POINTER);
  AppendUint16(p_Output, Constants::Dns::DNS_TYPE_SOA);
  AppendUint16(p_Output, p_Packet.Questions()[0].Qclass());
  AppendUint32(p_Output, static_cast<uint32_t>(g_Config.DefaultTtl()));
  AppendUint16(p_Output, static_cast<uint16_t>(s_RdataLen));

  p_Output.insert(p_Output.end(), s_PrimaryWire.begin(), s_PrimaryWire.end());
  p_Output.insert(p_Output.end(), s_AdminWire.begin(), s_AdminWire.end());
  AppendUint32(p_Output, p_Data["serial"].get<uint32_t>());
  AppendUint32(p_Output, p_Data["refresh"].get<uint32_t>());
  AppendUint32(p_Output, p_Data["retry"].get<uint32_t>());
  AppendUint32(p_Output, p_Data["expire"].get<uint32_t>());
  AppendUint32(p_Output, p_Data["minimum"].get<uint32_t>());

  return 0;
}

int DnsResponse::MX(const DnsRequestPacket &p_Packet, const nlohmann::json &p_Data, std::vector<char> &p_Output) {
  if (!p_Data.is_object()) {
    logKernel(LL_Error, "MX data must be a JSON object");
    return -1;
  }

  if (!p_Data.contains("preference") || !p_Data.contains("exchange")) {
    logKernel(LL_Error, "MX record missing required field(s)");
    return -1;
  }

  const std::string &s_Exchange{p_Data["exchange"].get_ref<const std::string &>()};
  if (!IsValidDnsName(s_Exchange)) {
    logKernel(LL_Error, "Invalid MX exchange domain: %s", s_Exchange.c_str());
    return -1;
  }

  std::vector<char> s_ExchangeWire;
  if (DomainToQuestion(s_Exchange, s_ExchangeWire) == -1) {
    return -1;
  }

  std::size_t s_RdataLen{2 + s_ExchangeWire.size()}; // uint16 preference + domain
  if (s_RdataLen > UINT16_MAX) {
    return -1;
  }

  WriteStandardHeader(p_Output, p_Packet, Constants::Dns::DNS_RCODE_NOERROR, 1, 0, 0, true);
  if (!WriteQuestion(p_Output, p_Packet)) {
    return -1;
  }

  AppendUint16(p_Output, Constants::Dns::DNS_QUESTION_POINTER);
  AppendUint16(p_Output, Constants::Dns::DNS_TYPE_MX);
  AppendUint16(p_Output, p_Packet.Questions()[0].Qclass());
  AppendUint32(p_Output, static_cast<uint32_t>(g_Config.DefaultTtl()));
  AppendUint16(p_Output, static_cast<uint16_t>(s_RdataLen));

  AppendUint16(p_Output, p_Data["preference"].get<uint16_t>());
  p_Output.insert(p_Output.end(), s_ExchangeWire.begin(), s_ExchangeWire.end());

  return 0;
}

int DnsResponse::TXT(const DnsRequestPacket &p_Packet, const nlohmann::json &p_Data, std::vector<char> &p_Output) {
  if (!p_Data.is_array() || p_Data.empty()) {
    logKernel(LL_Error, "TXT data must be a non-empty JSON array of strings");
    return -1;
  }

  // Build the concatenated character-strings (each prefixed with length byte)
  std::vector<char> s_Rdata;
  for (const nlohmann::json &l_Entry : p_Data) {
    if (!l_Entry.is_string()) {
      logKernel(LL_Error, "TXT record entry must be a string");
      return -1;
    }
    const std::string &s_Str{l_Entry.get_ref<const std::string &>()};
    if (s_Str.size() > Constants::Dns::MAX_TXT_STRING_LENGTH) {
      logKernel(LL_Error, "TXT string exceeds 255 bytes: %zu", s_Str.size());
      return -1;
    }
    s_Rdata.push_back(static_cast<char>(s_Str.size()));
    s_Rdata.insert(s_Rdata.end(), s_Str.begin(), s_Str.end());
  }

  if (s_Rdata.size() > UINT16_MAX) {
    return -1;
  }

  WriteStandardHeader(p_Output, p_Packet, Constants::Dns::DNS_RCODE_NOERROR, 1, 0, 0, true);
  if (!WriteQuestion(p_Output, p_Packet)) {
    return -1;
  }

  AppendUint16(p_Output, Constants::Dns::DNS_QUESTION_POINTER);
  AppendUint16(p_Output, Constants::Dns::DNS_TYPE_TXT);
  AppendUint16(p_Output, p_Packet.Questions()[0].Qclass());
  AppendUint32(p_Output, static_cast<uint32_t>(g_Config.DefaultTtl()));
  AppendUint16(p_Output, static_cast<uint16_t>(s_Rdata.size()));
  p_Output.insert(p_Output.end(), s_Rdata.begin(), s_Rdata.end());

  return 0;
}

int DnsResponse::SRV(const DnsRequestPacket &p_Packet, const nlohmann::json &p_Data, std::vector<char> &p_Output) {
  if (!p_Data.is_object()) {
    logKernel(LL_Error, "SRV data must be a JSON object");
    return -1;
  }

  static const std::vector<std::string> s_RequiredFields{"priority", "weight", "port", "target"};
  for (const std::string &l_Field : s_RequiredFields) {
    if (!p_Data.contains(l_Field)) {
      logKernel(LL_Error, "SRV record missing required field: %s", l_Field.c_str());
      return -1;
    }
  }

  const std::string &s_Target{p_Data["target"].get_ref<const std::string &>()};
  if (!IsValidDnsName(s_Target)) {
    logKernel(LL_Error, "Invalid SRV target domain: %s", s_Target.c_str());
    return -1;
  }

  std::vector<char> s_TargetWire;
  if (DomainToQuestion(s_Target, s_TargetWire) == -1) {
    return -1;
  }

  std::size_t s_RdataLen{6 + s_TargetWire.size()}; // 3 * uint16 + domain
  if (s_RdataLen > UINT16_MAX) {
    return -1;
  }

  WriteStandardHeader(p_Output, p_Packet, Constants::Dns::DNS_RCODE_NOERROR, 1, 0, 0, true);
  if (!WriteQuestion(p_Output, p_Packet)) {
    return -1;
  }

  AppendUint16(p_Output, Constants::Dns::DNS_QUESTION_POINTER);
  AppendUint16(p_Output, Constants::Dns::DNS_TYPE_SRV);
  AppendUint16(p_Output, p_Packet.Questions()[0].Qclass());
  AppendUint32(p_Output, static_cast<uint32_t>(g_Config.DefaultTtl()));
  AppendUint16(p_Output, static_cast<uint16_t>(s_RdataLen));

  AppendUint16(p_Output, p_Data["priority"].get<uint16_t>());
  AppendUint16(p_Output, p_Data["weight"].get<uint16_t>());
  AppendUint16(p_Output, p_Data["port"].get<uint16_t>());
  p_Output.insert(p_Output.end(), s_TargetWire.begin(), s_TargetWire.end());

  return 0;
}

int DnsResponse::AppendAnswer(const std::string &p_RecordType, const DnsRequestPacket &p_Packet, const nlohmann::json &p_Data, std::vector<char> &p_Output, const std::string &p_Name) {
  if (p_Packet.Questions().empty()) {
    return -1;
  }
  return DispatchAppendAnswer(p_RecordType, p_Packet.Questions()[0].Qclass(), p_Data, p_Output, p_Name);
}

int DnsResponse::MultiAnswer(const DnsRequestPacket &p_Packet, const std::vector<AnswerRecord> &p_Records, std::vector<char> &p_Output) {
  if (p_Records.empty() || p_Records.size() > UINT16_MAX) {
    return -1;
  }

  WriteStandardHeader(p_Output, p_Packet, Constants::Dns::DNS_RCODE_NOERROR, static_cast<uint16_t>(p_Records.size()), 0, 0, true);
  if (!WriteQuestion(p_Output, p_Packet)) {
    return -1;
  }

  uint16_t s_Qclass{p_Packet.Questions()[0].Qclass()};
  for (const DnsResponse::AnswerRecord &l_Record : p_Records) {
    if (DispatchAppendAnswer(l_Record.m_Type_, s_Qclass, l_Record.m_Data_, p_Output, l_Record.m_Name_) != 0) {
      return -1;
    }
  }

  return 0;
}

int DnsResponse::CallResponseFunction(const std::string &p_RecordType, const DnsRequestPacket &p_Packet, const nlohmann::json &p_Data, std::vector<char> &p_Output) {
  if (p_RecordType == "PTR") {
    return DnsResponse::PTR(p_Packet, p_Data.get<std::string>(), p_Output);
  } else if (p_RecordType == "CNAME") {
    return DnsResponse::CNAME(p_Packet, p_Data.get<std::string>(), p_Output);
  } else if (p_RecordType == "A") {
    return DnsResponse::A(p_Packet, p_Data.get<std::string>(), p_Output);
  } else if (p_RecordType == "AAAA") {
    return DnsResponse::AAAA(p_Packet, p_Data.get<std::string>(), p_Output);
  } else if (p_RecordType == "NS") {
    return DnsResponse::NS(p_Packet, p_Data.get<std::string>(), p_Output);
  } else if (p_RecordType == "SOA") {
    return DnsResponse::SOA(p_Packet, p_Data, p_Output);
  } else if (p_RecordType == "MX") {
    return DnsResponse::MX(p_Packet, p_Data, p_Output);
  } else if (p_RecordType == "TXT") {
    return DnsResponse::TXT(p_Packet, p_Data, p_Output);
  } else if (p_RecordType == "SRV") {
    return DnsResponse::SRV(p_Packet, p_Data, p_Output);
  } else if (p_RecordType == "NXDOMAIN") {
    std::string s_Zone{p_Data.is_string() ? p_Data.get<std::string>() : ""};
    return DnsResponse::NXDOMAIN(p_Packet, p_Output, s_Zone);
  } else if (p_RecordType == "NOTIMP") {
    return DnsResponse::NOTIMP(p_Packet, p_Output);
  } else if (p_RecordType == "FORMERR") {
    return DnsResponse::FORMERR(p_Packet, p_Output);
  } else if (p_RecordType == "SERVFAIL") {
    return DnsResponse::SERVFAIL(p_Packet, p_Output);
  } else if (p_RecordType == "REFUSED") {
    return DnsResponse::REFUSED(p_Packet, p_Output);
  }

  logKernel(LL_Error, "Unsupported record type: %s", p_RecordType.c_str());
  return -1;
}

int DnsResponse::CallResponseFunction(const std::string &p_RecordType, const char *p_RawData, std::size_t p_DataSize, std::vector<char> &p_Output) {
  if (p_RecordType == "FORMERR") {
    return DnsResponse::FORMERR(p_RawData, p_DataSize, p_Output);
  }

  logKernel(LL_Error, "Raw data function only supports FORMERR, got: %s", p_RecordType.c_str());
  return -1;
}

// ============================================================================
// EDNS0 / OPT support (RFC 6891)
// ============================================================================

void DnsResponse::AppendOpt(std::vector<char> &p_Output, uint8_t p_ExtendedRcode, const EdnsData *p_RequestEdns) {
  // Build RDATA: echo COOKIE options from request, ignore unknown options
  std::vector<char> s_Rdata;
  if (p_RequestEdns != nullptr) {
    for (const EdnsOption &l_Opt : p_RequestEdns->m_Options_) {
      if (l_Opt.m_Code_ == Constants::Dns::EDNS_OPTION_CODE_COOKIE && l_Opt.m_Data_.size() >= Constants::Dns::EDNS_COOKIE_MIN_LENGTH && l_Opt.m_Data_.size() <= Constants::Dns::EDNS_COOKIE_MAX_LENGTH) {
        // Echo COOKIE option
        AppendUint16(s_Rdata, l_Opt.m_Code_);
        AppendUint16(s_Rdata, static_cast<uint16_t>(l_Opt.m_Data_.size()));
        s_Rdata.insert(s_Rdata.end(), l_Opt.m_Data_.begin(), l_Opt.m_Data_.end());
      }
      // Unknown option codes are silently ignored per RFC 6891 §6.1.2
    }
  }

  // OPT pseudo-RR: NAME = root (0x00)
  p_Output.push_back(0x00);

  // TYPE = OPT (41)
  AppendUint16(p_Output, Constants::Dns::DNS_TYPE_OPT);

  // CLASS = server UDP payload size
  AppendUint16(p_Output, Constants::Dns::DEFAULT_EDNS_PACKET_SIZE);

  // TTL = extended RCODE (8) | version (8) | DO (1) | Z (15)
  // We always respond with EDNS version 0, DO=0 (we don't sign), Z=0
  uint32_t s_Ttl{static_cast<uint32_t>(p_ExtendedRcode) << 24};
  AppendUint32(p_Output, s_Ttl);

  // RDLENGTH + RDATA
  if (s_Rdata.size() > UINT16_MAX) {
    AppendUint16(p_Output, 0);
  } else {
    AppendUint16(p_Output, static_cast<uint16_t>(s_Rdata.size()));
    if (!s_Rdata.empty()) {
      p_Output.insert(p_Output.end(), s_Rdata.begin(), s_Rdata.end());
    }
  }

  // Increment ARCOUNT in header (offset 10-11)
  if (p_Output.size() >= DnsHeader::HeaderSize) {
    uint16_t s_Arcount{0};
    uint16_t s_NetworkArcount{0};
    const char *s_ArcountPtr{p_Output.data() + 10};
    std::copy(s_ArcountPtr, s_ArcountPtr + 2, reinterpret_cast<char *>(&s_NetworkArcount));
    s_Arcount = NetworkToHost(s_NetworkArcount);
    s_Arcount++;
    WriteUint16(p_Output, 10, s_Arcount);
  }
}

int DnsResponse::FORMERR_OPT(const DnsRequestPacket &p_Packet, std::vector<char> &p_Output, const EdnsData *p_RequestEdns) {
  int s_Ret{FORMERR(p_Packet, p_Output)};
  if (s_Ret == 0) {
    AppendOpt(p_Output, 0, p_RequestEdns);
  }
  return s_Ret;
}

int DnsResponse::FORMERR_OPT(const char *p_RawData, std::size_t p_DataSize, std::vector<char> &p_Output, const EdnsData *p_RequestEdns) {
  int s_Ret{FORMERR(p_RawData, p_DataSize, p_Output)};
  if (s_Ret == 0) {
    AppendOpt(p_Output, 0, p_RequestEdns);
  }
  return s_Ret;
}

int DnsResponse::BADVERS(const DnsRequestPacket &p_Packet, std::vector<char> &p_Output, const EdnsData *p_RequestEdns) {
  // Header RCODE = 0 (NOERROR), extended RCODE in OPT = 1 => full RCODE = 16 (BADVERS)
  WriteStandardHeader(p_Output, p_Packet, Constants::Dns::DNS_RCODE_NOERROR, 0, 0, 0);
  if (!WriteQuestion(p_Output, p_Packet)) {
    return -1;
  }
  AppendOpt(p_Output, 1, p_RequestEdns);
  return 0;
}
