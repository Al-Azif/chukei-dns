// Self
#include "dns_packet_answer.h"

// C

// C++
#include <algorithm>  // std::all_of, std::copy, std::copy_if
#include <cassert>    // assert
#include <cctype>     // std::isalnum
#include <cstdint>    // uint8_t, uint16_t, uint32_t
#include <functional> // std::hash
#include <iomanip>    // std::hex
#include <numeric>    // std::accumulate
#include <ostream>    // std::ostream
#include <sstream>    // std::ostringstream
#include <stdexcept>  // std::invalid_argument
#include <string>     // std::string
#include <utility>    // std::move, std::swap
#include <vector>     // std::vector

// Other libraries

// This Project's
#include "constants.h" // Constants::Dns::DEFAULT_DNS_PACKET_SIZE
#include "utils.h"     // HostToNetwork, NetworkToHost

// Logging
#include "libLog.h"

// Banned
#include "banned.h"

DnsAnswer::DnsAnswer(const char *p_Data, size_type p_Size) {
  size_type s_Offset{0};
  if (!FromWire(p_Data, p_Size, s_Offset, *this)) {
    throw std::invalid_argument("DnsAnswer: invalid or insufficient data");
  }
}

DnsAnswer::DnsAnswer(const char *p_Data, size_type p_Size, size_type &p_Offset) {
  if (!FromWire(p_Data, p_Size, p_Offset, *this)) {
    throw std::invalid_argument("DnsAnswer: invalid or insufficient data");
  }
}

DnsAnswer::DnsAnswer(const std::string &p_Data) {
  size_type s_Offset{0};
  if (!FromWire(p_Data.data(), p_Data.size(), s_Offset, *this)) {
    throw std::invalid_argument("DnsAnswer: invalid string data");
  }
}

DnsAnswer::DnsAnswer(const std::string &p_Data, size_type &p_Offset) {
  if (!FromWire(p_Data.data(), p_Data.size(), p_Offset, *this)) {
    throw std::invalid_argument("DnsAnswer: invalid string data");
  }
}

DnsAnswer::DnsAnswer(const std::vector<char> &p_Data) {
  size_type s_Offset{0};
  if (!FromWire(p_Data.data(), p_Data.size(), s_Offset, *this)) {
    throw std::invalid_argument("DnsAnswer: invalid vector data");
  }
}

DnsAnswer::DnsAnswer(const std::vector<char> &p_Data, size_type &p_Offset) {
  if (!FromWire(p_Data.data(), p_Data.size(), p_Offset, *this)) {
    throw std::invalid_argument("DnsAnswer: invalid vector data");
  }
}

DnsAnswer::DnsAnswer(const std::vector<unsigned char> &p_Data) {
  size_type s_Offset{0};
  if (!FromWire(reinterpret_cast<const char *>(p_Data.data()), p_Data.size(), s_Offset, *this)) {
    throw std::invalid_argument("DnsAnswer: invalid vector data");
  }
}

DnsAnswer::DnsAnswer(const std::vector<unsigned char> &p_Data, size_type &p_Offset) {
  if (!FromWire(reinterpret_cast<const char *>(p_Data.data()), p_Data.size(), p_Offset, *this)) {
    throw std::invalid_argument("DnsAnswer: invalid vector data");
  }
}

DnsAnswer::DnsAnswer(std::vector<std::string> p_Name, uint16_t p_Type, uint16_t p_Class, uint32_t p_Ttl, std::vector<char> p_RData) : m_Name_(std::move(p_Name)), m_Rdata_(std::move(p_RData)) {
  SetType(p_Type);
  SetRclass(p_Class);
  SetTtl(p_Ttl);
  UpdateRDLENGTH();
}

DnsAnswer::DnsAnswer(const std::string &p_Name, uint16_t p_Type, uint16_t p_Class, uint32_t p_Ttl, std::vector<char> p_RData) : m_Rdata_(std::move(p_RData)) {
  SetNameFromString(p_Name);
  SetType(p_Type);
  SetRclass(p_Class);
  SetTtl(p_Ttl);
  UpdateRDLENGTH();
}

DnsAnswer DnsAnswer::MakeARecord(const std::string &p_Name, const std::string &p_Ipv4Address, uint32_t p_Ttl) {
  DnsAnswer s_Answer;
  s_Answer.SetNameFromString(p_Name);
  s_Answer.SetType(1);
  s_Answer.SetRclass(1);
  s_Answer.SetTtl(p_Ttl);
  s_Answer.SetRdataIpv4(p_Ipv4Address);
  return s_Answer;
}

DnsAnswer DnsAnswer::MakeAaaaRecord(const std::string &p_Name, const std::string &p_Ipv6Address, uint32_t p_Ttl) {
  DnsAnswer s_Answer;
  s_Answer.SetNameFromString(p_Name);
  s_Answer.SetType(28);
  s_Answer.SetRclass(1);
  s_Answer.SetTtl(p_Ttl);
  s_Answer.SetRdataIpv6(p_Ipv6Address);
  return s_Answer;
}

DnsAnswer DnsAnswer::MakeCnameRecord(const std::string &p_Name, const std::string &p_CanonicalName, uint32_t p_Ttl) {
  DnsAnswer s_Answer;
  s_Answer.SetNameFromString(p_Name);
  s_Answer.SetType(5);
  s_Answer.SetRclass(1);
  s_Answer.SetTtl(p_Ttl);
  s_Answer.SetRdataDomainName(p_CanonicalName);
  return s_Answer;
}

DnsAnswer DnsAnswer::MakeMxRecord(const std::string &p_Name, const std::string &p_MailServer, uint16_t p_Priority, uint32_t p_Ttl) {
  DnsAnswer s_Answer;
  s_Answer.SetNameFromString(p_Name);
  s_Answer.SetType(15);
  s_Answer.SetRclass(1);
  s_Answer.SetTtl(p_Ttl);

  // MX record format: 2 bytes priority + domain name
  std::vector<char> s_RData;
  uint16_t s_NetworkPriority{HostToNetwork(p_Priority)};
  const char *s_PriorityBytes{reinterpret_cast<const char *>(&s_NetworkPriority)};
  s_RData.insert(s_RData.end(), s_PriorityBytes, s_PriorityBytes + 2);

  // Encode domain name
  std::vector<std::string> s_Labels;
  std::string s_Domain{p_MailServer};
  if (!s_Domain.empty() && s_Domain.back() == '.') {
    s_Domain.pop_back();
  }

  size_type s_Start{0};
  size_type s_Position{0};
  while ((s_Position = s_Domain.find('.', s_Start)) != std::string::npos) {
    std::string s_Label{s_Domain.substr(s_Start, s_Position - s_Start)};
    if (IsValidLabel(s_Label)) {
      s_Labels.push_back(s_Label);
    }
    s_Start = s_Position + 1;
  }
  if (s_Start < s_Domain.length()) {
    std::string s_Label{s_Domain.substr(s_Start)};
    if (IsValidLabel(s_Label)) {
      s_Labels.push_back(s_Label);
    }
  }

  // Serialize domain name
  for (const std::string &l_Label : s_Labels) {
    if (l_Label.size() > 63) {
      continue; // Skip invalid labels
    }
    s_RData.push_back(static_cast<char>(l_Label.size()));
    s_RData.insert(s_RData.end(), l_Label.begin(), l_Label.end());
  }
  s_RData.push_back('\0'); // Null terminator

  s_Answer.SetRdata(s_RData);
  return s_Answer;
}

DnsAnswer DnsAnswer::MakeTxtRecord(const std::string &p_Name, const std::string &p_TextData, uint32_t p_Ttl) {
  DnsAnswer s_Answer;
  s_Answer.SetNameFromString(p_Name);
  s_Answer.SetType(16);
  s_Answer.SetRclass(1);
  s_Answer.SetTtl(p_Ttl);
  s_Answer.SetRdataText(p_TextData);
  return s_Answer;
}

DnsAnswer DnsAnswer::MakePtrRecord(const std::string &p_Name, const std::string &p_TargetName, uint32_t p_Ttl) {
  DnsAnswer s_Answer;
  s_Answer.SetNameFromString(p_Name);
  s_Answer.SetType(12);
  s_Answer.SetRclass(1);
  s_Answer.SetTtl(p_Ttl);
  s_Answer.SetRdataDomainName(p_TargetName);
  return s_Answer;
}

DnsAnswer DnsAnswer::MakeNsRecord(const std::string &p_Name, const std::string &p_NameServer, uint32_t p_Ttl) {
  DnsAnswer s_Answer;
  s_Answer.SetNameFromString(p_Name);
  s_Answer.SetType(2);
  s_Answer.SetRclass(1);
  s_Answer.SetTtl(p_Ttl);
  s_Answer.SetRdataDomainName(p_NameServer);
  return s_Answer;
}

const std::vector<std::string> &DnsAnswer::Name() const noexcept {
  return m_Name_;
}

uint16_t DnsAnswer::Type(bool p_Raw) const noexcept {
  return p_Raw ? m_Type_ : NetworkToHost(m_Type_);
}

uint16_t DnsAnswer::Rclass(bool p_Raw) const noexcept {
  return p_Raw ? m_Class_ : NetworkToHost(m_Class_);
}

uint32_t DnsAnswer::Ttl(bool p_Raw) const noexcept {
  return p_Raw ? m_Ttl_ : NetworkToHost(m_Ttl_);
}

uint16_t DnsAnswer::Rdlength(bool p_Raw) const noexcept {
  return p_Raw ? m_Rdlength_ : NetworkToHost(m_Rdlength_);
}

const std::vector<char> &DnsAnswer::Rdata() const noexcept {
  return m_Rdata_;
}

std::string DnsAnswer::NameAsString() const {
  if (m_Name_.empty()) {
    return "";
  }

  std::string s_Result;
  s_Result.reserve(CalculateStringSize());

  for (size_type l_Index{0}; l_Index < m_Name_.size(); ++l_Index) {
    if (l_Index > 0) {
      s_Result += '.';
    }
    s_Result += m_Name_[l_Index];
  }
  return s_Result;
}

std::string DnsAnswer::Fqdn() const {
  std::string s_Result{NameAsString()};
  if (!s_Result.empty()) {
    s_Result += '.';
  }
  return s_Result;
}

std::string DnsAnswer::RdataAsIpv4() const {
  if (Type() != 1 || m_Rdata_.size() != 4) {
    throw std::invalid_argument("DnsAnswer: not an A record or invalid data size");
  }

  std::ostringstream s_Stream;
  s_Stream << static_cast<unsigned int>(static_cast<unsigned char>(m_Rdata_[0])) << '.' << static_cast<unsigned int>(static_cast<unsigned char>(m_Rdata_[1])) << '.' << static_cast<unsigned int>(static_cast<unsigned char>(m_Rdata_[2])) << '.' << static_cast<unsigned int>(static_cast<unsigned char>(m_Rdata_[3]));
  return s_Stream.str();
}

std::string DnsAnswer::RdataAsIpv6() const {
  if (Type() != 28 || m_Rdata_.size() != 16) {
    throw std::invalid_argument("DnsAnswer: not an AAAA record or invalid data size");
  }

  std::ostringstream s_Stream;
  s_Stream << std::hex;
  for (size_type l_Index{0}; l_Index < 16; l_Index += 2) {
    if (l_Index > 0) {
      s_Stream << ':';
    }
    uint16_t s_Word{static_cast<uint16_t>((static_cast<unsigned char>(m_Rdata_[l_Index]) << 8) | static_cast<unsigned char>(m_Rdata_[l_Index + 1]))};
    s_Stream << s_Word;
  }
  return s_Stream.str();
}

std::string DnsAnswer::RdataAsDomainName() const {
  uint16_t s_RecordType{Type()};
  if (s_RecordType != 2 && s_RecordType != 5 && s_RecordType != 12) { // NS, CNAME, PTR
    throw std::invalid_argument("DnsAnswer: not a domain name record type");
  }

  // Parse domain name from RDATA
  std::vector<std::string> s_Labels;
  size_type s_Offset{0};
  if (!ParseDomainName(m_Rdata_.data(), m_Rdata_.size(), s_Offset, s_Labels)) {
    throw std::invalid_argument("DnsAnswer: invalid domain name in RDATA");
  }

  if (s_Labels.empty()) {
    return "";
  }

  std::string s_Result;
  for (size_type l_Index{0}; l_Index < s_Labels.size(); ++l_Index) {
    if (l_Index > 0) {
      s_Result += '.';
    }
    s_Result += s_Labels[l_Index];
  }
  return s_Result;
}

std::string DnsAnswer::RdataAsText() const {
  if (Type() != 16) { // TXT record
    throw std::invalid_argument("DnsAnswer: not a TXT record");
  }

  std::string s_Result;
  size_type s_Offset{0};

  while (s_Offset < m_Rdata_.size()) {
    uint8_t s_Length{static_cast<uint8_t>(m_Rdata_[s_Offset])};
    s_Offset++;

    if (s_Offset + s_Length > m_Rdata_.size()) {
      break;
    }

    if (!s_Result.empty()) {
      s_Result += " "; // Separate multiple strings with space
    }

    s_Result.append(m_Rdata_.data() + s_Offset, s_Length);
    s_Offset += s_Length;
  }

  return s_Result;
}

void DnsAnswer::SetName(const std::vector<std::string> &p_Labels) {
  m_Name_.clear();
  m_Name_.reserve(p_Labels.size());

  std::copy_if(p_Labels.begin(), p_Labels.end(), std::back_inserter(m_Name_), [](const std::string &l_Label) { return DnsAnswer::IsValidLabel(l_Label); });
}

void DnsAnswer::SetNameFromString(const std::string &p_Name) {
  m_Name_.clear();

  if (p_Name.empty()) {
    return;
  }

  std::string s_Domain{p_Name};
  // Remove trailing dot if present, don't need to check for empty as it's checked above before assignment
  if (s_Domain.back() == '.') {
    s_Domain.pop_back();
  }

  size_type s_Start{0};
  size_type s_Position{0};

  while ((s_Position = s_Domain.find('.', s_Start)) != std::string::npos) {
    std::string s_Label{s_Domain.substr(s_Start, s_Position - s_Start)};
    if (IsValidLabel(s_Label)) {
      m_Name_.push_back(s_Label);
    }
    s_Start = s_Position + 1;
  }

  // Add final label if any
  if (s_Start < s_Domain.length()) {
    std::string s_Label{s_Domain.substr(s_Start)};
    if (IsValidLabel(s_Label)) {
      m_Name_.push_back(s_Label);
    }
  }
}

void DnsAnswer::SetType(uint16_t p_Type, bool p_Raw) noexcept {
  m_Type_ = p_Raw ? p_Type : HostToNetwork(p_Type);
}

void DnsAnswer::SetRclass(uint16_t p_Class, bool p_Raw) noexcept {
  m_Class_ = p_Raw ? p_Class : HostToNetwork(p_Class);
}

void DnsAnswer::SetTtl(uint32_t p_Ttl, bool p_Raw) noexcept {
  m_Ttl_ = p_Raw ? p_Ttl : HostToNetwork(p_Ttl);
}

void DnsAnswer::SetRdata(const std::vector<char> &p_Data) {
  m_Rdata_ = p_Data;
  UpdateRDLENGTH();
}

void DnsAnswer::SetRdataIpv4(const std::string &p_Ipv4Address) {
  // Parse IPv4 address string
  std::vector<char> s_RData;
  s_RData.reserve(4);

  std::size_t s_Start{0};
  std::size_t s_Pos{0};

  while ((s_Pos = p_Ipv4Address.find('.', s_Start)) != std::string::npos) {
    try {
      int s_Value{std::stoi(p_Ipv4Address.substr(s_Start, s_Pos - s_Start))};
      if (s_Value < 0 || s_Value > 255) {
        throw std::invalid_argument("DnsAnswer: invalid IPv4 octet value");
      }
      s_RData.push_back(static_cast<char>(s_Value));
    } catch (const std::exception &) {
      throw std::invalid_argument("DnsAnswer: invalid IPv4 address format");
    }
    s_Start = s_Pos + 1;
  }
  // Last octet (after final dot or whole string if no dots)
  if (s_Start <= p_Ipv4Address.size()) {
    try {
      int s_Value{std::stoi(p_Ipv4Address.substr(s_Start))};
      if (s_Value < 0 || s_Value > 255) {
        throw std::invalid_argument("DnsAnswer: invalid IPv4 octet value");
      }
      s_RData.push_back(static_cast<char>(s_Value));
    } catch (const std::exception &) {
      throw std::invalid_argument("DnsAnswer: invalid IPv4 address format");
    }
  }

  if (s_RData.size() != 4) {
    throw std::invalid_argument("DnsAnswer: IPv4 address must have 4 octets");
  }

  SetRdata(s_RData);
}

void DnsAnswer::SetRdataIpv6(const std::string &p_Ipv6Address) {
  std::vector<char> s_RData;
  s_RData.reserve(16);

  std::string s_Address{p_Ipv6Address};

  // Handle :: expansion
  // Split into "before ::" and "after ::" halves, fill middle with zero groups
  std::vector<std::string> s_AllGroups;
  std::string::size_type s_DoubleColon{s_Address.find("::")};

  if (s_DoubleColon != std::string::npos) {
    // Parse groups before ::
    std::vector<std::string> s_Before;
    std::vector<std::string> s_After;

    std::string s_Left{s_Address.substr(0, s_DoubleColon)};
    std::string s_Right{(s_DoubleColon + 2 < s_Address.size()) ? s_Address.substr(s_DoubleColon + 2) : ""};

    if (!s_Left.empty()) {
      size_type s_Start{0};
      size_type s_Pos{0};
      while ((s_Pos = s_Left.find(':', s_Start)) != std::string::npos) {
        s_Before.push_back(s_Left.substr(s_Start, s_Pos - s_Start));
        s_Start = s_Pos + 1;
      }
      s_Before.push_back(s_Left.substr(s_Start));
    }

    if (!s_Right.empty()) {
      size_type s_Start{0};
      size_type s_Pos{0};
      while ((s_Pos = s_Right.find(':', s_Start)) != std::string::npos) {
        s_After.push_back(s_Right.substr(s_Start, s_Pos - s_Start));
        s_Start = s_Pos + 1;
      }
      s_After.push_back(s_Right.substr(s_Start));
    }

    // Fill: before + zeros + after = 8 groups
    int s_ZeroGroups{8 - static_cast<int>(s_Before.size()) - static_cast<int>(s_After.size())};
    if (s_ZeroGroups < 0) {
      throw std::invalid_argument("DnsAnswer: invalid IPv6 address - too many groups");
    }

    s_AllGroups = s_Before;
    for (int l_Index{0}; l_Index < s_ZeroGroups; ++l_Index) {
      s_AllGroups.push_back("0");
    }
    s_AllGroups.insert(s_AllGroups.end(), s_After.begin(), s_After.end());
  } else {
    // No :: - split normally by ':'
    size_type s_Start{0};
    size_type s_Pos{0};
    while ((s_Pos = s_Address.find(':', s_Start)) != std::string::npos) {
      s_AllGroups.push_back(s_Address.substr(s_Start, s_Pos - s_Start));
      s_Start = s_Pos + 1;
    }
    s_AllGroups.push_back(s_Address.substr(s_Start));
  }

  if (s_AllGroups.size() != 8) {
    throw std::invalid_argument("DnsAnswer: IPv6 address must have exactly 8 groups");
  }

  for (const std::string &s_Group : s_AllGroups) {
    try {
      int s_IntValue{std::stoi(s_Group.empty() ? "0" : s_Group, nullptr, 16)};
      if (s_IntValue < 0 || s_IntValue > 0xFFFF) {
        throw std::invalid_argument("DnsAnswer: IPv6 group value out of range");
      }
      uint16_t s_Value{static_cast<uint16_t>(s_IntValue)};
      s_RData.push_back(static_cast<char>(s_Value >> 8));
      s_RData.push_back(static_cast<char>(s_Value & 0xFF));
    } catch (const std::exception &) {
      throw std::invalid_argument("DnsAnswer: invalid IPv6 address format");
    }
  }

  if (s_RData.size() != 16) {
    throw std::invalid_argument("DnsAnswer: IPv6 address must be 16 bytes");
  }

  SetRdata(s_RData);
}

void DnsAnswer::SetRdataDomainName(const std::string &p_DomainName) {
  // Encodes a domain name into DNS wire format (length-prefixed labels + null terminator).
  // Parallel logic exists in DnsResponse::DomainToQuestion; kept separate to avoid
  // cross-layer dependency and because error handling differs (skip vs return -1).
  std::vector<char> s_RData;

  std::string s_Domain{p_DomainName};
  if (!s_Domain.empty() && s_Domain.back() == '.') {
    s_Domain.pop_back();
  }

  // Split domain into labels
  std::vector<std::string> s_Labels;
  size_type s_Start{0};
  size_type s_Position{0};

  while ((s_Position = s_Domain.find('.', s_Start)) != std::string::npos) {
    std::string s_Label{s_Domain.substr(s_Start, s_Position - s_Start)};
    if (IsValidLabel(s_Label)) {
      s_Labels.push_back(s_Label);
    }
    s_Start = s_Position + 1;
  }
  if (s_Start < s_Domain.length()) {
    std::string s_Label{s_Domain.substr(s_Start)};
    if (IsValidLabel(s_Label)) {
      s_Labels.push_back(s_Label);
    }
  }

  // Serialize labels
  for (const std::string &l_Label : s_Labels) {
    if (l_Label.size() > 63) {
      continue; // Skip invalid labels
    }
    s_RData.push_back(static_cast<char>(l_Label.size()));
    s_RData.insert(s_RData.end(), l_Label.begin(), l_Label.end());
  }
  s_RData.push_back('\0'); // Null terminator

  SetRdata(s_RData);
}

void DnsAnswer::SetRdataText(const std::string &p_Text) {
  std::vector<char> s_RData;

  // TXT records are length-prefixed strings
  // For simplicity, we'll create a single string entry
  if (p_Text.size() > 255) {
    throw std::invalid_argument("DnsAnswer: TXT record string too long (max 255 bytes)");
  }

  s_RData.push_back(static_cast<char>(p_Text.size()));
  s_RData.insert(s_RData.end(), p_Text.begin(), p_Text.end());

  SetRdata(s_RData);
}

bool DnsAnswer::AddLabel(const std::string &p_Label) {
  if (IsValidLabel(p_Label)) {
    m_Name_.push_back(p_Label);
    return true;
  }
  return false;
}

bool DnsAnswer::PrependLabel(const std::string &p_Label) {
  if (IsValidLabel(p_Label)) {
    m_Name_.insert(m_Name_.begin(), p_Label);
    return true;
  }
  return false;
}

bool DnsAnswer::PopLabel() noexcept {
  if (!m_Name_.empty()) {
    m_Name_.pop_back();
    return true;
  }
  return false;
}

bool DnsAnswer::RemoveFirstLabel() noexcept {
  if (!m_Name_.empty()) {
    m_Name_.erase(m_Name_.begin());
    return true;
  }
  return false;
}

void DnsAnswer::swap(DnsAnswer &p_Other) noexcept {
  std::swap(m_Name_, p_Other.m_Name_);
  std::swap(m_Type_, p_Other.m_Type_);
  std::swap(m_Class_, p_Other.m_Class_);
  std::swap(m_Ttl_, p_Other.m_Ttl_);
  std::swap(m_Rdlength_, p_Other.m_Rdlength_);
  std::swap(m_Rdata_, p_Other.m_Rdata_);
}

bool DnsAnswer::empty() const noexcept {
  return m_Name_.empty();
}

DnsAnswer::size_type DnsAnswer::size() const noexcept {
  return m_Name_.size();
}

DnsAnswer::size_type DnsAnswer::max_size() const noexcept {
  return m_Name_.max_size();
}

void DnsAnswer::reserve(size_type p_Size) {
  m_Name_.reserve(p_Size);
}

void DnsAnswer::clear() noexcept {
  m_Name_.clear();
  m_Type_ = 0;
  m_Class_ = 0;
  m_Ttl_ = 0;
  m_Rdlength_ = 0;
  m_Rdata_.clear();
}

void DnsAnswer::resize(size_type p_Size, const std::string &p_Value) {
  m_Name_.resize(p_Size, p_Value);
}

DnsAnswer::iterator DnsAnswer::begin() noexcept {
  return m_Name_.begin();
}

DnsAnswer::const_iterator DnsAnswer::begin() const noexcept {
  return m_Name_.begin();
}

DnsAnswer::const_iterator DnsAnswer::cbegin() const noexcept {
  return m_Name_.cbegin();
}

DnsAnswer::iterator DnsAnswer::end() noexcept {
  return m_Name_.end();
}

DnsAnswer::const_iterator DnsAnswer::end() const noexcept {
  return m_Name_.end();
}

DnsAnswer::const_iterator DnsAnswer::cend() const noexcept {
  return m_Name_.cend();
}

DnsAnswer::reverse_iterator DnsAnswer::rbegin() noexcept {
  return m_Name_.rbegin();
}

DnsAnswer::const_reverse_iterator DnsAnswer::rbegin() const noexcept {
  return m_Name_.rbegin();
}

DnsAnswer::const_reverse_iterator DnsAnswer::crbegin() const noexcept {
  return m_Name_.crbegin();
}

DnsAnswer::reverse_iterator DnsAnswer::rend() noexcept {
  return m_Name_.rend();
}

DnsAnswer::const_reverse_iterator DnsAnswer::rend() const noexcept {
  return m_Name_.rend();
}

DnsAnswer::const_reverse_iterator DnsAnswer::crend() const noexcept {
  return m_Name_.crend();
}

DnsAnswer::reference DnsAnswer::at(size_type p_Index) {
  return m_Name_.at(p_Index);
}

DnsAnswer::const_reference DnsAnswer::at(size_type p_Index) const {
  return m_Name_.at(p_Index);
}

DnsAnswer::reference DnsAnswer::operator[](size_type p_Index) noexcept {
  return m_Name_[p_Index];
}

DnsAnswer::const_reference DnsAnswer::operator[](size_type p_Index) const noexcept {
  return m_Name_[p_Index];
}

DnsAnswer::reference DnsAnswer::front() noexcept {
  return m_Name_.front();
}

DnsAnswer::const_reference DnsAnswer::front() const noexcept {
  return m_Name_.front();
}

DnsAnswer::reference DnsAnswer::back() noexcept {
  return m_Name_.back();
}

DnsAnswer::const_reference DnsAnswer::back() const noexcept {
  return m_Name_.back();
}

bool DnsAnswer::Valid() const noexcept {
  if (m_Name_.empty()) {
    // Root domain is valid
    return true;
  }

  size_type s_TotalLength{0};
  for (const std::string &l_Label : m_Name_) {
    if (!IsValidLabel(l_Label)) {
      return false;
    }
    s_TotalLength += l_Label.length() + 1; // +1 for length byte
  }
  s_TotalLength += 1; // +1 for null terminator

  // Check domain name length limit
  if (s_TotalLength > 255) {
    return false;
  }

  // Check RDLENGTH matches actual RDATA size
  return Rdlength() == m_Rdata_.size();
}

DnsAnswer::size_type DnsAnswer::Hash() const noexcept {
  size_type s_Result = std::accumulate(m_Name_.begin(), m_Name_.end(), size_type{0}, [](size_type s_Result, const std::string &l_Label) { return s_Result ^ (std::hash<std::string>{}(l_Label) + 0x9e3779b9 + (s_Result << 6) + (s_Result >> 2)); });

  // Combine with type, class, and TTL
  s_Result ^= std::hash<uint16_t>{}(m_Type_) + 0x9e3779b9 + (s_Result << 6) + (s_Result >> 2);
  s_Result ^= std::hash<uint16_t>{}(m_Class_) + 0x9e3779b9 + (s_Result << 6) + (s_Result >> 2);
  s_Result ^= std::hash<uint32_t>{}(m_Ttl_) + 0x9e3779b9 + (s_Result << 6) + (s_Result >> 2);

  // Hash RDATA
  s_Result = std::accumulate(m_Rdata_.begin(), m_Rdata_.end(), s_Result, [](size_type s_Result, char c) { return s_Result ^ (std::hash<char>{}(c) + 0x9e3779b9 + (s_Result << 6) + (s_Result >> 2)); });

  return s_Result;
}

void *DnsAnswer::data() noexcept {
  return m_Name_.data();
}

const void *DnsAnswer::data() const noexcept {
  return m_Name_.data();
}

DnsAnswer::size_type DnsAnswer::WireSize() const noexcept {
  // NAME size (length bytes + label data + null terminator)
  size_type s_Size{std::accumulate(m_Name_.begin(), m_Name_.end(), size_type{0}, [](size_type s_Sum, const std::string &l_Label) { return l_Label.size() <= 63 ? s_Sum + 1 + l_Label.size() : s_Sum; })};
  s_Size += 1; // Null terminator

  s_Size += 10; // TYPE + CLASS + TTL + RDLENGTH
  s_Size += m_Rdata_.size(); // RDATA

  return s_Size;
}

// Encode domain name labels into uncompressed wire format (label-length pairs + null terminator)
void DnsAnswer::EncodeDomainLabels(const std::vector<std::string> &p_Labels, std::vector<char> &p_Output) {
  for (const std::string &l_Label : p_Labels) {
    p_Output.push_back(static_cast<char>(l_Label.size()));
    p_Output.insert(p_Output.end(), l_Label.begin(), l_Label.end());
  }
  p_Output.push_back('\0');
}

// Decompress RDATA domain names for record types that contain them.
// Compression pointers in RDATA reference offsets in the full packet, so we must
// resolve them using the full packet buffer and re-encode without compression.
bool DnsAnswer::DecompressRDATA(const void *p_Data, size_type p_Size, size_type p_RdataOffset, uint16_t p_TypeHost, std::vector<char> &p_RData) {
  const char *s_DataBytes{static_cast<const char *>(p_Data)};

  if (p_TypeHost == 2 || p_TypeHost == 5 || p_TypeHost == 12) {
    // NS (2), CNAME (5), PTR (12): single domain name
    std::vector<std::string> s_RdataLabels;
    size_type s_Offset{p_RdataOffset};
    if (!ParseDomainName(p_Data, p_Size, s_Offset, s_RdataLabels)) {
      return false;
    }
    p_RData.clear();
    EncodeDomainLabels(s_RdataLabels, p_RData);
    return true;
  }

  if (p_TypeHost == 6) {
    // SOA: MNAME (domain) + RNAME (domain) + 5 x uint32 (20 bytes)
    std::vector<std::string> s_MnameLabels;
    std::vector<std::string> s_RnameLabels;
    size_type s_Offset{p_RdataOffset};
    if (!ParseDomainName(p_Data, p_Size, s_Offset, s_MnameLabels)) {
      return false;
    }
    if (!ParseDomainName(p_Data, p_Size, s_Offset, s_RnameLabels)) {
      return false;
    }
    if (s_Offset + 20 > p_Size) {
      return false;
    }
    p_RData.clear();
    EncodeDomainLabels(s_MnameLabels, p_RData);
    EncodeDomainLabels(s_RnameLabels, p_RData);
    p_RData.insert(p_RData.end(), s_DataBytes + s_Offset, s_DataBytes + s_Offset + 20);
    return true;
  }

  if (p_TypeHost == 15) {
    // MX: uint16 preference + domain name
    if (p_RdataOffset + 2 > p_Size) {
      return false;
    }
    std::vector<std::string> s_ExchangeLabels;
    size_type s_Offset{p_RdataOffset + 2};
    if (!ParseDomainName(p_Data, p_Size, s_Offset, s_ExchangeLabels)) {
      return false;
    }
    p_RData.clear();
    p_RData.push_back(s_DataBytes[p_RdataOffset]);
    p_RData.push_back(s_DataBytes[p_RdataOffset + 1]);
    EncodeDomainLabels(s_ExchangeLabels, p_RData);
    return true;
  }

  if (p_TypeHost == 33) {
    // SRV: uint16 priority + uint16 weight + uint16 port + domain name
    if (p_RdataOffset + 6 > p_Size) {
      return false;
    }
    std::vector<std::string> s_TargetLabels;
    size_type s_Offset{p_RdataOffset + 6};
    if (!ParseDomainName(p_Data, p_Size, s_Offset, s_TargetLabels)) {
      return false;
    }
    p_RData.clear();
    p_RData.insert(p_RData.end(), s_DataBytes + p_RdataOffset, s_DataBytes + p_RdataOffset + 6);
    EncodeDomainLabels(s_TargetLabels, p_RData);
    return true;
  }

  return false; // Not a domain-name record type
}

bool DnsAnswer::FromWire(const void *p_Data, size_type p_Size, size_type &p_Offset, DnsAnswer &p_OutAnswer) {
  if (!p_Data) {
    return false;
  }

  // Parse NAME
  std::vector<std::string> s_Labels;
  if (!ParseDomainName(p_Data, p_Size, p_Offset, s_Labels)) {
    return false;
  }

  // Parse TYPE, CLASS, TTL, RDLENGTH (10 bytes)
  if (p_Offset + 10 > p_Size) {
    return false;
  }

  const char *s_DataBytes{static_cast<const char *>(p_Data)};

  uint16_t s_Type;
  uint16_t s_Class;
  uint32_t s_Ttl;
  uint16_t s_RdLength;
  std::copy(s_DataBytes + p_Offset, s_DataBytes + p_Offset + sizeof(uint16_t), reinterpret_cast<char *>(&s_Type));
  std::copy(s_DataBytes + p_Offset + 2, s_DataBytes + p_Offset + 2 + sizeof(uint16_t), reinterpret_cast<char *>(&s_Class));
  std::copy(s_DataBytes + p_Offset + 4, s_DataBytes + p_Offset + 4 + sizeof(uint32_t), reinterpret_cast<char *>(&s_Ttl));
  std::copy(s_DataBytes + p_Offset + 8, s_DataBytes + p_Offset + 8 + sizeof(uint16_t), reinterpret_cast<char *>(&s_RdLength));

  p_Offset += 10;

  // Parse RDATA
  uint16_t s_RdLengthHost{NetworkToHost(s_RdLength)};
  if (p_Offset + s_RdLengthHost > p_Size) {
    return false;
  }

  size_type s_RdataOffset{p_Offset};
  std::vector<char> s_RData(s_DataBytes + p_Offset, s_DataBytes + p_Offset + s_RdLengthHost);
  p_Offset += s_RdLengthHost;

  // Decompress RDATA domain names for record types that contain them.
  // Compression pointers in RDATA reference offsets in the full packet, not within
  // the RDATA buffer itself. Re-encoding without compression makes the stored RDATA
  // self-contained and safe for later use (e.g., RdataAsDomainName()).
  uint16_t s_TypeHost{NetworkToHost(s_Type)};
  if (s_TypeHost == 2 || s_TypeHost == 5 || s_TypeHost == 6 || s_TypeHost == 12 || s_TypeHost == 15 || s_TypeHost == 33) {
    DecompressRDATA(p_Data, p_Size, s_RdataOffset, s_TypeHost, s_RData);
  }

  // Update member variables
  p_OutAnswer.m_Name_ = std::move(s_Labels);
  p_OutAnswer.m_Type_ = s_Type;
  p_OutAnswer.m_Class_ = s_Class;
  p_OutAnswer.m_Ttl_ = s_Ttl;
  p_OutAnswer.m_Rdata_ = std::move(s_RData);
  p_OutAnswer.UpdateRDLENGTH();

  return true;
}

DnsAnswer::size_type DnsAnswer::ToWire(void *p_Data, size_type p_Size) const noexcept {
  if (!p_Data) {
    return 0;
  }

  size_type s_RequiredSize{WireSize()};
  if (p_Size < s_RequiredSize) {
    return 0;
  }

  char *s_Output{static_cast<char *>(p_Data)};
  size_type s_Offset{0};

  // Serialize NAME
  for (const std::string &l_Label : m_Name_) {
    if (l_Label.size() > 63) {
      continue; // Skip invalid labels
    }
    s_Output[s_Offset++] = static_cast<char>(l_Label.size());
    std::copy(l_Label.begin(), l_Label.end(), s_Output + s_Offset);
    s_Offset += l_Label.size();
  }
  s_Output[s_Offset++] = '\0'; // Null terminator

  // Serialize TYPE, CLASS, TTL, RDLENGTH (raw network order)
  const char *s_TypeSource{reinterpret_cast<const char *>(&m_Type_)};
  std::copy(s_TypeSource, s_TypeSource + 2, s_Output + s_Offset);
  s_Offset += 2;
  const char *s_ClassSource{reinterpret_cast<const char *>(&m_Class_)};
  std::copy(s_ClassSource, s_ClassSource + 2, s_Output + s_Offset);
  s_Offset += 2;
  const char *s_TtlSource{reinterpret_cast<const char *>(&m_Ttl_)};
  std::copy(s_TtlSource, s_TtlSource + 4, s_Output + s_Offset);
  s_Offset += 4;
  const char *s_RdlengthSource{reinterpret_cast<const char *>(&m_Rdlength_)};
  std::copy(s_RdlengthSource, s_RdlengthSource + 2, s_Output + s_Offset);
  s_Offset += 2;

  // Serialize RDATA
  if (!m_Rdata_.empty()) {
    std::copy(m_Rdata_.begin(), m_Rdata_.end(), s_Output + s_Offset);
    s_Offset += m_Rdata_.size();
  }

  return s_Offset;
}

bool DnsAnswer::operator==(const DnsAnswer &p_Other) const noexcept {
  return m_Name_ == p_Other.m_Name_ && m_Type_ == p_Other.m_Type_ && m_Class_ == p_Other.m_Class_ && m_Ttl_ == p_Other.m_Ttl_ && m_Rdata_ == p_Other.m_Rdata_;
}

bool DnsAnswer::operator!=(const DnsAnswer &p_Other) const noexcept {
  return !(*this == p_Other);
}

bool DnsAnswer::operator<(const DnsAnswer &p_Other) const noexcept {
  if (m_Name_ != p_Other.m_Name_) {
    return m_Name_ < p_Other.m_Name_;
  }
  if (m_Type_ != p_Other.m_Type_) {
    return NetworkToHost(m_Type_) < NetworkToHost(p_Other.m_Type_);
  }
  if (m_Class_ != p_Other.m_Class_) {
    return NetworkToHost(m_Class_) < NetworkToHost(p_Other.m_Class_);
  }
  if (m_Ttl_ != p_Other.m_Ttl_) {
    return NetworkToHost(m_Ttl_) < NetworkToHost(p_Other.m_Ttl_);
  }
  return m_Rdata_ < p_Other.m_Rdata_;
}

bool DnsAnswer::IsValidLabel(const std::string &p_Label) noexcept {
  if (p_Label.empty() || p_Label.length() > 63) {
    return false; // Empty or too long
  }

  // Check for valid characters (letters, digits, hyphens)
  // Must not start or end with hyphen
  if (p_Label.front() == '-' || p_Label.back() == '-') {
    return false;
  }

  // Allow underscores for SRV/DKIM/DNSKEY records (e.g. _sip._tcp, _dmarc)
  return std::all_of(p_Label.begin(), p_Label.end(), [](char l_Char) { return std::isalnum(static_cast<unsigned char>(l_Char)) || l_Char == '-' || l_Char == '_'; });
}

DnsAnswer::size_type DnsAnswer::CalculateStringSize() const noexcept {
  size_type s_Size{std::accumulate(m_Name_.begin(), m_Name_.end(), size_type{0}, [](size_type s_Sum, const std::string &l_Label) {
    return s_Sum + l_Label.size() + 1; // +1 for dot
  })};
  return s_Size > 0 ? s_Size - 1 : 0; // Remove last dot
}

bool DnsAnswer::ParseDomainName(const void *p_Data, size_type p_Size, size_type &p_Offset, std::vector<std::string> &p_Labels) {
  const char *s_DataBytes{static_cast<const char *>(p_Data)};
  int s_PointerHops{0};
  size_type s_ReadOffset{p_Offset};
  bool s_FollowedPointer{false};

  while (s_ReadOffset < p_Size) {
    uint8_t s_Length{static_cast<uint8_t>(s_DataBytes[s_ReadOffset])};

    if (s_Length == 0) {
      // Null terminator - end of domain name
      if (!s_FollowedPointer) {
        p_Offset = s_ReadOffset + 1;
      }
      return true;
    }

    if ((s_Length & 0xC0) == 0xC0) {
      // Compression pointer
      if (s_ReadOffset + 1 >= p_Size) {
        return false;
      }
      if (++s_PointerHops > Constants::Dns::DNS_MAX_POINTER_HOPS) {
        return false; // Too many pointer hops - likely a loop
      }
      // Save the offset past the pointer for the caller (only once)
      if (!s_FollowedPointer) {
        p_Offset = s_ReadOffset + 2;
        s_FollowedPointer = true;
      }
      // Follow the pointer
      s_ReadOffset = static_cast<size_type>((s_Length & 0x3F) << 8) | static_cast<uint8_t>(s_DataBytes[s_ReadOffset + 1]);
      continue;
    }

    if (s_Length > 63) {
      // Invalid label length
      return false;
    }

    s_ReadOffset++;
    if (s_ReadOffset + s_Length > p_Size) {
      return false;
    }

    std::string s_Label(s_DataBytes + s_ReadOffset, s_Length);
    p_Labels.push_back(s_Label);
    s_ReadOffset += s_Length;
  }

  return false; // Reached end without null terminator
}

void DnsAnswer::UpdateRDLENGTH() noexcept {
  assert(m_Rdata_.size() <= UINT16_MAX);
  m_Rdlength_ = HostToNetwork(static_cast<uint16_t>(m_Rdata_.size()));
}

std::ostream &operator<<(std::ostream &p_OutputStream, const DnsAnswer &p_Answer) {
  return p_OutputStream << "DnsAnswer{name=\"" << p_Answer.NameAsString() << "\", type=" << p_Answer.Type() << ", class=" << p_Answer.Rclass() << ", ttl=" << p_Answer.Ttl() << ", rdlength=" << p_Answer.Rdlength() << "}";
}

void swap(DnsAnswer &p_LeftSide, DnsAnswer &p_RightSide) noexcept {
  p_LeftSide.swap(p_RightSide);
}

namespace std {
DnsAnswer::size_type hash<DnsAnswer>::operator()(const DnsAnswer &p_Answer) const noexcept {
  return p_Answer.Hash();
}
} // namespace std
