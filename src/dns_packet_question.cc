// Self
#include "dns_packet_question.h"

// C

// C++
#include <algorithm>  // std::all_of, std::copy, std::copy_if
#include <cctype>     // std::isalnum
#include <cstdint>    // uint8_t, uint16_t
#include <functional> // std::hash
#include <numeric>    // std::accumulate
#include <ostream>    // std::ostream
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

DnsQuestion::DnsQuestion(const char *p_Data, size_type p_Size) {
  size_type s_Offset{0};
  if (!FromWire(p_Data, p_Size, s_Offset, *this)) {
    throw std::invalid_argument("DnsQuestion: invalid or insufficient data");
  }
}

DnsQuestion::DnsQuestion(const char *p_Data, size_type p_Size, size_type &p_Offset) {
  if (!FromWire(p_Data, p_Size, p_Offset, *this)) {
    throw std::invalid_argument("DnsQuestion: invalid or insufficient data");
  }
}

DnsQuestion::DnsQuestion(const std::string &p_Data) {
  size_type s_Offset{0};
  if (!FromWire(p_Data.data(), p_Data.size(), s_Offset, *this)) {
    throw std::invalid_argument("DnsQuestion: invalid string data");
  }
}

DnsQuestion::DnsQuestion(const std::string &p_Data, size_type &p_Offset) {
  if (!FromWire(p_Data.data(), p_Data.size(), p_Offset, *this)) {
    throw std::invalid_argument("DnsQuestion: invalid string data");
  }
}

DnsQuestion::DnsQuestion(const std::vector<char> &p_Data) {
  size_type s_Offset{0};
  if (!FromWire(p_Data.data(), p_Data.size(), s_Offset, *this)) {
    throw std::invalid_argument("DnsQuestion: invalid vector data");
  }
}

DnsQuestion::DnsQuestion(const std::vector<char> &p_Data, size_type &p_Offset) {
  if (!FromWire(p_Data.data(), p_Data.size(), p_Offset, *this)) {
    throw std::invalid_argument("DnsQuestion: invalid vector data");
  }
}

DnsQuestion::DnsQuestion(const std::vector<unsigned char> &p_Data) {
  size_type s_Offset{0};
  if (!FromWire(reinterpret_cast<const char *>(p_Data.data()), p_Data.size(), s_Offset, *this)) {
    throw std::invalid_argument("DnsQuestion: invalid vector data");
  }
}

DnsQuestion::DnsQuestion(const std::vector<unsigned char> &p_Data, size_type &p_Offset) {
  if (!FromWire(reinterpret_cast<const char *>(p_Data.data()), p_Data.size(), p_Offset, *this)) {
    throw std::invalid_argument("DnsQuestion: invalid vector data");
  }
}

DnsQuestion::DnsQuestion(const std::string &p_DomainName, uint16_t p_Type, uint16_t p_Class) {
  SetQnameFromString(p_DomainName);
  SetQtype(p_Type);
  SetQclass(p_Class);
}

DnsQuestion::DnsQuestion(std::vector<std::string> p_Labels, uint16_t p_Type, uint16_t p_Class) : m_Qname_(std::move(p_Labels)) {
  SetQtype(p_Type);
  SetQclass(p_Class);
}

DnsQuestion DnsQuestion::MakeAQuery(const std::string &p_DomainName) {
  DnsQuestion s_Question;
  s_Question.SetQnameFromString(p_DomainName);
  s_Question.SetQtype(1);
  s_Question.SetQclass(1);
  return s_Question;
}

DnsQuestion DnsQuestion::MakeNsQuery(const std::string &p_DomainName) {
  DnsQuestion s_Question;
  s_Question.SetQnameFromString(p_DomainName);
  s_Question.SetQtype(2);
  s_Question.SetQclass(1);
  return s_Question;
}

DnsQuestion DnsQuestion::MakeCnameQuery(const std::string &p_DomainName) {
  DnsQuestion s_Question;
  s_Question.SetQnameFromString(p_DomainName);
  s_Question.SetQtype(5);
  s_Question.SetQclass(1);
  return s_Question;
}

DnsQuestion DnsQuestion::MakeSoaQuery(const std::string &p_DomainName) {
  DnsQuestion s_Question;
  s_Question.SetQnameFromString(p_DomainName);
  s_Question.SetQtype(6);
  s_Question.SetQclass(1);
  return s_Question;
}

DnsQuestion DnsQuestion::MakePtrQuery(const std::string &p_IpAddress) {
  DnsQuestion s_Question;
  s_Question.SetPTRFromIp(p_IpAddress);
  s_Question.SetQtype(12);
  s_Question.SetQclass(1);
  return s_Question;
}

DnsQuestion DnsQuestion::MakeMxQuery(const std::string &p_DomainName) {
  DnsQuestion s_Question;
  s_Question.SetQnameFromString(p_DomainName);
  s_Question.SetQtype(15);
  s_Question.SetQclass(1);
  return s_Question;
}

DnsQuestion DnsQuestion::MakeTxtQuery(const std::string &p_DomainName) {
  DnsQuestion s_Question;
  s_Question.SetQnameFromString(p_DomainName);
  s_Question.SetQtype(16);
  s_Question.SetQclass(1);
  return s_Question;
}

DnsQuestion DnsQuestion::MakeAaaaQuery(const std::string &p_DomainName) {
  DnsQuestion s_Question;
  s_Question.SetQnameFromString(p_DomainName);
  s_Question.SetQtype(28);
  s_Question.SetQclass(1);
  return s_Question;
}

DnsQuestion DnsQuestion::MakeSrvQuery(const std::string &p_DomainName) {
  DnsQuestion s_Question;
  s_Question.SetQnameFromString(p_DomainName);
  s_Question.SetQtype(33);
  s_Question.SetQclass(1);
  return s_Question;
}

const std::vector<std::string> &DnsQuestion::Qname() const noexcept {
  return m_Qname_;
}

uint16_t DnsQuestion::Qtype(bool p_Raw) const noexcept {
  return p_Raw ? m_Qtype_ : NetworkToHost(m_Qtype_);
}

uint16_t DnsQuestion::Qclass(bool p_Raw) const noexcept {
  return p_Raw ? m_Qclass_ : NetworkToHost(m_Qclass_);
}

std::string DnsQuestion::QnameAsString() const {
  if (m_Qname_.empty()) {
    return "";
  }

  std::string s_Result;
  s_Result.reserve(CalculateStringSize());

  for (size_type i{0}; i < m_Qname_.size(); ++i) {
    if (i > 0) {
      s_Result += '.';
    }
    s_Result += m_Qname_[i];
  }
  return s_Result;
}

std::string DnsQuestion::Fqdn() const {
  std::string s_Result{QnameAsString()};
  if (!s_Result.empty()) {
    s_Result += '.';
  }
  return s_Result;
}

void DnsQuestion::SetQname(const std::vector<std::string> &p_Labels) {
  m_Qname_.clear();
  m_Qname_.reserve(p_Labels.size());

  std::copy_if(p_Labels.begin(), p_Labels.end(), std::back_inserter(m_Qname_), [](const std::string &l_Label) { return DnsQuestion::IsValidLabel(l_Label); });
}

void DnsQuestion::SetQnameFromString(const std::string &p_DomainName) {
  m_Qname_.clear();

  if (p_DomainName.empty()) {
    return;
  }

  std::string s_Domain{p_DomainName};
  // Remove trailing dot if present, don't need to check for empty as it's checked above before assignment
  if (s_Domain.back() == '.') {
    s_Domain.pop_back();
  }

  size_type s_Start{0};
  size_type s_Position{0};

  while ((s_Position = s_Domain.find('.', s_Start)) != std::string::npos) {
    std::string s_Label{s_Domain.substr(s_Start, s_Position - s_Start)};
    if (IsValidLabel(s_Label)) {
      m_Qname_.push_back(s_Label);
    }
    s_Start = s_Position + 1;
  }

  // Add final label if any
  if (s_Start < s_Domain.length()) {
    std::string s_Label{s_Domain.substr(s_Start)};
    if (IsValidLabel(s_Label)) {
      m_Qname_.push_back(s_Label);
    }
  }
}

void DnsQuestion::SetQtype(uint16_t p_Type, bool p_Raw) noexcept {
  m_Qtype_ = p_Raw ? p_Type : HostToNetwork(p_Type);
}

void DnsQuestion::SetQclass(uint16_t p_Class, bool p_Raw) noexcept {
  m_Qclass_ = p_Raw ? p_Class : HostToNetwork(p_Class);
}

bool DnsQuestion::AddLabel(const std::string &p_Label) {
  if (IsValidLabel(p_Label)) {
    m_Qname_.push_back(p_Label);
    return true;
  }
  return false;
}

bool DnsQuestion::PrependLabel(const std::string &p_Label) {
  if (IsValidLabel(p_Label)) {
    m_Qname_.insert(m_Qname_.begin(), p_Label);
    return true;
  }
  return false;
}

bool DnsQuestion::PopLabel() noexcept {
  if (!m_Qname_.empty()) {
    m_Qname_.pop_back();
    return true;
  }
  return false;
}

bool DnsQuestion::RemoveFirstLabel() noexcept {
  if (!m_Qname_.empty()) {
    m_Qname_.erase(m_Qname_.begin());
    return true;
  }
  return false;
}

void DnsQuestion::swap(DnsQuestion &p_Other) noexcept {
  std::swap(m_Qname_, p_Other.m_Qname_);
  std::swap(m_Qtype_, p_Other.m_Qtype_);
  std::swap(m_Qclass_, p_Other.m_Qclass_);
}

bool DnsQuestion::empty() const noexcept {
  return m_Qname_.empty();
}

DnsQuestion::size_type DnsQuestion::size() const noexcept {
  return m_Qname_.size();
}

DnsQuestion::size_type DnsQuestion::max_size() const noexcept {
  return m_Qname_.max_size();
}

void DnsQuestion::reserve(size_type p_Size) {
  m_Qname_.reserve(p_Size);
}

void DnsQuestion::clear() noexcept {
  m_Qname_.clear();
  m_Qtype_ = 0;
  m_Qclass_ = 0;
}

void DnsQuestion::resize(size_type p_Size, const std::string &p_Value) {
  m_Qname_.resize(p_Size, p_Value);
}

DnsQuestion::iterator DnsQuestion::begin() noexcept {
  return m_Qname_.begin();
}

DnsQuestion::const_iterator DnsQuestion::begin() const noexcept {
  return m_Qname_.begin();
}

DnsQuestion::const_iterator DnsQuestion::cbegin() const noexcept {
  return m_Qname_.cbegin();
}

DnsQuestion::iterator DnsQuestion::end() noexcept {
  return m_Qname_.end();
}

DnsQuestion::const_iterator DnsQuestion::end() const noexcept {
  return m_Qname_.end();
}

DnsQuestion::const_iterator DnsQuestion::cend() const noexcept {
  return m_Qname_.cend();
}

DnsQuestion::reverse_iterator DnsQuestion::rbegin() noexcept {
  return m_Qname_.rbegin();
}

DnsQuestion::const_reverse_iterator DnsQuestion::rbegin() const noexcept {
  return m_Qname_.rbegin();
}

DnsQuestion::const_reverse_iterator DnsQuestion::crbegin() const noexcept {
  return m_Qname_.crbegin();
}

DnsQuestion::reverse_iterator DnsQuestion::rend() noexcept {
  return m_Qname_.rend();
}

DnsQuestion::const_reverse_iterator DnsQuestion::rend() const noexcept {
  return m_Qname_.rend();
}

DnsQuestion::const_reverse_iterator DnsQuestion::crend() const noexcept {
  return m_Qname_.crend();
}

DnsQuestion::reference DnsQuestion::at(size_type p_Index) {
  return m_Qname_.at(p_Index);
}

DnsQuestion::const_reference DnsQuestion::at(size_type p_Index) const {
  return m_Qname_.at(p_Index);
}

DnsQuestion::reference DnsQuestion::operator[](size_type p_Index) noexcept {
  return m_Qname_[p_Index];
}

DnsQuestion::const_reference DnsQuestion::operator[](size_type p_Index) const noexcept {
  return m_Qname_[p_Index];
}

DnsQuestion::reference DnsQuestion::front() noexcept {
  return m_Qname_.front();
}

DnsQuestion::const_reference DnsQuestion::front() const noexcept {
  return m_Qname_.front();
}

DnsQuestion::reference DnsQuestion::back() noexcept {
  return m_Qname_.back();
}

DnsQuestion::const_reference DnsQuestion::back() const noexcept {
  return m_Qname_.back();
}

bool DnsQuestion::Valid() const noexcept {
  if (m_Qname_.empty()) {
    // Is "root domain"
    return true;
  }

  size_type s_TotalLength{0};
  for (const std::string &l_Label : m_Qname_) {
    if (!IsValidLabel(l_Label)) {
      return false;
    }
    s_TotalLength += l_Label.length() + 1; // +1 for length byte
  }
  s_TotalLength += 1; // +1 for null terminator

  return s_TotalLength <= 255; // DNS name length limit
}

DnsQuestion::size_type DnsQuestion::Hash() const noexcept {
  size_type s_Result = std::accumulate(m_Qname_.begin(), m_Qname_.end(), size_type{0}, [](size_type s_Result, const std::string &l_Label) { return s_Result ^ (std::hash<std::string>{}(l_Label) + 0x9e3779b9 + (s_Result << 6) + (s_Result >> 2)); });

  // Combine with type and class
  s_Result ^= std::hash<uint16_t>{}(m_Qtype_) + 0x9e3779b9 + (s_Result << 6) + (s_Result >> 2);
  s_Result ^= std::hash<uint16_t>{}(m_Qclass_) + 0x9e3779b9 + (s_Result << 6) + (s_Result >> 2);

  return s_Result;
}

void *DnsQuestion::data() noexcept {
  return m_Qname_.data();
}

const void *DnsQuestion::data() const noexcept {
  return m_Qname_.data();
}

DnsQuestion::size_type DnsQuestion::WireSize() const noexcept {
  // QNAME size (length bytes + label data + null terminator)
  size_type s_Size{std::accumulate(m_Qname_.begin(), m_Qname_.end(), size_type{0}, [](size_type s_Sum, const std::string &l_Label) { return l_Label.size() <= 63 ? s_Sum + 1 + l_Label.size() : s_Sum; })};
  s_Size += 1; // Null terminator

  s_Size += 4; // QTYPE + QCLASS

  return s_Size;
}

bool DnsQuestion::FromWire(const void *p_Data, size_type p_Size, size_type &p_Offset, DnsQuestion &p_OutQuestion) {
  if (!p_Data) {
    return false;
  }

  // Parse QNAME
  std::vector<std::string> s_Labels;
  if (!ParseDomainName(p_Data, p_Size, p_Offset, s_Labels)) {
    return false;
  }

  // Parse QTYPE and QCLASS (4 bytes)
  if (p_Offset + 4 > p_Size) {
    return false;
  }

  const char *s_DataBytes{static_cast<const char *>(p_Data)};
  p_OutQuestion.m_Qname_ = std::move(s_Labels);
  std::copy(s_DataBytes + p_Offset, s_DataBytes + p_Offset + sizeof(uint16_t), reinterpret_cast<char *>(&p_OutQuestion.m_Qtype_));
  std::copy(s_DataBytes + p_Offset + 2, s_DataBytes + p_Offset + 2 + sizeof(uint16_t), reinterpret_cast<char *>(&p_OutQuestion.m_Qclass_));
  p_Offset += 4;

  return true;
}

DnsQuestion::size_type DnsQuestion::ToWire(void *p_Data, size_type p_Size) const noexcept {
  if (!p_Data) {
    return 0;
  }

  size_type s_RequiredSize{WireSize()};
  if (p_Size < s_RequiredSize) {
    return 0;
  }

  char *s_Output{static_cast<char *>(p_Data)};
  size_type s_Offset{0};

  // Serialize QNAME
  for (const std::string &l_Label : m_Qname_) {
    if (l_Label.size() > 63) {
      continue; // Skip invalid labels
    }
    s_Output[s_Offset++] = static_cast<char>(l_Label.size());
    std::copy(l_Label.begin(), l_Label.end(), s_Output + s_Offset);
    s_Offset += l_Label.size();
  }
  s_Output[s_Offset++] = '\0'; // Null terminator

  // Serialize QTYPE and QCLASS (raw network order)
  const char *s_TypeSource{reinterpret_cast<const char *>(&m_Qtype_)};
  std::copy(s_TypeSource, s_TypeSource + 2, s_Output + s_Offset);
  s_Offset += 2;
  const char *s_ClassSource{reinterpret_cast<const char *>(&m_Qclass_)};
  std::copy(s_ClassSource, s_ClassSource + 2, s_Output + s_Offset);
  s_Offset += 2;

  return s_Offset;
}

bool DnsQuestion::operator==(const DnsQuestion &p_Other) const noexcept {
  return m_Qname_ == p_Other.m_Qname_ && m_Qtype_ == p_Other.m_Qtype_ && m_Qclass_ == p_Other.m_Qclass_;
}

bool DnsQuestion::operator!=(const DnsQuestion &p_Other) const noexcept {
  return !(*this == p_Other);
}

bool DnsQuestion::operator<(const DnsQuestion &p_Other) const noexcept {
  if (m_Qname_ != p_Other.m_Qname_) {
    return m_Qname_ < p_Other.m_Qname_;
  }
  if (m_Qtype_ != p_Other.m_Qtype_) {
    return NetworkToHost(m_Qtype_) < NetworkToHost(p_Other.m_Qtype_);
  }
  return NetworkToHost(m_Qclass_) < NetworkToHost(p_Other.m_Qclass_);
}

bool DnsQuestion::IsValidLabel(const std::string &p_Label) noexcept {
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

DnsQuestion::size_type DnsQuestion::CalculateStringSize() const noexcept {
  size_type s_Size{std::accumulate(m_Qname_.begin(), m_Qname_.end(), size_type{0}, [](size_type s_Sum, const std::string &l_Label) {
    return s_Sum + l_Label.size() + 1; // +1 for dot
  })};
  return s_Size > 0 ? s_Size - 1 : 0; // Remove last dot
}

bool DnsQuestion::ParseDomainName(const void *p_Data, size_type p_Size, size_type &p_Offset, std::vector<std::string> &p_Labels) {
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

void DnsQuestion::SetPTRFromIp(const std::string &p_IpAddress) {
  m_Qname_.clear();

  if (p_IpAddress.empty()) {
    return;
  }

  if (p_IpAddress.find(':') != std::string::npos) {
    // IPv6 - expand to full 32 hex nibbles, reverse, append ip6.arpa
    // 1. Parse groups, handling :: expansion
    std::string s_Left;
    std::string s_Right;
    bool s_HasDoubleColon{false};
    size_type s_DoubleColon{p_IpAddress.find("::")};

    if (s_DoubleColon != std::string::npos) {
      s_HasDoubleColon = true;
      s_Left = p_IpAddress.substr(0, s_DoubleColon);
      s_Right = p_IpAddress.substr(s_DoubleColon + 2);
    } else {
      s_Left = p_IpAddress;
    }

    auto SplitByColon = [](const std::string &l_Str) {
      std::vector<std::string> l_Parts;
      if (l_Str.empty()) {
        return l_Parts;
      }
      size_type l_Start{0};
      size_type l_Pos{0};
      while ((l_Pos = l_Str.find(':', l_Start)) != std::string::npos) {
        l_Parts.push_back(l_Str.substr(l_Start, l_Pos - l_Start));
        l_Start = l_Pos + 1;
      }
      l_Parts.push_back(l_Str.substr(l_Start));
      return l_Parts; };

    std::vector<std::string> s_LeftParts{SplitByColon(s_Left)};
    std::vector<std::string> s_RightParts{SplitByColon(s_Right)};

    // 2. Build full 8-group list
    std::vector<std::string> s_Groups;
    s_Groups.reserve(8);
    s_Groups.insert(s_Groups.end(), s_LeftParts.begin(), s_LeftParts.end());
    if (s_HasDoubleColon) {
      size_type s_ExistingGroups{s_LeftParts.size() + s_RightParts.size()};
      if (s_ExistingGroups > 8) {
        return; // Invalid IPv6
      }
      size_type s_MissingGroups{8 - s_ExistingGroups};
      for (size_type i{0}; i < s_MissingGroups; ++i) {
        s_Groups.emplace_back("0");
      }
    }
    s_Groups.insert(s_Groups.end(), s_RightParts.begin(), s_RightParts.end());
    if (s_Groups.size() != 8) {
      return; // Invalid IPv6
    }

    // 3. Pad each group to 4 hex chars and collect all 32 nibbles
    std::string s_Expanded;
    s_Expanded.reserve(32);
    for (const std::string &l_Group : s_Groups) {
      if (l_Group.size() > 4) {
        return; // Invalid group
      }
      for (size_type i{l_Group.size()}; i < 4; ++i) {
        s_Expanded += '0';
      }
      for (char l_Char : l_Group) {
        s_Expanded += static_cast<char>(std::tolower(static_cast<unsigned char>(l_Char)));
      }
    }

    // 4. Reverse nibble-by-nibble, each nibble as a separate label
    for (std::string::const_reverse_iterator l_It{s_Expanded.crbegin()}; l_It != s_Expanded.crend(); ++l_It) {
      m_Qname_.push_back(std::string(1, *l_It));
    }
    m_Qname_.push_back("ip6");
    m_Qname_.push_back("arpa");
  } else {
    // IPv4 - reverse the octets and add in-addr.arpa
    std::vector<std::string> s_Octets;
    size_type s_Start{0};
    size_type s_Position{0};

    while ((s_Position = p_IpAddress.find('.', s_Start)) != std::string::npos) {
      s_Octets.push_back(p_IpAddress.substr(s_Start, s_Position - s_Start));
      s_Start = s_Position + 1;
    }
    if (s_Start < p_IpAddress.length()) {
      s_Octets.push_back(p_IpAddress.substr(s_Start));
    }

    // Reverse and add to QNAME
    for (std::vector<std::string>::reverse_iterator l_Iterator{s_Octets.rbegin()}; l_Iterator != s_Octets.rend(); ++l_Iterator) {
      m_Qname_.push_back(*l_Iterator);
    }
    m_Qname_.push_back("in-addr");
    m_Qname_.push_back("arpa");
  }
}

std::ostream &operator<<(std::ostream &p_OutputStream, const DnsQuestion &p_Question) {
  return p_OutputStream << "DnsQuestion{qname=\"" << p_Question.QnameAsString() << "\", qtype=" << p_Question.Qtype() << ", qclass=" << p_Question.Qclass() << "}";
}

void swap(DnsQuestion &p_LeftSide, DnsQuestion &p_RightSide) noexcept {
  p_LeftSide.swap(p_RightSide);
}

namespace std {
DnsQuestion::size_type hash<DnsQuestion>::operator()(const DnsQuestion &p_Question) const noexcept {
  return p_Question.Hash();
}
} // namespace std
