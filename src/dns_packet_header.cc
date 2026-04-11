// Self
#include "dns_packet_header.h"

// C

// C++
#include <algorithm>  // std::copy
#include <cstdint>    // uint8_t, uint16_t, uint32_t, uint64_t
#include <functional> // std::hash
#include <ostream>    // std::ostream
#include <stdexcept>  // std::invalid_argument
#include <string>     // std::string
#include <utility>    // std::swap
#include <vector>     // std::vector

// Other libraries

// This Project's
#include "utils.h" // HostToNetwork, NetworkToHost

// Logging
#include "libLog.h"

// Banned
#include "banned.h"

DnsHeader::DnsHeader(const char *p_Data) {
  if (!p_Data) {
    throw std::invalid_argument("DnsHeader: null data pointer");
  }
  if (!FromWire(p_Data, HeaderSize, *this)) {
    throw std::invalid_argument("DnsHeader: invalid data format");
  }
}

DnsHeader::DnsHeader(const char *p_Data, size_type p_Size) {
  if (!p_Data) {
    throw std::invalid_argument("DnsHeader: null data pointer");
  }
  if (p_Size < HeaderSize) {
    throw std::invalid_argument("DnsHeader: insufficient data size (need 12 bytes)");
  }
  if (!FromWire(p_Data, p_Size, *this)) {
    throw std::invalid_argument("DnsHeader: invalid data format");
  }
}

DnsHeader::DnsHeader(const std::string &p_Data) {
  if (p_Data.size() < HeaderSize) {
    throw std::invalid_argument("DnsHeader: string too short (need 12 bytes)");
  }
  if (!FromWire(p_Data.data(), p_Data.size(), *this)) {
    throw std::invalid_argument("DnsHeader: invalid data format");
  }
}

DnsHeader::DnsHeader(const std::vector<char> &p_Data) {
  if (p_Data.size() < HeaderSize) {
    throw std::invalid_argument("DnsHeader: vector too short (need 12 bytes)");
  }
  if (!FromWire(p_Data.data(), p_Data.size(), *this)) {
    throw std::invalid_argument("DnsHeader: invalid data format");
  }
}

DnsHeader::DnsHeader(const std::vector<unsigned char> &p_Data) {
  if (p_Data.size() < HeaderSize) {
    throw std::invalid_argument("DnsHeader: vector too short (need 12 bytes)");
  }
  if (!FromWire(p_Data.data(), p_Data.size(), *this)) {
    throw std::invalid_argument("DnsHeader: invalid data format");
  }
}

DnsHeader::DnsHeader(uint16_t p_Id, uint16_t p_Flags, uint16_t p_Qdcount, uint16_t p_Ancount, uint16_t p_Nscount, uint16_t p_Arcount) {
  SetId(p_Id);
  SetFlags(p_Flags);
  SetQdcount(p_Qdcount);
  SetAncount(p_Ancount);
  SetNscount(p_Nscount);
  SetArcount(p_Arcount);
}

DnsHeader DnsHeader::MakeQueryHeader(uint16_t p_Id, uint8_t p_Opcode, bool p_RecursionDesired, uint16_t p_QuestionCount) {
  DnsHeader s_Header;
  s_Header.SetId(p_Id);
  s_Header.SetQr(false);
  s_Header.SetOpcode(p_Opcode);
  s_Header.SetRd(p_RecursionDesired);
  s_Header.SetZ(false);
  s_Header.SetRcode(0);
  s_Header.SetQdcount(p_QuestionCount);
  return s_Header;
}

DnsHeader DnsHeader::MakeResponseHeader(const DnsHeader &p_QueryHeader, uint8_t p_Rcode, bool p_Authoritative, bool p_RecursionAvailable) {
  DnsHeader s_Header;
  s_Header.SetId(p_QueryHeader.Id());
  s_Header.SetQr(true);
  s_Header.SetOpcode(p_QueryHeader.Opcode());
  s_Header.SetAa(p_Authoritative);
  s_Header.SetRd(p_QueryHeader.Rd());
  s_Header.SetRa(p_RecursionAvailable);
  s_Header.SetZ(false);
  s_Header.SetRcode(p_Rcode);
  return s_Header;
}

uint16_t DnsHeader::Id(bool p_Raw) const noexcept {
  return p_Raw ? m_Id_ : NetworkToHost(m_Id_);
}

uint16_t DnsHeader::Flags(bool p_Raw) const noexcept {
  return p_Raw ? m_Flags_ : NetworkToHost(m_Flags_);
}

uint16_t DnsHeader::Qdcount(bool p_Raw) const noexcept {
  return p_Raw ? m_Qdcount_ : NetworkToHost(m_Qdcount_);
}

uint16_t DnsHeader::Ancount(bool p_Raw) const noexcept {
  return p_Raw ? m_Ancount_ : NetworkToHost(m_Ancount_);
}

uint16_t DnsHeader::Nscount(bool p_Raw) const noexcept {
  return p_Raw ? m_Nscount_ : NetworkToHost(m_Nscount_);
}

uint16_t DnsHeader::Arcount(bool p_Raw) const noexcept {
  return p_Raw ? m_Arcount_ : NetworkToHost(m_Arcount_);
}

bool DnsHeader::Qr(bool p_Raw) const noexcept {
  return (Flags(p_Raw) >> 15) & 0x1;
}

uint8_t DnsHeader::Opcode(bool p_Raw) const noexcept {
  return (Flags(p_Raw) >> 11) & 0xF;
}

bool DnsHeader::Aa(bool p_Raw) const noexcept {
  return (Flags(p_Raw) >> 10) & 0x1;
}

bool DnsHeader::Tc(bool p_Raw) const noexcept {
  return (Flags(p_Raw) >> 9) & 0x1;
}

bool DnsHeader::Rd(bool p_Raw) const noexcept {
  return (Flags(p_Raw) >> 8) & 0x1;
}

bool DnsHeader::Ra(bool p_Raw) const noexcept {
  return (Flags(p_Raw) >> 7) & 0x1;
}

bool DnsHeader::Z(bool p_Raw) const noexcept {
  return (Flags(p_Raw) >> 6) & 0x1;
}

bool DnsHeader::Ad(bool p_Raw) const noexcept {
  return (Flags(p_Raw) >> 5) & 0x1;
}

bool DnsHeader::Cd(bool p_Raw) const noexcept {
  return (Flags(p_Raw) >> 4) & 0x1;
}

uint8_t DnsHeader::Rcode(bool p_Raw) const noexcept {
  return Flags(p_Raw) & 0xF;
}

void DnsHeader::SetId(uint16_t p_Value, bool p_Raw) noexcept {
  m_Id_ = p_Raw ? p_Value : HostToNetwork(p_Value);
}

void DnsHeader::SetFlags(uint16_t p_Value, bool p_Raw) noexcept {
  m_Flags_ = p_Raw ? p_Value : HostToNetwork(p_Value);
}

void DnsHeader::SetQdcount(uint16_t p_Value, bool p_Raw) noexcept {
  m_Qdcount_ = p_Raw ? p_Value : HostToNetwork(p_Value);
}

void DnsHeader::SetAncount(uint16_t p_Value, bool p_Raw) noexcept {
  m_Ancount_ = p_Raw ? p_Value : HostToNetwork(p_Value);
}

void DnsHeader::SetNscount(uint16_t p_Value, bool p_Raw) noexcept {
  m_Nscount_ = p_Raw ? p_Value : HostToNetwork(p_Value);
}

void DnsHeader::SetArcount(uint16_t p_Value, bool p_Raw) noexcept {
  m_Arcount_ = p_Raw ? p_Value : HostToNetwork(p_Value);
}

void DnsHeader::SetQr(bool p_Value, bool p_Raw) noexcept {
  SetFlagBit(15, p_Value, p_Raw);
}

void DnsHeader::SetOpcode(uint8_t p_Value, bool p_Raw) noexcept {
  SetFlagValue(11, 0xF, p_Value, p_Raw);
}

void DnsHeader::SetAa(bool p_Value, bool p_Raw) noexcept {
  SetFlagBit(10, p_Value, p_Raw);
}

void DnsHeader::SetTc(bool p_Value, bool p_Raw) noexcept {
  SetFlagBit(9, p_Value, p_Raw);
}

void DnsHeader::SetRd(bool p_Value, bool p_Raw) noexcept {
  SetFlagBit(8, p_Value, p_Raw);
}

void DnsHeader::SetRa(bool p_Value, bool p_Raw) noexcept {
  SetFlagBit(7, p_Value, p_Raw);
}

void DnsHeader::SetZ(bool p_Value, bool p_Raw) noexcept {
  SetFlagBit(6, p_Value, p_Raw);
}

void DnsHeader::SetAd(bool p_Value, bool p_Raw) noexcept {
  SetFlagBit(5, p_Value, p_Raw);
}

void DnsHeader::SetCd(bool p_Value, bool p_Raw) noexcept {
  SetFlagBit(4, p_Value, p_Raw);
}

void DnsHeader::SetRcode(uint8_t p_Value, bool p_Raw) noexcept {
  SetFlagValue(0, 0xF, p_Value, p_Raw);
}

void DnsHeader::swap(DnsHeader &p_Other) noexcept {
  std::swap(m_Id_, p_Other.m_Id_);
  std::swap(m_Flags_, p_Other.m_Flags_);
  std::swap(m_Qdcount_, p_Other.m_Qdcount_);
  std::swap(m_Ancount_, p_Other.m_Ancount_);
  std::swap(m_Nscount_, p_Other.m_Nscount_);
  std::swap(m_Arcount_, p_Other.m_Arcount_);
}

bool DnsHeader::empty() const noexcept {
  return m_Flags_ == 0 && m_Qdcount_ == 0 && m_Ancount_ == 0 && m_Nscount_ == 0 && m_Arcount_ == 0;
}

DnsHeader::size_type DnsHeader::size() noexcept {
  return HeaderSize;
}

DnsHeader::size_type DnsHeader::max_size() noexcept {
  return HeaderSize;
}

void DnsHeader::UpdateCounts(uint16_t p_QuestionCount, uint16_t p_AnswerCount, uint16_t p_AuthorityCount, uint16_t p_AdditionalCount) noexcept {
  SetQdcount(p_QuestionCount);
  SetAncount(p_AnswerCount);
  SetNscount(p_AuthorityCount);
  SetArcount(p_AdditionalCount);
}

bool DnsHeader::CountsMatch(uint16_t p_ActualQuestions, uint16_t p_ActualAnswers, uint16_t p_ActualAuthority, uint16_t p_ActualAdditional) const noexcept {
  return Qdcount() == p_ActualQuestions && Ancount() == p_ActualAnswers && Nscount() == p_ActualAuthority && Arcount() == p_ActualAdditional;
}

uint32_t DnsHeader::TotalRecords() const noexcept {
  return static_cast<uint32_t>(Qdcount()) + Ancount() + Nscount() + Arcount();
}

uint16_t DnsHeader::IncrementCount(char p_Section) noexcept {
  switch (p_Section) {
  case 'q':
  case 'Q': {
    if (Qdcount() == UINT16_MAX) {
      return 0;
    }
    uint16_t s_NewCount{static_cast<uint16_t>(Qdcount() + 1)};
    SetQdcount(s_NewCount);
    return s_NewCount;
  }
  case 'a':
  case 'A': {
    if (Ancount() == UINT16_MAX) {
      return 0;
    }
    uint16_t s_NewCount{static_cast<uint16_t>(Ancount() + 1)};
    SetAncount(s_NewCount);
    return s_NewCount;
  }
  case 'n':
  case 'N': {
    if (Nscount() == UINT16_MAX) {
      return 0;
    }
    uint16_t s_NewCount{static_cast<uint16_t>(Nscount() + 1)};
    SetNscount(s_NewCount);
    return s_NewCount;
  }
  case 'r':
  case 'R': {
    if (Arcount() == UINT16_MAX) {
      return 0;
    }
    uint16_t s_NewCount{static_cast<uint16_t>(Arcount() + 1)};
    SetArcount(s_NewCount);
    return s_NewCount;
  }
  default:
    return 0;
  }
}

void DnsHeader::MakeResponse(const DnsHeader &p_Query) noexcept {
  SetId(p_Query.Id());
  SetQr(true);
  SetOpcode(p_Query.Opcode());
  SetRd(p_Query.Rd());
  SetRa(true);
}

void DnsHeader::MakeErrorResponse(const DnsHeader &p_QueryHeader, uint8_t p_ErrorCode) noexcept {
  MakeResponse(p_QueryHeader);
  SetRcode(p_ErrorCode);
  UpdateCounts(0, 0, 0, 0);
}

void DnsHeader::clear() noexcept {
  m_Id_ = m_Flags_ = m_Qdcount_ = m_Ancount_ = m_Nscount_ = m_Arcount_ = 0;
}

bool DnsHeader::Valid() const noexcept {
  return Z() == false;
}

bool DnsHeader::IsQuery() const noexcept {
  return !Qr();
}

bool DnsHeader::IsSimpleQuery() const noexcept {
  return IsQuery() && Qdcount() == 1 && Ancount() == 0 && Nscount() == 0 && Arcount() == 0;
}

bool DnsHeader::IsResponse() const noexcept {
  return Qr();
}

bool DnsHeader::HasError() const noexcept {
  return Rcode() != 0;
}

bool DnsHeader::IsStandardQuery() const noexcept {
  return Opcode() == 0;
}

DnsHeader::size_type DnsHeader::Hash() const noexcept {
  return std::hash<uint64_t>{}((static_cast<uint64_t>(m_Id_) << 48) | (static_cast<uint64_t>(m_Flags_) << 32) | (static_cast<uint64_t>(m_Qdcount_) << 16) | static_cast<uint64_t>(m_Ancount_)) ^ std::hash<uint32_t>{}((static_cast<uint32_t>(m_Nscount_) << 16) | static_cast<uint32_t>(m_Arcount_));
}

const void *DnsHeader::data() const noexcept {
  return &m_Id_;
}

void *DnsHeader::data() noexcept {
  return &m_Id_;
}

DnsHeader::size_type DnsHeader::WireSize() noexcept {
  return HeaderSize;
}

bool DnsHeader::FromWire(const void *p_Data, size_type p_Size, DnsHeader &p_OutHeader) noexcept {
  if (!p_Data || p_Size < HeaderSize) {
    return false;
  }

  try {
    // Direct memory copy since DNS header has fixed 12-byte format
    const char *s_Source{static_cast<const char *>(p_Data)};
    char *s_Destination{reinterpret_cast<char *>(&p_OutHeader.m_Id_)};
    std::copy(s_Source, s_Source + HeaderSize, s_Destination);

    // Validate the header
    if (!p_OutHeader.Valid()) {
      return false;
    }
    return true;
  } catch (...) {
    return false;
  }
}

DnsHeader::size_type DnsHeader::ToWire(void *p_Data, size_type p_Size) const noexcept {
  if (!p_Data || p_Size < HeaderSize) {
    return 0;
  }

  // Direct memory copy since DNS header has fixed 12-byte format
  const char *s_Source{reinterpret_cast<const char *>(&m_Id_)};
  char *s_Destination{static_cast<char *>(p_Data)};
  std::copy(s_Source, s_Source + HeaderSize, s_Destination);

  return HeaderSize;
}

bool DnsHeader::operator==(const DnsHeader &p_Other) const noexcept {
  return m_Id_ == p_Other.m_Id_ && m_Flags_ == p_Other.m_Flags_ && m_Qdcount_ == p_Other.m_Qdcount_ && m_Ancount_ == p_Other.m_Ancount_ && m_Nscount_ == p_Other.m_Nscount_ && m_Arcount_ == p_Other.m_Arcount_;
}

bool DnsHeader::operator!=(const DnsHeader &p_Other) const noexcept {
  return !(*this == p_Other);
}

bool DnsHeader::operator<(const DnsHeader &p_Other) const noexcept {
  if (m_Id_ != p_Other.m_Id_) {
    return m_Id_ < p_Other.m_Id_;
  }
  if (m_Flags_ != p_Other.m_Flags_) {
    return m_Flags_ < p_Other.m_Flags_;
  }
  if (m_Qdcount_ != p_Other.m_Qdcount_) {
    return m_Qdcount_ < p_Other.m_Qdcount_;
  }
  if (m_Ancount_ != p_Other.m_Ancount_) {
    return m_Ancount_ < p_Other.m_Ancount_;
  }
  if (m_Nscount_ != p_Other.m_Nscount_) {
    return m_Nscount_ < p_Other.m_Nscount_;
  }
  return m_Arcount_ < p_Other.m_Arcount_;
}

void DnsHeader::SetFlagBit(uint8_t p_Bit, bool p_Value, bool p_Raw) noexcept {
  if (p_Bit >= 16) {
    return;
  }

  if (p_Raw) {
    if (p_Value) {
      m_Flags_ |= (1U << p_Bit);
    } else {
      m_Flags_ &= ~(1U << p_Bit);
    }
  } else {
    uint16_t s_Flags{Flags()};
    if (p_Value) {
      s_Flags |= (1U << p_Bit);
    } else {
      s_Flags &= ~(1U << p_Bit);
    }
    SetFlags(s_Flags);
  }
}

void DnsHeader::SetFlagValue(uint8_t p_BitPos, uint16_t p_Mask, uint8_t p_Value, bool p_Raw) noexcept {
  if (p_BitPos >= 16) {
    return;
  }

  uint8_t s_MaskedValue{static_cast<uint8_t>(p_Value & static_cast<uint8_t>(p_Mask))};

  if (p_Raw) {
    m_Flags_ &= ~(p_Mask << p_BitPos);
    m_Flags_ |= (static_cast<uint16_t>(s_MaskedValue)) << p_BitPos;
  } else {
    uint16_t s_Flags{Flags()};
    s_Flags &= ~(p_Mask << p_BitPos);
    s_Flags |= (static_cast<uint16_t>(s_MaskedValue)) << p_BitPos;
    SetFlags(s_Flags);
  }
}

std::ostream &operator<<(std::ostream &p_OutputStream, const DnsHeader &p_Header) {
  return p_OutputStream << "DnsHeader{id=" << p_Header.Id() << ", qr=" << p_Header.Qr() << ", opcode=" << static_cast<int>(p_Header.Opcode()) << ", rcode=" << static_cast<int>(p_Header.Rcode()) << ", qdcount=" << p_Header.Qdcount() << ", ancount=" << p_Header.Ancount() << "}";
}

void swap(DnsHeader &p_LeftSide, DnsHeader &p_RightSide) noexcept {
  p_LeftSide.swap(p_RightSide);
}

namespace std {
DnsHeader::size_type hash<DnsHeader>::operator()(const DnsHeader &p_Header) const noexcept {
  return p_Header.Hash();
}
} // namespace std
