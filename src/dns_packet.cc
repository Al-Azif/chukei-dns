// Self
#include "dns_packet.h"

// C

// C++
#include <algorithm> // std::all_of, std::copy
#include <algorithm> // std::copy
#include <cassert>   // assert
#include <cstddef>   // std::size_t
#include <cstdint>   // uint8_t, uint16_t, uint32_t
#include <numeric>   // std::accumulate
#include <ostream>   // std::ostream
#include <stdexcept> // std::invalid_argument
#include <string>    // std::string
#include <vector>    // std::vector

// Other libraries

// This Project's
#include "constants.h"
#include "dns_edns0.h"
#include "dns_packet_answer.h"
#include "dns_packet_header.h"
#include "dns_packet_question.h"
#include "utils.h"

// Logging
#include "libLog.h"

// Banned
#include "banned.h"

// ============================================================================
// DnsRequestPacket Implementation
// ============================================================================

// Constructors throw on invalid data for convenience.
// Use the static FromWire() method for non-throwing (returns bool) parsing.
DnsRequestPacket::DnsRequestPacket(const char *p_Data, size_type p_Size) {
  if (!FromWire(p_Data, p_Size, *this)) {
    throw std::invalid_argument("DnsRequestPacket: invalid packet data");
  }
}

DnsRequestPacket::DnsRequestPacket(const std::string &p_Data) {
  if (!FromWire(p_Data.data(), p_Data.size(), *this)) {
    throw std::invalid_argument("DnsRequestPacket: invalid packet data");
  }
}

DnsRequestPacket::DnsRequestPacket(const std::vector<char> &p_Data) {
  if (!FromWire(p_Data.data(), p_Data.size(), *this)) {
    throw std::invalid_argument("DnsRequestPacket: invalid packet data");
  }
}

DnsRequestPacket::DnsRequestPacket(const std::vector<unsigned char> &p_Data) {
  if (!FromWire(reinterpret_cast<const char *>(p_Data.data()), p_Data.size(), *this)) {
    throw std::invalid_argument("DnsRequestPacket: invalid packet data");
  }
}

DnsRequestPacket::DnsRequestPacket(const DnsHeader &p_Header, const std::vector<DnsQuestion> &p_Questions) : m_Header_(p_Header), m_Questions_(p_Questions) {
  UpdateHeaderCounts();
}

const DnsHeader &DnsRequestPacket::Header() const noexcept {
  return m_Header_;
}

const std::vector<DnsQuestion> &DnsRequestPacket::Questions() const noexcept {
  return m_Questions_;
}

void DnsRequestPacket::SetHeader(const DnsHeader &p_Header) {
  m_Header_ = p_Header;
}

void DnsRequestPacket::AddQuestion(const DnsQuestion &p_Question) {
  m_Questions_.push_back(p_Question);
  UpdateHeaderCounts();
}

void DnsRequestPacket::ClearQuestions() {
  m_Questions_.clear();
  UpdateHeaderCounts();
}

const std::optional<EdnsData> &DnsRequestPacket::Edns() const noexcept {
  return m_Edns_;
}

EdnsParseStatus DnsRequestPacket::EdnsStatus() const noexcept {
  return m_EdnsStatus_;
}

bool DnsRequestPacket::HasEdns() const noexcept {
  return m_Edns_.has_value();
}

void DnsRequestPacket::SetEdns(const EdnsData &p_Edns, EdnsParseStatus p_Status) {
  m_Edns_ = p_Edns;
  m_EdnsStatus_ = p_Status;
}

void DnsRequestPacket::SetEdnsStatus(EdnsParseStatus p_Status) {
  m_EdnsStatus_ = p_Status;
}

DnsRequestPacket DnsRequestPacket::MakeAQuery(uint16_t p_Id, const std::string &p_DomainName, bool p_RecursionDesired) {
  DnsHeader s_Header{DnsHeader::MakeQueryHeader(p_Id, 0, p_RecursionDesired, 1)};
  DnsQuestion s_Question{DnsQuestion::MakeAQuery(p_DomainName)};
  return DnsRequestPacket(s_Header, {s_Question});
}

DnsRequestPacket DnsRequestPacket::MakeAaaaQuery(uint16_t p_Id, const std::string &p_DomainName, bool p_RecursionDesired) {
  DnsHeader s_Header{DnsHeader::MakeQueryHeader(p_Id, 0, p_RecursionDesired, 1)};
  DnsQuestion s_Question{DnsQuestion::MakeAaaaQuery(p_DomainName)};
  return DnsRequestPacket(s_Header, {s_Question});
}

DnsRequestPacket DnsRequestPacket::MakePtrQuery(uint16_t p_Id, const std::string &p_IpAddress, bool p_RecursionDesired) {
  DnsHeader s_Header{DnsHeader::MakeQueryHeader(p_Id, 0, p_RecursionDesired, 1)};
  DnsQuestion s_Question{DnsQuestion::MakePtrQuery(p_IpAddress)};
  return DnsRequestPacket(s_Header, {s_Question});
}

void DnsRequestPacket::swap(DnsRequestPacket &p_Other) noexcept {
  m_Header_.swap(p_Other.m_Header_);
  m_Questions_.swap(p_Other.m_Questions_);
  m_Edns_.swap(p_Other.m_Edns_);
  std::swap(m_EdnsStatus_, p_Other.m_EdnsStatus_);
}

bool DnsRequestPacket::empty() const noexcept {
  return m_Questions_.empty();
}

DnsRequestPacket::size_type DnsRequestPacket::size() const noexcept {
  return m_Questions_.size();
}

DnsRequestPacket::size_type DnsRequestPacket::max_size() const noexcept {
  return m_Questions_.max_size();
}

void DnsRequestPacket::clear() noexcept {
  m_Header_.clear();
  m_Questions_.clear();
  m_Edns_.reset();
  m_EdnsStatus_ = EdnsParseStatus::None;
}

bool DnsRequestPacket::Valid() const noexcept {
  // Check header validity
  if (!m_Header_.Valid()) {
    return false;
  }

  // Must be a query
  if (!m_Header_.IsQuery()) {
    return false;
  }

  // Question count must match
  if (m_Header_.Qdcount() != m_Questions_.size()) {
    return false;
  }

  // Request packets should not have answers or authority records
  if (m_Header_.Ancount() != 0 || m_Header_.Nscount() != 0) {
    return false;
  }

  // ARCOUNT may be non-zero for EDNS0 OPT records (RFC 6891)
  // Allow arcount == 1 when EDNS0 data is present, otherwise must be 0
  if (m_Header_.Arcount() != 0) {
    if (!m_Edns_.has_value() && m_EdnsStatus_ == EdnsParseStatus::None) {
      return false;
    }
  }

  // Validate all questions
  return std::all_of(m_Questions_.begin(), m_Questions_.end(), [](const DnsQuestion &l_Question) { return l_Question.Valid(); });
}

DnsRequestPacket::size_type DnsRequestPacket::Hash() const noexcept {
  size_type s_Hash{m_Header_.Hash()};

  // Combine hash values from all questions
  s_Hash = std::accumulate(m_Questions_.begin(), m_Questions_.end(), s_Hash, [](size_type s_Hash, const DnsQuestion &l_Question) { return s_Hash ^ (l_Question.Hash() + 0x9e3779b9 + (s_Hash << 6) + (s_Hash >> 2)); });

  return s_Hash;
}

DnsRequestPacket::size_type DnsRequestPacket::WireSize() const noexcept {
  // Header is always 12 bytes
  size_type s_Size{DnsHeader::size()};

  // Add question sizes
  s_Size += std::accumulate(m_Questions_.begin(), m_Questions_.end(), size_type{0}, [](size_type s_Sum, const DnsQuestion &l_Question) { return s_Sum + l_Question.WireSize(); });

  return s_Size;
}

bool DnsRequestPacket::FromWire(const char *p_Data, size_type p_Size, DnsRequestPacket &p_OutPacket) {
  if (!p_Data || p_Size < DnsHeader::size()) {
    return false;
  }

  size_type s_Offset{0};

  // Parse header
  if (!DnsHeader::FromWire(p_Data, DnsHeader::size(), p_OutPacket.m_Header_)) {
    return false;
  }
  s_Offset += DnsHeader::size();

  // Ensure this is a query packet
  if (p_OutPacket.m_Header_.IsResponse()) {
    return false;
  }

  // Parse questions
  p_OutPacket.m_Questions_.clear();
  p_OutPacket.m_Questions_.reserve(p_OutPacket.m_Header_.Qdcount());

  for (uint16_t l_Index{0}; l_Index < p_OutPacket.m_Header_.Qdcount(); ++l_Index) {
    DnsQuestion s_Question;
    if (!DnsQuestion::FromWire(p_Data, p_Size, s_Offset, s_Question)) {
      return false;
    }
    p_OutPacket.m_Questions_.push_back(s_Question);
  }

  // Verify we parsed all expected questions
  if (p_OutPacket.m_Questions_.size() != p_OutPacket.m_Header_.Qdcount()) {
    return false;
  }

  // Request packets should not have answers or authority records
  // Note: arcount may be non-zero for EDNS0 OPT records (RFC 6891), which is valid
  if (p_OutPacket.m_Header_.Ancount() != 0 || p_OutPacket.m_Header_.Nscount() != 0) {
    return false;
  }

  // Parse additional section for EDNS0 OPT records (RFC 6891)
  p_OutPacket.m_Edns_.reset();
  p_OutPacket.m_EdnsStatus_ = EdnsParseStatus::None;

  if (p_OutPacket.m_Header_.Arcount() > 0) {
    uint16_t s_OptCount{0};

    for (uint16_t l_Index{0}; l_Index < p_OutPacket.m_Header_.Arcount(); ++l_Index) {
      // Validate minimum bounds: NAME (1) + TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2) = 11 bytes
      if (s_Offset + 11 > p_Size) {
        p_OutPacket.m_EdnsStatus_ = EdnsParseStatus::Malformed;
        logKernel(LL_Warn, "EDNS0: additional record truncated at offset %zu", s_Offset);
        return true; // Parse succeeded for questions; let caller handle EDNS error
      }

      const uint8_t *s_Wire{reinterpret_cast<const uint8_t *>(p_Data)};

      // Read NAME byte - OPT must be root (0x00)
      uint8_t s_NameByte{s_Wire[s_Offset]};

      // Skip non-OPT additional records by parsing their NAME+fixed fields+RDATA
      // First, read ahead to check TYPE after the name
      std::size_t s_NameEnd{s_Offset};

      // Advance past NAME: root label (0x00) = 1 byte, compression pointer = 2 bytes,
      // or full label sequence
      if (s_NameByte == 0x00) {
        s_NameEnd = s_Offset + 1;
      } else if ((s_NameByte & 0xC0) == 0xC0) {
        if (s_Offset + 2 > p_Size) {
          p_OutPacket.m_EdnsStatus_ = EdnsParseStatus::Malformed;
          return true;
        }
        s_NameEnd = s_Offset + 2;
      } else {
        // Walk label sequence
        std::size_t s_Pos{s_Offset};
        while (s_Pos < p_Size) {
          uint8_t s_Len{s_Wire[s_Pos]};
          if (s_Len == 0) {
            s_Pos += 1;
            break;
          }
          if ((s_Len & 0xC0) == 0xC0) {
            s_Pos += 2;
            break;
          }
          s_Pos += 1 + s_Len;
        }
        if (s_Pos > p_Size) {
          p_OutPacket.m_EdnsStatus_ = EdnsParseStatus::Malformed;
          return true;
        }
        s_NameEnd = s_Pos;
      }

      // Need at least 10 bytes after NAME: TYPE(2)+CLASS(2)+TTL(4)+RDLENGTH(2)
      if (s_NameEnd + 10 > p_Size) {
        p_OutPacket.m_EdnsStatus_ = EdnsParseStatus::Malformed;
        return true;
      }

      uint16_t s_Type{0};
      std::copy(reinterpret_cast<const char *>(s_Wire + s_NameEnd), reinterpret_cast<const char *>(s_Wire + s_NameEnd) + 2, reinterpret_cast<char *>(&s_Type));
      s_Type = NetworkToHost(s_Type);

      if (s_Type == Constants::Dns::DNS_TYPE_OPT) {
        s_OptCount++;

        if (s_OptCount > 1) {
          p_OutPacket.m_EdnsStatus_ = EdnsParseStatus::DuplicateOpt;
          logKernel(LL_Warn, "EDNS0: multiple OPT records in additional section");
          // Skip past this record
          uint16_t s_Rdlen{0};
          std::copy(reinterpret_cast<const char *>(s_Wire + s_NameEnd + 8), reinterpret_cast<const char *>(s_Wire + s_NameEnd + 8) + 2, reinterpret_cast<char *>(&s_Rdlen));
          s_Rdlen = NetworkToHost(s_Rdlen);
          s_Offset = s_NameEnd + 10 + s_Rdlen;
          continue;
        }

        // OPT NAME must be root (0x00)
        if (s_NameByte != 0x00 || s_NameEnd != s_Offset + 1) {
          p_OutPacket.m_EdnsStatus_ = EdnsParseStatus::Malformed;
          logKernel(LL_Warn, "EDNS0: OPT NAME is not root label");
          // Skip past record
          uint16_t s_Rdlen{0};
          std::copy(reinterpret_cast<const char *>(s_Wire + s_NameEnd + 8), reinterpret_cast<const char *>(s_Wire + s_NameEnd + 8) + 2, reinterpret_cast<char *>(&s_Rdlen));
          s_Rdlen = NetworkToHost(s_Rdlen);
          s_Offset = s_NameEnd + 10 + s_Rdlen;
          continue;
        }

        EdnsData s_Edns{};

        // CLASS = UDP payload size
        uint16_t s_PayloadSize{0};
        std::copy(reinterpret_cast<const char *>(s_Wire + s_NameEnd + 2), reinterpret_cast<const char *>(s_Wire + s_NameEnd + 2) + 2, reinterpret_cast<char *>(&s_PayloadSize));
        s_PayloadSize = NetworkToHost(s_PayloadSize);
        // RFC 6891 §6.2.3: treat values below 512 as 512
        s_Edns.m_UdpPayloadSize_ = (s_PayloadSize < Constants::Dns::DEFAULT_DNS_PACKET_SIZE) ? static_cast<uint16_t>(Constants::Dns::DEFAULT_DNS_PACKET_SIZE) : s_PayloadSize;

        // TTL = extended RCODE (8 bits) | version (8 bits) | DO (1 bit) | Z (15 bits)
        uint32_t s_Ttl{0};
        std::copy(reinterpret_cast<const char *>(s_Wire + s_NameEnd + 4), reinterpret_cast<const char *>(s_Wire + s_NameEnd + 4) + 4, reinterpret_cast<char *>(&s_Ttl));
        s_Ttl = NetworkToHost(s_Ttl);
        s_Edns.m_ExtendedRcode_ = static_cast<uint8_t>((s_Ttl >> 24) & 0xFF);
        s_Edns.m_Version_ = static_cast<uint8_t>((s_Ttl >> 16) & 0xFF);
        s_Edns.m_DoBit_ = ((s_Ttl >> 15) & 0x01) != 0;

        // RDLENGTH
        uint16_t s_Rdlen{0};
        std::copy(reinterpret_cast<const char *>(s_Wire + s_NameEnd + 8), reinterpret_cast<const char *>(s_Wire + s_NameEnd + 8) + 2, reinterpret_cast<char *>(&s_Rdlen));
        s_Rdlen = NetworkToHost(s_Rdlen);

        std::size_t s_RdataStart{s_NameEnd + 10};
        if (s_RdataStart + s_Rdlen > p_Size) {
          p_OutPacket.m_EdnsStatus_ = EdnsParseStatus::Malformed;
          logKernel(LL_Warn, "EDNS0: OPT RDATA extends past packet (rdlen=%u, avail=%zu)", s_Rdlen, p_Size - s_RdataStart);
          return true;
        }

        // Parse RDATA options
        std::size_t s_OptOffset{s_RdataStart};
        while (s_OptOffset + 4 <= s_RdataStart + s_Rdlen) {
          uint16_t s_OptCode{0};
          uint16_t s_OptLen{0};
          std::copy(reinterpret_cast<const char *>(s_Wire + s_OptOffset), reinterpret_cast<const char *>(s_Wire + s_OptOffset) + 2, reinterpret_cast<char *>(&s_OptCode));
          std::copy(reinterpret_cast<const char *>(s_Wire + s_OptOffset + 2), reinterpret_cast<const char *>(s_Wire + s_OptOffset + 2) + 2, reinterpret_cast<char *>(&s_OptLen));
          s_OptCode = NetworkToHost(s_OptCode);
          s_OptLen = NetworkToHost(s_OptLen);

          if (s_OptOffset + 4 + s_OptLen > s_RdataStart + s_Rdlen) {
            p_OutPacket.m_EdnsStatus_ = EdnsParseStatus::Malformed;
            logKernel(LL_Warn, "EDNS0: option extends past RDATA (code=%u, len=%u)", s_OptCode, s_OptLen);
            return true;
          }

          EdnsOption s_Option{};
          s_Option.m_Code_ = s_OptCode;
          s_Option.m_Data_.assign(s_Wire + s_OptOffset + 4, s_Wire + s_OptOffset + 4 + s_OptLen);
          s_Edns.m_Options_.push_back(std::move(s_Option));

          s_OptOffset += 4 + s_OptLen;
        }

        p_OutPacket.m_Edns_ = std::move(s_Edns);

        // Check version after storing data (caller may need udp_payload_size for response)
        if (p_OutPacket.m_Edns_->m_Version_ > 0) {
          p_OutPacket.m_EdnsStatus_ = EdnsParseStatus::BadVersion;
          logKernel(LL_Warn, "EDNS0: unsupported version %u", p_OutPacket.m_Edns_->m_Version_);
        } else if (p_OutPacket.m_EdnsStatus_ == EdnsParseStatus::None) {
          p_OutPacket.m_EdnsStatus_ = EdnsParseStatus::Ok;
        }

        s_Offset = s_RdataStart + s_Rdlen;

        logKernel(LL_Debug, "EDNS0: udp_payload=%u version=%u do=%d ext_rcode=%u options=%zu", p_OutPacket.m_Edns_->m_UdpPayloadSize_, p_OutPacket.m_Edns_->m_Version_, p_OutPacket.m_Edns_->m_DoBit_ ? 1 : 0, p_OutPacket.m_Edns_->m_ExtendedRcode_, p_OutPacket.m_Edns_->m_Options_.size());
      } else {
        // Non-OPT additional record: skip it
        uint16_t s_Rdlen{0};
        std::copy(reinterpret_cast<const char *>(s_Wire + s_NameEnd + 8), reinterpret_cast<const char *>(s_Wire + s_NameEnd + 8) + 2, reinterpret_cast<char *>(&s_Rdlen));
        s_Rdlen = NetworkToHost(s_Rdlen);
        s_Offset = s_NameEnd + 10 + s_Rdlen;
      }
    }
  }

  return true;
}

DnsRequestPacket::size_type DnsRequestPacket::ToWire(void *p_Buffer, size_type p_BufferSize) const noexcept {
  if (!p_Buffer) {
    return 0;
  }

  size_type s_RequiredSize{WireSize()};
  if (p_BufferSize < s_RequiredSize) {
    return 0;
  }

  char *s_Output{static_cast<char *>(p_Buffer)};
  size_type s_Offset{0};

  // Serialize header
  size_type s_HeaderBytes{m_Header_.ToWire(s_Output + s_Offset, DnsHeader::size())};
  if (s_HeaderBytes != DnsHeader::size()) {
    return 0;
  }
  s_Offset += s_HeaderBytes;

  // Serialize questions
  for (const DnsQuestion &l_Question : m_Questions_) {
    size_type s_QuestionBytes{l_Question.ToWire(s_Output + s_Offset, p_BufferSize - s_Offset)};
    if (s_QuestionBytes == 0) {
      return 0;
    }
    s_Offset += s_QuestionBytes;
  }

  return s_Offset;
}

bool DnsRequestPacket::operator==(const DnsRequestPacket &p_Other) const noexcept {
  if (m_Header_ != p_Other.m_Header_) {
    return false;
  }

  if (m_Questions_.size() != p_Other.m_Questions_.size()) {
    return false;
  }

  for (std::size_t l_Index{0}; l_Index < m_Questions_.size(); ++l_Index) {
    if (m_Questions_[l_Index] != p_Other.m_Questions_[l_Index]) {
      return false;
    }
  }

  return true;
}

bool DnsRequestPacket::operator!=(const DnsRequestPacket &p_Other) const noexcept {
  return !(*this == p_Other);
}

bool DnsRequestPacket::operator<(const DnsRequestPacket &p_Other) const noexcept {
  if (m_Header_ != p_Other.m_Header_) {
    return m_Header_ < p_Other.m_Header_;
  }

  // Headers are equal, compare questions
  return m_Questions_ < p_Other.m_Questions_;
}

std::ostream &operator<<(std::ostream &p_OutputStream, const DnsRequestPacket &p_Packet) {
  p_OutputStream << "DnsRequestPacket {";
  p_OutputStream << "\n  Header: " << p_Packet.m_Header_;
  p_OutputStream << "\n  Questions[" << p_Packet.m_Questions_.size() << "]: {";

  for (std::size_t l_Index{0}; l_Index < p_Packet.m_Questions_.size(); ++l_Index) {
    p_OutputStream << "\n    [" << l_Index << "]: " << p_Packet.m_Questions_[l_Index];
  }

  p_OutputStream << "\n  }";

  if (p_Packet.m_Edns_.has_value()) {
    const EdnsData &e{*p_Packet.m_Edns_};
    p_OutputStream << "\n  EDNS0: { udp_payload=" << e.m_UdpPayloadSize_ << " version=" << static_cast<int>(e.m_Version_) << " do=" << e.m_DoBit_ << " ext_rcode=" << static_cast<int>(e.m_ExtendedRcode_) << " options=" << e.m_Options_.size() << " }";
  }

  p_OutputStream << "\n}";

  return p_OutputStream;
}

void DnsRequestPacket::UpdateHeaderCounts() noexcept {
  assert(m_Questions_.size() <= UINT16_MAX);
  m_Header_.UpdateCounts(static_cast<uint16_t>(m_Questions_.size()), 0, 0, 0);
}

// ============================================================================
// DnsResponsePacket Implementation
// ============================================================================

// Constructors throw on invalid data for convenience.
// Use the static FromWire() method for non-throwing (returns bool) parsing.
DnsResponsePacket::DnsResponsePacket(const char *p_Data, size_type p_Size) {
  if (!FromWire(p_Data, p_Size, *this)) {
    throw std::invalid_argument("DnsResponsePacket: invalid packet data");
  }
}

DnsResponsePacket::DnsResponsePacket(const std::string &p_Data) {
  if (!FromWire(p_Data.data(), p_Data.size(), *this)) {
    throw std::invalid_argument("DnsResponsePacket: invalid packet data");
  }
}

DnsResponsePacket::DnsResponsePacket(const std::vector<char> &p_Data) {
  if (!FromWire(p_Data.data(), p_Data.size(), *this)) {
    throw std::invalid_argument("DnsResponsePacket: invalid packet data");
  }
}

DnsResponsePacket::DnsResponsePacket(const std::vector<unsigned char> &p_Data) {
  if (!FromWire(p_Data.data(), p_Data.size(), *this)) {
    throw std::invalid_argument("DnsResponsePacket: invalid packet data");
  }
}

DnsResponsePacket::DnsResponsePacket(const DnsHeader &p_Header, const std::vector<DnsQuestion> &p_Questions, const std::vector<DnsAnswer> &p_Answers, const std::vector<DnsAnswer> &p_Authority, const std::vector<DnsAnswer> &p_Additional) : m_Header_(p_Header), m_Questions_(p_Questions), m_Answers_(p_Answers), m_Authority_(p_Authority), m_Additional_(p_Additional) {
  UpdateHeaderCounts();
}

const DnsHeader &DnsResponsePacket::Header() const noexcept {
  return m_Header_;
}

const std::vector<DnsQuestion> &DnsResponsePacket::Questions() const noexcept {
  return m_Questions_;
}

const std::vector<DnsAnswer> &DnsResponsePacket::Answers() const noexcept {
  return m_Answers_;
}

const std::vector<DnsAnswer> &DnsResponsePacket::Authority() const noexcept {
  return m_Authority_;
}

const std::vector<DnsAnswer> &DnsResponsePacket::Additional() const noexcept {
  return m_Additional_;
}

void DnsResponsePacket::SetHeader(const DnsHeader &p_Header) {
  m_Header_ = p_Header;
}

void DnsResponsePacket::AddQuestion(const DnsQuestion &p_Question) {
  m_Questions_.push_back(p_Question);
  UpdateHeaderCounts();
}

void DnsResponsePacket::AddAnswer(const DnsAnswer &p_Answer) {
  m_Answers_.push_back(p_Answer);
  UpdateHeaderCounts();
}

void DnsResponsePacket::AddAuthority(const DnsAnswer &p_Authority) {
  m_Authority_.push_back(p_Authority);
  UpdateHeaderCounts();
}

void DnsResponsePacket::AddAdditional(const DnsAnswer &p_Additional) {
  m_Additional_.push_back(p_Additional);
  UpdateHeaderCounts();
}

void DnsResponsePacket::ClearQuestions() {
  m_Questions_.clear();
  UpdateHeaderCounts();
}

void DnsResponsePacket::ClearAnswers() {
  m_Answers_.clear();
  UpdateHeaderCounts();
}

void DnsResponsePacket::ClearAuthority() {
  m_Authority_.clear();
  UpdateHeaderCounts();
}

void DnsResponsePacket::ClearAdditional() {
  m_Additional_.clear();
  UpdateHeaderCounts();
}

DnsResponsePacket DnsResponsePacket::MakeResponse(const DnsRequestPacket &p_Request, uint8_t p_Rcode, bool p_Authoritative, bool p_RecursionAvailable) {
  DnsHeader s_Header{DnsHeader::MakeResponseHeader(p_Request.Header(), p_Rcode, p_Authoritative, p_RecursionAvailable)};
  return DnsResponsePacket(s_Header, p_Request.Questions());
}

DnsResponsePacket DnsResponsePacket::MakeErrorResponse(const DnsRequestPacket &p_Request, uint8_t p_ErrorCode) {
  DnsHeader s_Header{p_Request.Header()};
  s_Header.MakeErrorResponse(p_Request.Header(), p_ErrorCode);
  return DnsResponsePacket(s_Header, p_Request.Questions());
}

void DnsResponsePacket::swap(DnsResponsePacket &p_Other) noexcept {
  m_Header_.swap(p_Other.m_Header_);
  m_Questions_.swap(p_Other.m_Questions_);
  m_Answers_.swap(p_Other.m_Answers_);
  m_Authority_.swap(p_Other.m_Authority_);
  m_Additional_.swap(p_Other.m_Additional_);
}

bool DnsResponsePacket::empty() const noexcept {
  return m_Questions_.empty() && m_Answers_.empty() && m_Authority_.empty() && m_Additional_.empty();
}

DnsResponsePacket::size_type DnsResponsePacket::size() const noexcept {
  return m_Questions_.size() + m_Answers_.size() + m_Authority_.size() + m_Additional_.size();
}

DnsResponsePacket::size_type DnsResponsePacket::max_size() const noexcept {
  return m_Questions_.max_size();
}

void DnsResponsePacket::clear() noexcept {
  m_Header_.clear();
  m_Questions_.clear();
  m_Answers_.clear();
  m_Authority_.clear();
  m_Additional_.clear();
}

bool DnsResponsePacket::Valid() const noexcept {
  // Check header validity
  if (!m_Header_.Valid()) {
    return false;
  }

  // Must be a response
  if (!m_Header_.IsResponse()) {
    return false;
  }

  // Counts must match
  if (m_Header_.Qdcount() != m_Questions_.size() || m_Header_.Ancount() != m_Answers_.size() || m_Header_.Nscount() != m_Authority_.size() || m_Header_.Arcount() != m_Additional_.size()) {
    return false;
  }

  // Validate all sections using std::all_of
  return std::all_of(m_Questions_.begin(), m_Questions_.end(), [](const DnsQuestion &l_Question) { return l_Question.Valid(); }) && std::all_of(m_Answers_.begin(), m_Answers_.end(), [](const DnsAnswer &l_Answer) { return l_Answer.Valid(); }) && std::all_of(m_Authority_.begin(), m_Authority_.end(), [](const DnsAnswer &l_Authority) { return l_Authority.Valid(); }) && std::all_of(m_Additional_.begin(), m_Additional_.end(), [](const DnsAnswer &l_Additional) { return l_Additional.Valid(); });
}

DnsResponsePacket::size_type DnsResponsePacket::Hash() const noexcept {
  size_type s_Hash{m_Header_.Hash()};

  // Combine hash values from all sections
  s_Hash = std::accumulate(m_Questions_.begin(), m_Questions_.end(), s_Hash, [](size_type s_Hash, const DnsQuestion &l_Question) { return s_Hash ^ (l_Question.Hash() + 0x9e3779b9 + (s_Hash << 6) + (s_Hash >> 2)); });

  s_Hash = std::accumulate(m_Answers_.begin(), m_Answers_.end(), s_Hash, [](size_type s_Hash, const DnsAnswer &l_Answer) { return s_Hash ^ (l_Answer.Hash() + 0x9e3779b9 + (s_Hash << 6) + (s_Hash >> 2)); });

  s_Hash = std::accumulate(m_Authority_.begin(), m_Authority_.end(), s_Hash, [](size_type s_Hash, const DnsAnswer &l_Authority) { return s_Hash ^ (l_Authority.Hash() + 0x9e3779b9 + (s_Hash << 6) + (s_Hash >> 2)); });

  s_Hash = std::accumulate(m_Additional_.begin(), m_Additional_.end(), s_Hash, [](size_type s_Hash, const DnsAnswer &l_Additional) { return s_Hash ^ (l_Additional.Hash() + 0x9e3779b9 + (s_Hash << 6) + (s_Hash >> 2)); });

  return s_Hash;
}

DnsResponsePacket::size_type DnsResponsePacket::WireSize() const noexcept {
  // Header is always 12 bytes
  size_type s_Size{DnsHeader::size()};

  // Add question sizes
  s_Size += std::accumulate(m_Questions_.begin(), m_Questions_.end(), size_type{0}, [](size_type s_Sum, const DnsQuestion &l_Question) { return s_Sum + l_Question.WireSize(); });

  // Add answer sizes
  s_Size += std::accumulate(m_Answers_.begin(), m_Answers_.end(), size_type{0}, [](size_type s_Sum, const DnsAnswer &l_Answer) { return s_Sum + l_Answer.WireSize(); });

  // Add authority sizes
  s_Size += std::accumulate(m_Authority_.begin(), m_Authority_.end(), size_type{0}, [](size_type s_Sum, const DnsAnswer &l_Authority) { return s_Sum + l_Authority.WireSize(); });

  // Add additional sizes
  s_Size += std::accumulate(m_Additional_.begin(), m_Additional_.end(), size_type{0}, [](size_type s_Sum, const DnsAnswer &l_Additional) { return s_Sum + l_Additional.WireSize(); });

  return s_Size;
}

bool DnsResponsePacket::FromWire(const void *p_Data, size_type p_Size, DnsResponsePacket &p_OutPacket) {
  if (!p_Data || p_Size < DnsHeader::size()) {
    return false;
  }

  size_type s_Offset{0};

  // Parse header
  if (!DnsHeader::FromWire(p_Data, DnsHeader::size(), p_OutPacket.m_Header_)) {
    return false;
  }
  s_Offset += DnsHeader::size();

  // Ensure this is a response packet
  if (!p_OutPacket.m_Header_.IsResponse()) {
    return false;
  }

  // Parse questions
  p_OutPacket.m_Questions_.clear();
  p_OutPacket.m_Questions_.reserve(p_OutPacket.m_Header_.Qdcount());

  for (uint16_t l_Index{0}; l_Index < p_OutPacket.m_Header_.Qdcount(); ++l_Index) {
    DnsQuestion s_Question;
    if (!DnsQuestion::FromWire(p_Data, p_Size, s_Offset, s_Question)) {
      return false;
    }
    p_OutPacket.m_Questions_.push_back(s_Question);
  }

  // Parse answers
  p_OutPacket.m_Answers_.clear();
  p_OutPacket.m_Answers_.reserve(p_OutPacket.m_Header_.Ancount());

  for (uint16_t l_Index{0}; l_Index < p_OutPacket.m_Header_.Ancount(); ++l_Index) {
    DnsAnswer s_Answer;
    if (!DnsAnswer::FromWire(p_Data, p_Size, s_Offset, s_Answer)) {
      return false;
    }
    p_OutPacket.m_Answers_.push_back(s_Answer);
  }

  // Parse authority records
  p_OutPacket.m_Authority_.clear();
  p_OutPacket.m_Authority_.reserve(p_OutPacket.m_Header_.Nscount());

  for (uint16_t l_Index{0}; l_Index < p_OutPacket.m_Header_.Nscount(); ++l_Index) {
    DnsAnswer s_Authority;
    if (!DnsAnswer::FromWire(p_Data, p_Size, s_Offset, s_Authority)) {
      return false;
    }
    p_OutPacket.m_Authority_.push_back(s_Authority);
  }

  // Parse additional records
  p_OutPacket.m_Additional_.clear();
  p_OutPacket.m_Additional_.reserve(p_OutPacket.m_Header_.Arcount());

  for (uint16_t l_Index{0}; l_Index < p_OutPacket.m_Header_.Arcount(); ++l_Index) {
    DnsAnswer s_Additional;
    if (!DnsAnswer::FromWire(p_Data, p_Size, s_Offset, s_Additional)) {
      return false;
    }
    p_OutPacket.m_Additional_.push_back(s_Additional);
  }

  // Verify we parsed all expected records
  if (p_OutPacket.m_Questions_.size() != p_OutPacket.m_Header_.Qdcount() || p_OutPacket.m_Answers_.size() != p_OutPacket.m_Header_.Ancount() || p_OutPacket.m_Authority_.size() != p_OutPacket.m_Header_.Nscount() || p_OutPacket.m_Additional_.size() != p_OutPacket.m_Header_.Arcount()) {
    return false;
  }

  return true;
}

DnsResponsePacket::size_type DnsResponsePacket::ToWire(void *p_Buffer, size_type p_BufferSize) const noexcept {
  if (!p_Buffer) {
    return 0;
  }

  size_type s_RequiredSize{WireSize()};
  if (p_BufferSize < s_RequiredSize) {
    return 0;
  }

  char *s_Output{static_cast<char *>(p_Buffer)};
  size_type s_Offset{0};

  // Serialize header
  size_type s_HeaderBytes{m_Header_.ToWire(s_Output + s_Offset, DnsHeader::size())};
  if (s_HeaderBytes != DnsHeader::size()) {
    return 0;
  }
  s_Offset += s_HeaderBytes;

  // Serialize questions
  for (const DnsQuestion &l_Question : m_Questions_) {
    size_type s_QuestionBytes{l_Question.ToWire(s_Output + s_Offset, p_BufferSize - s_Offset)};
    if (s_QuestionBytes == 0) {
      return 0;
    }
    s_Offset += s_QuestionBytes;
  }

  // Serialize answers
  for (const DnsAnswer &l_Answer : m_Answers_) {
    size_type s_AnswerBytes{l_Answer.ToWire(s_Output + s_Offset, p_BufferSize - s_Offset)};
    if (s_AnswerBytes == 0) {
      return 0;
    }
    s_Offset += s_AnswerBytes;
  }

  // Serialize authority records
  for (const DnsAnswer &l_Authority : m_Authority_) {
    size_type s_AuthorityBytes{l_Authority.ToWire(s_Output + s_Offset, p_BufferSize - s_Offset)};
    if (s_AuthorityBytes == 0) {
      return 0;
    }
    s_Offset += s_AuthorityBytes;
  }

  // Serialize additional records
  for (const DnsAnswer &l_Additional : m_Additional_) {
    size_type s_AdditionalBytes{l_Additional.ToWire(s_Output + s_Offset, p_BufferSize - s_Offset)};
    if (s_AdditionalBytes == 0) {
      return 0;
    }
    s_Offset += s_AdditionalBytes;
  }

  return s_Offset;
}

void DnsResponsePacket::UpdateHeaderCounts() noexcept {
  assert(m_Questions_.size() <= UINT16_MAX);
  assert(m_Answers_.size() <= UINT16_MAX);
  assert(m_Authority_.size() <= UINT16_MAX);
  assert(m_Additional_.size() <= UINT16_MAX);
  m_Header_.UpdateCounts(static_cast<uint16_t>(m_Questions_.size()), static_cast<uint16_t>(m_Answers_.size()), static_cast<uint16_t>(m_Authority_.size()), static_cast<uint16_t>(m_Additional_.size()));
}

bool DnsResponsePacket::operator==(const DnsResponsePacket &p_Other) const noexcept {
  if (m_Header_ != p_Other.m_Header_) {
    return false;
  }

  return (m_Questions_ == p_Other.m_Questions_ && m_Answers_ == p_Other.m_Answers_ && m_Authority_ == p_Other.m_Authority_ && m_Additional_ == p_Other.m_Additional_);
}

bool DnsResponsePacket::operator!=(const DnsResponsePacket &p_Other) const noexcept {
  return !(*this == p_Other);
}

bool DnsResponsePacket::operator<(const DnsResponsePacket &p_Other) const noexcept {
  if (m_Header_ != p_Other.m_Header_) {
    return m_Header_ < p_Other.m_Header_;
  }

  // Headers are equal, compare sections in order
  if (m_Questions_ != p_Other.m_Questions_) {
    return m_Questions_ < p_Other.m_Questions_;
  }

  if (m_Answers_ != p_Other.m_Answers_) {
    return m_Answers_ < p_Other.m_Answers_;
  }

  if (m_Authority_ != p_Other.m_Authority_) {
    return m_Authority_ < p_Other.m_Authority_;
  }

  return m_Additional_ < p_Other.m_Additional_;
}

std::ostream &operator<<(std::ostream &p_OutputStream, const DnsResponsePacket &p_Packet) {
  p_OutputStream << "DnsResponsePacket {";
  p_OutputStream << "\n  Header: " << p_Packet.m_Header_;
  p_OutputStream << "\n  Questions[" << p_Packet.m_Questions_.size() << "]: {";

  for (std::size_t l_Index{0}; l_Index < p_Packet.m_Questions_.size(); ++l_Index) {
    p_OutputStream << "\n    [" << l_Index << "]: " << p_Packet.m_Questions_[l_Index];
  }

  p_OutputStream << "\n  }";
  p_OutputStream << "\n  Answers[" << p_Packet.m_Answers_.size() << "]: {";

  for (std::size_t l_Index{0}; l_Index < p_Packet.m_Answers_.size(); ++l_Index) {
    p_OutputStream << "\n    [" << l_Index << "]: " << p_Packet.m_Answers_[l_Index];
  }

  p_OutputStream << "\n  }";
  p_OutputStream << "\n  Authority[" << p_Packet.m_Authority_.size() << "]: {";

  for (std::size_t l_Index{0}; l_Index < p_Packet.m_Authority_.size(); ++l_Index) {
    p_OutputStream << "\n    [" << l_Index << "]: " << p_Packet.m_Authority_[l_Index];
  }

  p_OutputStream << "\n  }";
  p_OutputStream << "\n  Additional[" << p_Packet.m_Additional_.size() << "]: {";

  for (std::size_t l_Index{0}; l_Index < p_Packet.m_Additional_.size(); ++l_Index) {
    p_OutputStream << "\n    [" << l_Index << "]: " << p_Packet.m_Additional_[l_Index];
  }

  p_OutputStream << "\n  }";
  p_OutputStream << "\n}";

  return p_OutputStream;
}
