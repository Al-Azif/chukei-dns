// Self
#include "tcp_server.h"

// C

// C++
#include <cstddef>      // std::size_t
#include <cstdint>      // uint16_t
#include <exception>    // std::exception
#include <memory>       // std::make_shared, std::shared_ptr
#include <optional>     // std::optional
#include <system_error> // std::error_code
#include <vector>       // std::vector

// Other libraries
#include "asio/read.hpp"
#include "asio/ts/buffer.hpp"
#include "asio/ts/internet.hpp"
#include "asio/write.hpp"

// This Project's
#include "config.h"
#include "constants.h"
#include "dns_edns0.h"
#include "dns_over_https.h"
#include "dns_parser.h"
#include "dns_response.h"
#include "local_dns.h"
#include "utils.h"

// Logging
#include "libLog.h"

// Banned
#include "banned.h"

// ============================================================================
// TcpSession
// ============================================================================

TcpSession::TcpSession(asio::ip::tcp::socket p_Socket, DnsOverHttps &p_DohQuery, DnsCache &p_DnsCache) : m_Socket_(std::move(p_Socket)), m_DohQuery_(p_DohQuery), m_DnsCache_(p_DnsCache) {
}

void TcpSession::Start() {
  ReadLength();
}

void TcpSession::ReadLength() {
  std::shared_ptr<TcpSession> self(shared_from_this());
  asio::async_read(m_Socket_, asio::buffer(m_LengthBuf_, 2), [this, self](std::error_code p_ErrorCode, std::size_t /*p_BytesRead*/) {
    if (p_ErrorCode) {
      if (p_ErrorCode != asio::error::eof && p_ErrorCode != asio::error::connection_reset && p_ErrorCode != asio::error::operation_aborted) {
        logKernel(LL_Error, "TCP read length error: %s", p_ErrorCode.message().c_str());
      }
      return;
    }

    uint16_t s_MessageLength{static_cast<uint16_t>((static_cast<uint8_t>(m_LengthBuf_[0]) << 8) | static_cast<uint8_t>(m_LengthBuf_[1]))};

    if (s_MessageLength < Constants::Dns::DNS_MIN_PACKET_SIZE) {
      logKernel(LL_Warn, "TCP DNS message too small: %u bytes", s_MessageLength);
      return;
    }

    // TCP DNS messages can be up to 65535 bytes (2-byte length field max)
    ReadMessage(s_MessageLength); });
}

void TcpSession::ReadMessage(uint16_t p_MessageLength) {
  m_Data_.resize(p_MessageLength);
  std::shared_ptr<TcpSession> self(shared_from_this());

  asio::async_read(m_Socket_, asio::buffer(m_Data_.data(), p_MessageLength), [this, self](std::error_code p_ErrorCode, std::size_t p_BytesReceived) {
    if (p_ErrorCode) {
      if (p_ErrorCode != asio::error::eof && p_ErrorCode != asio::error::connection_reset && p_ErrorCode != asio::error::operation_aborted) {
        logKernel(LL_Error, "TCP read message error: %s", p_ErrorCode.message().c_str());
      }
      return;
    }

    logKernel(LL_Debug, "TCP Query HexDump:");
    logKernelHexdump(LL_Debug, m_Data_.data(), p_BytesReceived);

    // Parse and validate packet
    std::optional<DnsParser> s_ParsedRequest;
    try {
      s_ParsedRequest.emplace(m_Data_.data(), p_BytesReceived);
    } catch (const std::exception &e) {
      logKernel(LL_Error, "TCP DNS parsing exception: %s", e.what());

      std::vector<char> s_ErrorResponse;
      DnsResponse::CallResponseFunction("FORMERR", m_Data_.data(), p_BytesReceived, s_ErrorResponse);

      if (!s_ErrorResponse.empty()) {
        Send(s_ErrorResponse.data(), s_ErrorResponse.size());
      }

      // Continue reading next query on same connection
      ReadLength();
      return;
    }

    bool s_Found{false};
    std::vector<char> s_Output;

    // EDNS0 error handling (RFC 6891)
    const DnsRequestPacket &s_Pkt{s_ParsedRequest->Packet()};
    EdnsParseStatus s_EdnsStatus{s_Pkt.EdnsStatus()};
    const EdnsData *s_EdnsPtr{s_Pkt.HasEdns() ? &(*s_Pkt.Edns()) : nullptr};

    if (s_EdnsStatus == EdnsParseStatus::DuplicateOpt || s_EdnsStatus == EdnsParseStatus::Malformed) {
      logKernel(LL_Debug, "TCP EDNS0 error (status=%d), responding FORMERR+OPT", static_cast<int>(s_EdnsStatus));
      DnsResponse::FORMERR_OPT(s_Pkt, s_Output, s_EdnsPtr);
      Send(s_Output.data(), s_Output.size());
      ReadLength();
      return;
    }

    if (s_EdnsStatus == EdnsParseStatus::BadVersion) {
      logKernel(LL_Debug, "TCP EDNS0 unsupported version %u, responding BADVERS", s_EdnsPtr ? s_EdnsPtr->m_Version_ : 0);
      DnsResponse::BADVERS(s_Pkt, s_Output, s_EdnsPtr);
      Send(s_Output.data(), s_Output.size());
      ReadLength();
      return;
    }

    // Reject non-standard queries (OPCODE != 0) with NOTIMP per RFC 1035 §4.1.1
    if (s_ParsedRequest->Packet().Header().Opcode() != 0) {
      logKernel(LL_Debug, "TCP non-standard opcode %d, responding NOTIMP", s_ParsedRequest->Packet().Header().Opcode());
      DnsResponse::NOTIMP(s_ParsedRequest->Packet(), s_Output);
      if (s_EdnsStatus == EdnsParseStatus::Ok) {
        DnsResponse::AppendOpt(s_Output, 0, s_EdnsPtr);
      }
      Send(s_Output.data(), s_Output.size());
      ReadLength();
      return;
    }

    // Check local zones unless running in DoH-only mode
    if (!g_Config.DohOnly()) {
      // Check local DNS for domain entry
      if (LocalDns::CheckLocalMatch(s_ParsedRequest.value(), s_Output) == 0) {
        logKernel(LL_Debug, "TCP local match found");
        s_Found = true;
      }
    }

    // Not found in local DNS, check cache, then DoH (with automatic resolver failover)
    if (!s_Found) {
      uint16_t s_TxnId{s_ParsedRequest->Packet().Header().Id()};
      uint16_t s_Qtype{s_ParsedRequest->Packet().Questions()[0].Qtype()};
      std::string s_Domain{s_ParsedRequest->Domain()};

      // Check DNS response cache before making upstream DoH request
      if (m_DnsCache_.Lookup(s_Domain, s_Qtype, s_TxnId, s_Output)) {
        logKernel(LL_Debug, "TCP cache hit for %s", s_Domain.c_str());
        s_Found = true;
      } else {
        DnsOverHttps::ResolveResult s_DohResponse{m_DohQuery_.Resolve(m_Data_.data(), p_BytesReceived, s_Output)};
        if (s_DohResponse == DnsOverHttps::ResolveResult::Success) {
          logKernel(LL_Debug, "TCP DoH match found");
          m_DnsCache_.Insert(s_Domain, s_Qtype, s_Output);
          s_Found = true;
        } else if (s_DohResponse != DnsOverHttps::ResolveResult::InvalidInput) {
          // Upstream resolver failed - respond with SERVFAIL
          DnsResponse::SERVFAIL(s_ParsedRequest->Packet(), s_Output);
          s_Found = true;
        }
      }
    }

    // No match found - respond with NXDOMAIN
    if (!s_Found) {
      DnsResponse::NXDOMAIN(s_ParsedRequest->Packet(), s_Output);
    }

    // Append OPT to response when query included valid EDNS0 (RFC 6891 §6.1.1)
    if (s_EdnsStatus == EdnsParseStatus::Ok) {
      DnsResponse::AppendOpt(s_Output, 0, s_EdnsPtr);
    }

    // Hexdump response packet for debugging
    logKernel(LL_Debug, "TCP Response HexDump:");
    logKernelHexdump(LL_Debug, s_Output.data(), s_Output.size());

    LogDnsResponseRecords(s_Output.data(), s_Output.size());

    // Send the response packet
    Send(s_Output.data(), s_Output.size());

    // Continue reading next query on same connection
    ReadLength(); });
}

void TcpSession::Send(const char *p_Data, std::size_t p_Length) {
  if (!p_Data || p_Length == 0) {
    logKernel(LL_Warn, "TCP attempted to send empty or null DNS response");
    return;
  }

  // Build message with 2-byte length prefix per RFC 1035 §4.2.2
  std::vector<char> s_Message(2 + p_Length);
  s_Message[0] = static_cast<char>((p_Length >> 8) & 0xFF);
  s_Message[1] = static_cast<char>(p_Length & 0xFF);
  for (std::size_t l_Index{0}; l_Index < p_Length; ++l_Index) {
    s_Message[2 + l_Index] = p_Data[l_Index];
  }

  std::shared_ptr<TcpSession> self(shared_from_this());
  asio::async_write(m_Socket_, asio::buffer(s_Message.data(), s_Message.size()), [self, s_Message](std::error_code ec, std::size_t /*bytes_written*/) {
    if (ec) {
      logKernel(LL_Error, "TCP send error: %s", ec.message().c_str());
    } else {
      logKernel(LL_Debug, "TCP sent %zu bytes", s_Message.size() - 2);
    } });
}

// ============================================================================
// TcpServer
// ============================================================================

TcpServer::TcpServer(asio::io_context &p_Context) : m_Context_(p_Context), m_Acceptor_(p_Context, asio::ip::tcp::endpoint(asio::ip::make_address(g_Config.DnsIpAddress()), g_Config.DnsPort())), m_ReopenTimer_(p_Context), m_DohQuery_(g_Config.Useragent(), g_Config.DohResolvers(), g_Config.CacertPath(), g_Config.DohTimeoutMs()) {
  IsRunning(true);
  Accept();
}

void TcpServer::Stop() {
  IsRunning(false);
  m_ReopenTimer_.cancel();
  std::error_code ec;
  m_Acceptor_.close(ec);
  if (ec) {
    logKernel(LL_Warn, "TCP error closing acceptor: %s", ec.message().c_str());
  }
}

bool TcpServer::IsRunning() const {
  return m_IsRunning_;
}

int TcpServer::IsRunning(bool p_Input) {
  m_IsRunning_ = p_Input;
  return 0;
}

void TcpServer::Accept() {
  if (!IsRunning()) {
    return;
  }

  m_Acceptor_.async_accept([this](std::error_code p_ErrorCode, asio::ip::tcp::socket p_Socket) {
    if (!p_ErrorCode) {
      logKernel(LL_Debug, "TCP connection accepted");
      std::shared_ptr<TcpSession> s_Session{std::make_shared<TcpSession>(std::move(p_Socket), m_DohQuery_, m_DnsCache_)};
      s_Session->Start();
    } else {
      if (p_ErrorCode == asio::error::bad_descriptor || p_ErrorCode == asio::error::not_socket) {
        logKernel(LL_Error, "TCP accept error (fatal): %s", p_ErrorCode.message().c_str());
        ReopenAcceptor();
        return;
      }
      if (p_ErrorCode != asio::error::operation_aborted) {
        logKernel(LL_Error, "TCP accept error: %s", p_ErrorCode.message().c_str());
      }
    }

    if (IsRunning()) {
      Accept();
    } });
}

void TcpServer::ReopenAcceptor() {
  if (!IsRunning()) {
    return;
  }
  logKernel(LL_Warn, "TCP attempting to reopen listening acceptor");
  std::error_code ec;
  m_Acceptor_.close(ec); // Ignore close errors on a broken acceptor
  try {
    m_Acceptor_ = asio::ip::tcp::acceptor(m_Context_, asio::ip::tcp::endpoint(asio::ip::make_address(g_Config.DnsIpAddress()), g_Config.DnsPort()));
    logKernel(LL_Info, "TCP listening acceptor restored on %s:%u", g_Config.DnsIpAddress().c_str(), g_Config.DnsPort());
    Accept();
  } catch (const std::exception &e) {
    logKernel(LL_Error, "TCP acceptor reopen failed: %s, retrying in 1s", e.what());
    m_ReopenTimer_.expires_after(std::chrono::seconds(1));
    m_ReopenTimer_.async_wait([this](std::error_code ec) {
      if (!ec && IsRunning()) {
        ReopenAcceptor();
      } });
  }
}
