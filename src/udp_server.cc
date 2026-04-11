// Self
#include "udp_server.h"

// C

// C++
#include <cstddef>      // std::size_t
#include <cstdint>      // uint16_t
#include <exception>    // std::exception
#include <optional>     // std::optional
#include <system_error> // std::error_code
#include <vector>       // std::vector

// Other libraries
#include "asio/ts/buffer.hpp"
#include "asio/ts/internet.hpp"

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

UdpServer::UdpServer(asio::io_context &p_Context) : m_Context_(p_Context), m_Socket_(p_Context, asio::ip::udp::endpoint(asio::ip::make_address(g_Config.DnsIpAddress()), g_Config.DnsPort())), m_ReopenTimer_(p_Context), m_DohQuery_(g_Config.Useragent(), g_Config.DohResolvers(), g_Config.CacertPath(), g_Config.DohTimeoutMs()) {
  IsRunning(true);
  Receive();
}

void UdpServer::Stop() {
  IsRunning(false);
  m_ReopenTimer_.cancel();
  std::error_code ec;
  m_Socket_.close(ec);
  if (ec) {
    logKernel(LL_Warn, "UDP error closing socket: %s", ec.message().c_str());
  }
}

bool UdpServer::IsRunning() const {
  return m_IsRunning_;
}

int UdpServer::IsRunning(bool p_Input) {
  m_IsRunning_ = p_Input;
  return 0;
}

void UdpServer::Receive() {
  if (!IsRunning()) {
    return;
  }

  m_Socket_.async_receive_from(asio::buffer(m_Data_, sizeof(m_Data_)), m_SenderEndpoint_, [this](std::error_code p_ErrorCode, std::size_t p_BytesReceived) {
    if (!p_ErrorCode && p_BytesReceived > 0) {
      if (p_BytesReceived < Constants::Dns::DNS_MIN_PACKET_SIZE) {
        logKernel(LL_Warn, "UDP DNS packet too small: %zu bytes", p_BytesReceived);
        if (IsRunning()) {
          Receive();
        }
        return;
      }

      if (p_BytesReceived > Constants::Dns::DEFAULT_DNS_PACKET_SIZE) {
        logKernel(LL_Warn, "UDP DNS packet too large: %zu bytes", p_BytesReceived);
        if (IsRunning()) {
          Receive();
        }
        return;
      }

      logKernel(LL_Debug, "UDP Query HexDump:");
      logKernelHexdump(LL_Debug, m_Data_, p_BytesReceived);

      // Parse and validate packet
      std::optional<DnsParser> s_ParsedRequest;
      try {
        s_ParsedRequest.emplace(m_Data_, p_BytesReceived);
      } catch (const std::exception &e) {
        logKernel(LL_Error, "UDP DNS parsing exception: %s", e.what());

        std::vector<char> s_ErrorResponse;
        DnsResponse::CallResponseFunction("FORMERR", m_Data_, p_BytesReceived, s_ErrorResponse);

        if (!s_ErrorResponse.empty()) {
          Send(s_ErrorResponse.data(), s_ErrorResponse.size());
        }

        if (IsRunning()) {
          Receive();
        }
        return;
      }

      bool s_Found{false};
      std::vector<char> s_Output;

      // EDNS0 error handling (RFC 6891)
      const DnsRequestPacket &s_Pkt{s_ParsedRequest->Packet()};
      EdnsParseStatus s_EdnsStatus{s_Pkt.EdnsStatus()};
      const EdnsData *s_EdnsPtr{s_Pkt.HasEdns() ? &(*s_Pkt.Edns()) : nullptr};

      if (s_EdnsStatus == EdnsParseStatus::DuplicateOpt || s_EdnsStatus == EdnsParseStatus::Malformed) {
        logKernel(LL_Debug, "UDP EDNS0 error (status=%d), responding FORMERR+OPT", static_cast<int>(s_EdnsStatus));
        DnsResponse::FORMERR_OPT(s_Pkt, s_Output, s_EdnsPtr);
        Send(s_Output.data(), s_Output.size());
        if (IsRunning()) {
          Receive();
        }
        return;
      }

      if (s_EdnsStatus == EdnsParseStatus::BadVersion) {
        logKernel(LL_Debug, "UDP EDNS0 unsupported version %u, responding BADVERS", s_EdnsPtr ? s_EdnsPtr->m_Version_ : 0);
        DnsResponse::BADVERS(s_Pkt, s_Output, s_EdnsPtr);
        Send(s_Output.data(), s_Output.size());
        if (IsRunning()) {
          Receive();
        }
        return;
      }

      // Reject non-standard queries (OPCODE != 0) with NOTIMP per RFC 1035 §4.1.1
      if (s_ParsedRequest->Packet().Header().Opcode() != 0) {
        logKernel(LL_Debug, "UDP non-standard opcode %d, responding NOTIMP", s_ParsedRequest->Packet().Header().Opcode());
        DnsResponse::NOTIMP(s_ParsedRequest->Packet(), s_Output);
        if (s_EdnsStatus == EdnsParseStatus::Ok) {
          DnsResponse::AppendOpt(s_Output, 0, s_EdnsPtr);
        }
        Send(s_Output.data(), s_Output.size());
        if (IsRunning()) {
          Receive();
        }
        return;
      }

      // Check local zones unless running in DoH-only mode
      if (!g_Config.DohOnly()) {
        // Check local DNS for domain entry
        if (LocalDns::CheckLocalMatch(s_ParsedRequest.value(), s_Output) == 0) {
          logKernel(LL_Debug, "UDP local match found");
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
          logKernel(LL_Debug, "UDP cache hit for %s", s_Domain.c_str());
          s_Found = true;
        } else {
          DnsOverHttps::ResolveResult s_DohResponse{m_DohQuery_.Resolve(m_Data_, p_BytesReceived, s_Output)};
          if (s_DohResponse == DnsOverHttps::ResolveResult::Success) {
            logKernel(LL_Debug, "UDP DoH match found");
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

        // Check if response exceeds client's advertised UDP payload size
        uint16_t s_ClientMax{s_EdnsPtr ? s_EdnsPtr->m_UdpPayloadSize_ : static_cast<uint16_t>(Constants::Dns::DEFAULT_DNS_PACKET_SIZE)};
        if (s_Output.size() > s_ClientMax) {
          logKernel(LL_Debug, "UDP response %zu bytes exceeds client payload %u, setting TC=1", s_Output.size(), s_ClientMax);
          // Set TC bit in response header (bit 9 of flags at offset 2-3)
          if (s_Output.size() >= 4) {
            uint16_t s_Flags{0};
            std::copy(s_Output.data() + 2, s_Output.data() + 4, reinterpret_cast<char *>(&s_Flags));
            s_Flags = NetworkToHost(s_Flags);
            s_Flags |= 0x0200; // TC bit
            s_Flags = HostToNetwork(s_Flags);
            std::copy(reinterpret_cast<const char *>(&s_Flags), reinterpret_cast<const char *>(&s_Flags) + 2, s_Output.data() + 2);
          }
        }
      }

      // Hexdump response packet for debugging
      logKernel(LL_Debug, "UDP Response HexDump:");
      logKernelHexdump(LL_Debug, s_Output.data(), s_Output.size());

      LogDnsResponseRecords(s_Output.data(), s_Output.size());

      // Send the response packet
      Send(s_Output.data(), s_Output.size());
    } else {
      if (p_ErrorCode) {
        logKernel(LL_Error, "UDP receive error: %s", p_ErrorCode.message().c_str());
        if (p_ErrorCode == asio::error::bad_descriptor || p_ErrorCode == asio::error::not_socket) {
          ReopenSocket();
          return;
        }
      } else if (p_BytesReceived == 0) {
        logKernel(LL_Debug, "UDP received zero bytes (normal for UDP)");
      }
    }

    if (IsRunning()) {
      Receive();
    } });
}

void UdpServer::Send(const char *p_Data, std::size_t p_Length) {
  if (!p_Data || p_Length == 0) {
    logKernel(LL_Warn, "UDP attempted to send empty or null DNS response");
  } else {
    // Use synchronous send - UDP sends are non-blocking in practice and this
    // avoids lifetime issues with async_send_to where the buffer must outlive the call.
    std::error_code ec;
    m_Socket_.send_to(asio::buffer(p_Data, p_Length), m_SenderEndpoint_, 0, ec);
    if (ec) {
      logKernel(LL_Error, "UDP send error: %s", ec.message().c_str());
      if (ec == asio::error::bad_descriptor || ec == asio::error::not_socket) {
        ReopenSocket();
      }
    } else {
      logKernel(LL_Debug, "UDP sent %zu bytes", p_Length);
    }
  }
}

void UdpServer::ReopenSocket() {
  if (!IsRunning()) {
    return;
  }
  logKernel(LL_Warn, "UDP attempting to reopen listening socket");
  std::error_code ec;
  m_Socket_.close(ec); // Ignore close errors on a broken socket
  try {
    m_Socket_ = asio::ip::udp::socket(m_Context_, asio::ip::udp::endpoint(asio::ip::make_address(g_Config.DnsIpAddress()), g_Config.DnsPort()));
    logKernel(LL_Info, "UDP listening socket restored on %s:%u", g_Config.DnsIpAddress().c_str(), g_Config.DnsPort());
    Receive();
  } catch (const std::exception &e) {
    logKernel(LL_Error, "UDP socket reopen failed: %s, retrying in 1s", e.what());
    m_ReopenTimer_.expires_after(std::chrono::seconds(1));
    m_ReopenTimer_.async_wait([this](std::error_code ec) {
      if (!ec && IsRunning()) {
        ReopenSocket();
      } });
  }
}
