/** @file tcp_server.h
 *  @brief Asynchronous TCP DNS server that routes queries through local zones, cache, and DoH.
 */

#ifndef TCP_SERVER_H_
#define TCP_SERVER_H_

#include <atomic>  // std::atomic
#include <cstddef> // std::size_t
#include <cstdint> // uint16_t
#include <memory>  // std::enable_shared_from_this, std::shared_ptr
#include <vector>  // std::vector

#include "asio/steady_timer.hpp"
#include "asio/ts/internet.hpp"

#include "constants.h"
#include "dns_cache.h"
#include "dns_over_https.h"

/**
 * @brief A single TCP DNS session handling one client connection
 *
 * Each session reads DNS messages prefixed with a 2-byte length field
 * per RFC 1035 §4.2.2, processes them through local zones / cache / DoH,
 * and writes back the response with the same 2-byte length prefix.
 * Multiple queries can be sent over one connection.
 */
class TcpSession : public std::enable_shared_from_this<TcpSession> {
public:
  TcpSession(asio::ip::tcp::socket p_Socket, DnsOverHttps &p_DohQuery, DnsCache &p_DnsCache);

  /** @brief Begin reading DNS messages from the connection. */
  void Start();

private:
  void ReadLength();
  void ReadMessage(uint16_t p_MessageLength);
  void Send(const char *p_Data, std::size_t p_Length);

  asio::ip::tcp::socket m_Socket_;
  DnsOverHttps &m_DohQuery_;
  DnsCache &m_DnsCache_;
  char m_LengthBuf_[2]{};  // Flawfinder: ignore // 2-byte length prefix buffer per RFC 1035 §4.2.2
  std::vector<char> m_Data_;
};

/**
 * @brief Asynchronous TCP DNS server for query dispatch and response routing
 *
 * Listens for incoming TCP connections and spawns a TcpSession for each.
 * Queries follow the same dispatch path as the UDP server: local zones
 * first, then cache, then DNS-over-HTTPS.
 */
class TcpServer {
public:
  /**
   * @brief Construct and start the TCP DNS server
   * @param p_Context ASIO io_context to run the server on.
   */
  explicit TcpServer(asio::io_context &p_Context);

  /** @brief Stop the server and close the TCP acceptor. */
  void Stop();

  /** @brief Check if the server is currently running. */
  [[nodiscard]] bool IsRunning() const;

private:
  asio::io_context &m_Context_;
  asio::ip::tcp::acceptor m_Acceptor_;
  asio::steady_timer m_ReopenTimer_;
  std::atomic<bool> m_IsRunning_{false};
  DnsOverHttps m_DohQuery_;
  DnsCache m_DnsCache_;

  int IsRunning(bool p_Input);

  void Accept();
  void ReopenAcceptor();
};

#endif
