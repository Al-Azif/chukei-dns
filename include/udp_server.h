/** @file udp_server.h
 *  @brief Asynchronous UDP DNS server that routes queries through local zones, cache, and DoH.
 */

#ifndef UDP_SERVER_H_
#define UDP_SERVER_H_

#include <atomic>  // std::atomic
#include <cstddef> // std::size_t
#include <cstdint> // uint16_t

#include "asio/steady_timer.hpp"
#include "asio/ts/internet.hpp"

#include "constants.h"
#include "dns_cache.h"
#include "dns_over_https.h"

/**
 * @brief Asynchronous UDP DNS server for query dispatch and response routing
 *
 * Queries are first checked against local zones, then the response cache,
 * and finally forwarded upstream via DNS-over-HTTPS. The server runs
 * asynchronously within an ASIO io_context.
 */
class UdpServer {
public:
  /**
   * @brief Construct and start the UDP DNS server
   * @param p_Context ASIO io_context to run the server on.
   */
  explicit UdpServer(asio::io_context &p_Context);

  /** @brief Stop the server and close the UDP socket. */
  void Stop();

  /** @brief Check if the server is currently running. */
  [[nodiscard]] bool IsRunning() const;

private:
  asio::io_context &m_Context_;
  asio::ip::udp::socket m_Socket_;
  asio::ip::udp::endpoint m_SenderEndpoint_;
  asio::steady_timer m_ReopenTimer_;
  std::atomic<bool> m_IsRunning_{false};
  DnsOverHttps m_DohQuery_;
  DnsCache m_DnsCache_;
  char m_Data_[Constants::Dns::DEFAULT_DNS_PACKET_SIZE]{}; // Flawfinder: ignore

  int IsRunning(bool p_Input);

  void Receive();
  void Send(const char *p_Data, std::size_t p_Length);
  void ReopenSocket();
};

#endif
