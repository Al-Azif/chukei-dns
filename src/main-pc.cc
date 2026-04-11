// C

// C++
#include <csignal>      // SIGINT, SIGTERM
#include <cstdlib>      // std::strtol, std::strtoul
#include <cstring>      // std::strcmp
#include <exception>    // std::exception
#include <string>       // std::string
#include <system_error> // std::error_code, std::system_error
#include <vector>       // std::vector

// Other libraries
#include "asio/signal_set.hpp"
#include "asio/ts/internet.hpp"

// This Project's
#include "config.h"
#include "constants.h"
#include "tcp_server.h"
#include "udp_server.h"

// Logging
#include "libLog.h"

// Banned
#include "banned.h"

static void PrintHelp(const char *p_Argv0) {
  logKernelUnformatted(LL_Info, "Usage: %s [options]\n", p_Argv0);
  logKernelUnformatted(LL_Info, "\n");
  logKernelUnformatted(LL_Info, "Options:\n");
  logKernelUnformatted(LL_Info, "  --log-level <level>     Log level: none, fatal, error, warn, info, debug, trace, all (default: info)\n");
  logKernelUnformatted(LL_Info, "  --doh-only              Enable DoH-only mode (no local zone responses)\n");
  logKernelUnformatted(LL_Info, "  --doh-resolver <url>    DoH resolver URL (can be specified multiple times)\n");
  logKernelUnformatted(LL_Info, "  --doh-timeout <ms>      Total timeout budget for DoH resolution (default: %d)\n", Constants::Network::DEFAULT_DOH_TIMEOUT_MS);
  logKernelUnformatted(LL_Info, "  --user-agent <string>   User-Agent string for DoH requests\n");
  logKernelUnformatted(LL_Info, "  --cacert <path>         Path to a PEM CA certificate bundle for TLS verification\n");
  logKernelUnformatted(LL_Info, "  --zones <path>          Path to the zones.json file (default: %s)\n", Constants::Paths::DEFAULT_ZONES_PATH);
  logKernelUnformatted(LL_Info, "  --dns-ip <ip>           IP address for the DNS server (default: %s)\n", Constants::Network::DEFAULT_DNS_IP);
  logKernelUnformatted(LL_Info, "  --dns-port <port>       Port for the DNS server (default: %u)\n", Constants::Network::DEFAULT_DNS_PORT);
  logKernelUnformatted(LL_Info, "  --redirect-ipv4 <ip>    IPv4 address for redirection (default: %s)\n", Constants::Network::DEFAULT_IPV4_REDIRECT);
  logKernelUnformatted(LL_Info, "  --redirect-ipv6 <ip>    IPv6 address for redirection (default: %s)\n", Constants::Network::DEFAULT_IPV6_REDIRECT);
  logKernelUnformatted(LL_Info, "  --ttl <seconds>         Default TTL for DNS responses (default: %d)\n", Constants::Network::DEFAULT_TTL);
  logKernelUnformatted(LL_Info, "  --help                  Display this help message\n");
}

int main(int argc, char *argv[]) {
  // Chūkei DNS - A lightweight DNS over HTTPS relay server

  // Parse CLI arguments
  std::string s_LogLevel{};
  bool s_DohOnly{false};
  std::vector<std::string> s_DohResolvers{};
  int32_t s_DohTimeout{-1};
  std::string s_UserAgent{};
  std::string s_CacertPath{};
  std::string s_ZonesPath{Constants::Paths::DEFAULT_ZONES_PATH};
  std::string s_DnsIp{};
  int s_DnsPort{-1};
  std::string s_RedirectIpv4{};
  std::string s_RedirectIpv6{};
  int32_t s_Ttl{-1};

  for (int l_Arg{1}; l_Arg < argc; ++l_Arg) {
    if (std::strcmp(argv[l_Arg], "--log-level") == 0) {
      if (l_Arg + 1 >= argc) {
        logKernel(LL_Fatal, "--log-level requires a level argument");
        return 1;
      }
      s_LogLevel = argv[++l_Arg];
    } else if (std::strcmp(argv[l_Arg], "--doh-only") == 0) {
      s_DohOnly = true;
    } else if (std::strcmp(argv[l_Arg], "--doh-resolver") == 0) {
      if (l_Arg + 1 >= argc) {
        logKernel(LL_Fatal, "--doh-resolver requires a URL argument");
        return 1;
      }
      s_DohResolvers.emplace_back(argv[++l_Arg]);
    } else if (std::strcmp(argv[l_Arg], "--doh-timeout") == 0) {
      if (l_Arg + 1 >= argc) {
        logKernel(LL_Fatal, "--doh-timeout requires a numeric argument");
        return 1;
      }
      char *s_End{nullptr};
      long s_Val{std::strtol(argv[++l_Arg], &s_End, 10)};
      if (s_End == argv[l_Arg] || *s_End != '\0' || s_Val < Constants::Network::MIN_DOH_TIMEOUT_MS || s_Val > Constants::Network::MAX_DOH_TIMEOUT_MS) {
        logKernel(LL_Fatal, "Invalid --doh-timeout value: %s (valid range: %d-%d)", argv[l_Arg], Constants::Network::MIN_DOH_TIMEOUT_MS, Constants::Network::MAX_DOH_TIMEOUT_MS);
        return 1;
      }
      s_DohTimeout = static_cast<int32_t>(s_Val);
    } else if (std::strcmp(argv[l_Arg], "--user-agent") == 0) {
      if (l_Arg + 1 >= argc) {
        logKernel(LL_Fatal, "--user-agent requires a string argument");
        return 1;
      }
      s_UserAgent = argv[++l_Arg];
    } else if (std::strcmp(argv[l_Arg], "--cacert") == 0) {
      if (l_Arg + 1 >= argc) {
        logKernel(LL_Fatal, "--cacert requires a path argument");
        return 1;
      }
      s_CacertPath = argv[++l_Arg];
    } else if (std::strcmp(argv[l_Arg], "--zones") == 0) {
      if (l_Arg + 1 >= argc) {
        logKernel(LL_Fatal, "--zones requires a path argument");
        return 1;
      }
      s_ZonesPath = argv[++l_Arg];
    } else if (std::strcmp(argv[l_Arg], "--dns-ip") == 0) {
      if (l_Arg + 1 >= argc) {
        logKernel(LL_Fatal, "--dns-ip requires an IP address argument");
        return 1;
      }
      s_DnsIp = argv[++l_Arg];
    } else if (std::strcmp(argv[l_Arg], "--dns-port") == 0) {
      if (l_Arg + 1 >= argc) {
        logKernel(LL_Fatal, "--dns-port requires a port number argument");
        return 1;
      }
      char *s_End{nullptr};
      long s_Val{std::strtol(argv[++l_Arg], &s_End, 10)};
      if (s_End == argv[l_Arg] || *s_End != '\0' || s_Val < Constants::Network::MIN_DNS_PORT || s_Val > Constants::Network::MAX_DNS_PORT) {
        logKernel(LL_Fatal, "Invalid port number: %s (valid range: %u-%u)", argv[l_Arg], Constants::Network::MIN_DNS_PORT, Constants::Network::MAX_DNS_PORT);
        return 1;
      }
      s_DnsPort = static_cast<int>(s_Val);
    } else if (std::strcmp(argv[l_Arg], "--redirect-ipv4") == 0) {
      if (l_Arg + 1 >= argc) {
        logKernel(LL_Fatal, "--redirect-ipv4 requires an IPv4 address argument");
        return 1;
      }
      s_RedirectIpv4 = argv[++l_Arg];
    } else if (std::strcmp(argv[l_Arg], "--redirect-ipv6") == 0) {
      if (l_Arg + 1 >= argc) {
        logKernel(LL_Fatal, "--redirect-ipv6 requires an IPv6 address argument");
        return 1;
      }
      s_RedirectIpv6 = argv[++l_Arg];
    } else if (std::strcmp(argv[l_Arg], "--ttl") == 0) {
      if (l_Arg + 1 >= argc) {
        logKernel(LL_Fatal, "--ttl requires a numeric argument");
        return 1;
      }
      char *s_End{nullptr};
      long s_Val{std::strtol(argv[++l_Arg], &s_End, 10)};
      if (s_End == argv[l_Arg] || *s_End != '\0' || s_Val < Constants::Network::MIN_TTL || s_Val > Constants::Network::MAX_TTL) {
        logKernel(LL_Fatal, "Invalid TTL value: %s (valid range: %d-%d)", argv[l_Arg], Constants::Network::MIN_TTL, Constants::Network::MAX_TTL);
        return 1;
      }
      s_Ttl = static_cast<int32_t>(s_Val);
    } else if (std::strcmp(argv[l_Arg], "--help") == 0) {
      PrintHelp(argv[0]);
      return 0;
    } else {
      logKernel(LL_Fatal, "Unknown option: %s", argv[l_Arg]);
      PrintHelp(argv[0]);
      return 1;
    }
  }

  // Apply log level as early as possible
  if (!s_LogLevel.empty()) {
    if (s_LogLevel == "none") {
      logSetLogLevel(LL_None);
    } else if (s_LogLevel == "fatal") {
      logSetLogLevel(LL_Fatal);
    } else if (s_LogLevel == "error") {
      logSetLogLevel(LL_Error);
    } else if (s_LogLevel == "warn") {
      logSetLogLevel(LL_Warn);
    } else if (s_LogLevel == "info") {
      logSetLogLevel(LL_Info);
    } else if (s_LogLevel == "debug") {
      logSetLogLevel(LL_Debug);
    } else if (s_LogLevel == "trace") {
      logSetLogLevel(LL_Trace);
    } else if (s_LogLevel == "all") {
      logSetLogLevel(LL_All);
    } else {
      logKernel(LL_Fatal, "Invalid --log-level value: %s (valid: none, fatal, error, warn, info, debug, trace, all)", s_LogLevel.c_str());
      return 1;
    }
  }

  // Apply pre-init settings
  g_Config.DohOnly(s_DohOnly);
  if (!s_CacertPath.empty()) {
    g_Config.CacertPath(s_CacertPath);
  }

  // Apply redirect addresses before Initialize so zones validation uses them
  if (!s_RedirectIpv4.empty()) {
    if (g_Config.RedirectIpv4(s_RedirectIpv4) != 0) {
      logKernel(LL_Fatal, "Invalid --redirect-ipv4 value: %s", s_RedirectIpv4.c_str());
      return 1;
    }
  }
  if (!s_RedirectIpv6.empty()) {
    if (g_Config.RedirectIpv6(s_RedirectIpv6) != 0) {
      logKernel(LL_Fatal, "Invalid --redirect-ipv6 value: %s", s_RedirectIpv6.c_str());
      return 1;
    }
  }

  // Apply TTL before Initialize so zones validation uses it
  if (s_Ttl >= 0) {
    if (g_Config.DefaultTtl(s_Ttl) != 0) {
      logKernel(LL_Fatal, "Failed to set TTL to %d", s_Ttl);
      return 1;
    }
  }

  g_Config.Initialize(s_ZonesPath);

  // Apply post-init overrides
  if (!s_DohResolvers.empty()) {
    if (g_Config.DohResolvers(s_DohResolvers) != 0) {
      logKernel(LL_Fatal, "No valid DoH resolvers provided");
      return 1;
    }
  }
  if (s_DohTimeout >= 0) {
    if (g_Config.DohTimeoutMs(s_DohTimeout) != 0) {
      logKernel(LL_Fatal, "Invalid DoH timeout value: %d", s_DohTimeout);
      return 1;
    }
  }
  if (!s_UserAgent.empty()) {
    if (g_Config.Useragent(s_UserAgent) != 0) {
      logKernel(LL_Fatal, "Invalid --user-agent value");
      return 1;
    }
  }
  if (!s_DnsIp.empty()) {
    if (g_Config.DnsIpAddress(s_DnsIp) != 0) {
      logKernel(LL_Fatal, "Invalid --dns-ip value: %s", s_DnsIp.c_str());
      return 1;
    }
  }
  if (s_DnsPort >= 0) {
    if (g_Config.DnsPort(static_cast<uint16_t>(s_DnsPort)) != 0) {
      logKernel(LL_Fatal, "Invalid --dns-port value: %d", s_DnsPort);
      return 1;
    }
  }

  if (!g_Config.Initialized()) {
    logKernel(LL_Fatal, "Failed to initialize configuration");
    return 1;
  }

  logKernelUnformatted(LL_Info, ".------------------------------------------------------------------------------.\n");
  const std::string s_AppNameLine{g_Config.AppName() + " by " + g_Config.AppAuthor()};
  const int s_PaddingNeeded{77 - static_cast<int>(s_AppNameLine.length())};
  const std::string s_Padding(s_PaddingNeeded > 0 ? s_PaddingNeeded : 0, ' ');
  logKernelUnformatted(LL_Info, "| %s%s |\n", s_AppNameLine.c_str(), s_Padding.c_str());
  logKernelUnformatted(LL_Info, "'------------------------------------------------------------------------------'\n");
  logKernelUnformatted(LL_Info, "License:      %s\n", g_Config.AppLicense().c_str());
  logKernelUnformatted(LL_Info, "Build Type:   %s\n", g_Config.AppBuildType().c_str());
  logKernelUnformatted(LL_Info, "Version:      %s\n", g_Config.AppVersion().c_str());
  logKernelUnformatted(LL_Info, "Description:  %s\n", g_Config.AppDescription().c_str());
  logKernelUnformatted(LL_Info, "Homepage:     %s\n", g_Config.AppHomepage().c_str());

  logKernelUnformatted(LL_Info, "Log Level:    %s\n", s_LogLevel.empty() ? "info" : s_LogLevel.c_str());

  logKernelUnformatted(LL_Info, "DoH Only:     %s\n", g_Config.DohOnly() ? "True" : "False");
  if (!s_DohResolvers.empty()) {
    logKernelUnformatted(LL_Info, "DoH Resolvers:\n");
    for (const std::string &resolver : s_DohResolvers) {
      logKernelUnformatted(LL_Info, "  - %s\n", resolver.c_str());
    }
  }
  logKernelUnformatted(LL_Info, "DoH Timeout:  %d ms\n", g_Config.DohTimeoutMs());
  logKernelUnformatted(LL_Info, "User-Agent:   %s\n", g_Config.Useragent().c_str());
  logKernelUnformatted(LL_Info, "CACert Path:  %s\n", g_Config.CacertPath().empty() ? "(system default)" : g_Config.CacertPath().c_str());

  logKernelUnformatted(LL_Info, "Zones Path:   %s\n", g_Config.ZonesPath().empty() ? "(default)" : g_Config.ZonesPath().c_str());
  logKernelUnformatted(LL_Info, "DNS Listen:   %s:%u\n", g_Config.DnsIpAddress().c_str(), g_Config.DnsPort());
  logKernelUnformatted(LL_Info, "Redirect v4:  %s\n", g_Config.RedirectIpv4().c_str());
  logKernelUnformatted(LL_Info, "Redirect v6:  %s\n", g_Config.RedirectIpv6().c_str());
  logKernelUnformatted(LL_Info, "Default TTL:  %d\n", g_Config.DefaultTtl());

  try {
    asio::io_context s_Context{};
    UdpServer s_UdpServer(s_Context);
    TcpServer s_TcpServer(s_Context);

    try {
      asio::signal_set signals(s_Context, SIGINT, SIGTERM);
      signals.async_wait([&](const std::error_code &ec, int signal_number) {
        if (!ec) {
          logKernel(LL_Info, "Shutdown signal received (signal: %d)", signal_number);
          s_UdpServer.Stop();
          s_TcpServer.Stop();
          s_Context.stop();
        } });

      logKernel(LL_Info, "Starting DNS relay (UDP + TCP)...");
      s_Context.run();
      logKernel(LL_Info, "DNS relay stopped");
    } catch (const std::exception &signal_error) {
      logKernel(LL_Warn, "Signal handling not available: %s", signal_error.what());
      logKernel(LL_Info, "Starting DNS relay without signal handling...");
      s_Context.run();
    }
  } catch (const std::system_error &e) {
    logKernel(LL_Fatal, "System error: %s (code: %d)", e.what(), e.code().value());
    return 1;
  } catch (const std::exception &e) {
    logKernel(LL_Fatal, "Exception: %s", e.what());
    return 1;
  } catch (...) {
    logKernel(LL_Fatal, "Unknown exception occurred");
    return 1;
  }

  return 0;
}
