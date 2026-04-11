// C
// `sys/types.h` must precede `sys/event.h` as it's not self contained
#include <sys/types.h>   // pid_t, size_t, u_int, u_short

#include <csignal>       // SIGINT, SIGTERM
#include <errno.h>       // ENOMEM, errno
#include <signal.h>      // kill, SIGKILL
#include <stdint.h>      // int32_t, uint8_t
#include <stdlib.h>      // free, malloc
#include <string.h>      // strcmp
#include <sys/event.h>   // EV_ADD, EVFILT_PROC, EV_SET, kevent, kqueue, NOTE_EXIT, struct kevent
#include <sys/syscall.h> // SYS_thr_set_name
#include <sys/sysctl.h>  // CTL_KERN, KERN_PROC, KERN_PROC_PROC, sysctl
#include <time.h>        // struct timespec
#include <unistd.h>      // close, getpid, syscall

// C++
#include <exception>    // std::exception
#include <fstream>      // std::ifstream
#include <string>       // std::string
#include <system_error> // std::error_code, std::system_error
#include <vector>       // std::vector

// Other libraries
#include "asio/signal_set.hpp"
#include "asio/ts/internet.hpp"
#include "nlohmann/json.hpp"

// This Project's
#include "config.h"
#include "constants.h"
#include "tcp_server.h"
#include "udp_server.h"

// Logging
#include "libLog.h"

// Banned
#include "banned.h"

pid_t GetPidFromProcName(const char *p_ProcName) {
  if (!p_ProcName) {
    logKernel(LL_Warn, "Process name is NULL");
    return -1;
  }

  int s_Mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
  std::size_t s_Len{0};
  uint8_t *s_Buffer{nullptr};

  // Get required buffer size and allocate with retry logic
  const int s_MaxRetries{3};
  for (int l_Attempt{0}; l_Attempt < s_MaxRetries; ++l_Attempt) {
    if (sysctl(s_Mib, 4, nullptr, &s_Len, nullptr, 0) != 0) {
      logKernel(LL_Warn, "Failed to query process list size");
      return -1;
    }

    if (s_Len == 0) {
      logKernel(LL_Warn, "No processes found in process list");
      return -1;
    }

    s_Buffer = static_cast<uint8_t *>(malloc(s_Len));
    if (!s_Buffer) {
      logKernel(LL_Warn, "Memory allocation failed for process list (%zu bytes)", s_Len);
      return -1;
    }

    if (sysctl(s_Mib, 4, s_Buffer, &s_Len, nullptr, 0) == 0) {
      // Success
      break;
    }
    if (errno != ENOMEM || l_Attempt == s_MaxRetries - 1) {
      logKernel(LL_Warn, "Failed to query process list after %d retries", s_MaxRetries);
      free(s_Buffer);
      return -1;
    }

    free(s_Buffer);
  }

  pid_t s_MyPid{getpid()};
  pid_t s_FoundPid{-1};

  for (uint8_t *l_Ptr{s_Buffer}; l_Ptr < (s_Buffer + s_Len);) {
    int s_StructSize{*(int *)l_Ptr};
    pid_t s_KiPid{*(pid_t *)&l_Ptr[72]};       // XXX: Can we detect this offset, is is standard across all FWs, etc?
    const char *s_TdName{(char *)&l_Ptr[447]}; // XXX: Can we detect this offset, is is standard across all FWs, etc?

    if (strcmp(p_ProcName, s_TdName) == 0 && s_KiPid != s_MyPid) {
      // Found first match
      s_FoundPid = s_KiPid;
      break;
    }

    l_Ptr += s_StructSize;
  }

  free(s_Buffer);
  return s_FoundPid;
}

void KillProcByName(const char *p_ProcName) {
  if (!p_ProcName) {
    return;
  }

  while (true) {
    pid_t s_ProcPid{GetPidFromProcName(p_ProcName)};
    if (s_ProcPid <= 0) {
      break;
    }

    // Use kqueue to wait for process exit
    int s_Kq{kqueue()};
    if (s_Kq == -1) {
      logKernel(LL_Warn, "Failed to create kqueue");
      return;
    }

    struct kevent s_Change;
    EV_SET(&s_Change, s_ProcPid, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, nullptr);

    // Send Signal
    int s_Ret{kill(s_ProcPid, SIGKILL)};
    logKernel(LL_Info, "Sending SIGKILL to %s (pid %d)", p_ProcName, s_ProcPid);
    if (s_Ret == -1) {
      logKernel(LL_Warn, "Failed to kill %s (pid %d)", p_ProcName, s_ProcPid);
      close(s_Kq);
      return;
    }

    struct kevent s_Event;
    struct timespec s_Timeout = {5, 0}; // 5 second timeout
    int s_Nev{kevent(s_Kq, &s_Change, 1, &s_Event, 1, &s_Timeout)};

    if (s_Nev == -1) {
      logKernel(LL_Warn, "kevent failed while waiting for %s (pid %d) to exit", p_ProcName, s_ProcPid);
    } else if (s_Nev == 0) {
      logKernel(LL_Warn, "Timed out waiting for %s (pid %d) to exit", p_ProcName, s_ProcPid);
    } else {
      // logKernel(LL_, "KillProcByName: %s(%d) exited\n", p_ProcName, s_ProcPid);
    }

    close(s_Kq);
  }
}

int main() {
  // Chūkei DNS - A lightweight DNS over HTTPS relay server
  // if (GetPidFromProcName(g_Config.AppName().c_str()) > 0) {
  KillProcByName(g_Config.AppName().c_str());
  // }
  syscall(SYS_thr_set_name, -1, g_Config.AppName().c_str());

  // Load optional runtime configuration from /data/chukei/config.json.
  // All keys are optional; missing keys fall back to built-in defaults.
  std::string s_LogLevel{};
  bool s_DohOnly{false};
  std::vector<std::string> s_DohResolvers{};
  int32_t s_DohTimeout{-1};
  std::string s_UserAgent{};
  std::string s_CacertPath{Constants::Certs::DEFAULT_CACERT_PATH};
  std::string s_ZonesPath{Constants::Paths::DEFAULT_ZONES_PATH};
  std::string s_DnsIp{};
  int s_DnsPort{-1};
  std::string s_RedirectIpv4{};
  std::string s_RedirectIpv6{};
  int32_t s_Ttl{-1};

  std::ifstream s_ConfigFile{Constants::Paths::DEFAULT_CONFIG_PATH};
  if (s_ConfigFile.is_open()) {
    try {
      nlohmann::json s_Json{nlohmann::json::parse(s_ConfigFile)};

      if (s_Json.contains("log_level") && s_Json["log_level"].is_string()) {
        s_LogLevel = s_Json["log_level"].get<std::string>();
      }
      if (s_Json.contains("doh_only") && s_Json["doh_only"].is_boolean()) {
        s_DohOnly = s_Json["doh_only"].get<bool>();
      }
      if (s_Json.contains("doh_resolvers") && s_Json["doh_resolvers"].is_array()) {
        for (const nlohmann::json &s_Entry : s_Json["doh_resolvers"]) {
          if (s_Entry.is_string()) {
            s_DohResolvers.emplace_back(s_Entry.get<std::string>());
          }
        }
      }
      if (s_Json.contains("doh_timeout_ms") && s_Json["doh_timeout_ms"].is_number_integer()) {
        s_DohTimeout = s_Json["doh_timeout_ms"].get<int>();
      }
      if (s_Json.contains("user_agent") && s_Json["user_agent"].is_string()) {
        s_UserAgent = s_Json["user_agent"].get<std::string>();
      }
      if (s_Json.contains("cacert_path") && s_Json["cacert_path"].is_string()) {
        s_CacertPath = s_Json["cacert_path"].get<std::string>();
      }
      if (s_Json.contains("zones_path") && s_Json["zones_path"].is_string()) {
        s_ZonesPath = s_Json["zones_path"].get<std::string>();
      }
      if (s_Json.contains("dns_ip") && s_Json["dns_ip"].is_string()) {
        s_DnsIp = s_Json["dns_ip"].get<std::string>();
      }
      if (s_Json.contains("dns_port") && s_Json["dns_port"].is_number_integer()) {
        s_DnsPort = s_Json["dns_port"].get<int>();
      }
      if (s_Json.contains("redirect_ipv4") && s_Json["redirect_ipv4"].is_string()) {
        s_RedirectIpv4 = s_Json["redirect_ipv4"].get<std::string>();
      }
      if (s_Json.contains("redirect_ipv6") && s_Json["redirect_ipv6"].is_string()) {
        s_RedirectIpv6 = s_Json["redirect_ipv6"].get<std::string>();
      }
      if (s_Json.contains("ttl") && s_Json["ttl"].is_number_integer()) {
        s_Ttl = s_Json["ttl"].get<int32_t>();
      }

      logKernel(LL_Info, "Loaded configuration from %s", Constants::Paths::DEFAULT_CONFIG_PATH);
    } catch (const nlohmann::json::exception &e) {
      logKernel(LL_Warn, "Failed to parse %s: %s - using defaults", Constants::Paths::DEFAULT_CONFIG_PATH, e.what());
    }
  } else {
    logKernel(LL_Info, "No %s found, using defaults", Constants::Paths::DEFAULT_CONFIG_PATH);
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
      logKernel(LL_Warn, "Invalid log_level value: %s (valid: none, fatal, error, warn, info, debug, trace, all) - using default", s_LogLevel.c_str());
    }
  }

  // Apply pre-init settings (must be set before Initialize so zone validation uses them)
  g_Config.DohOnly(s_DohOnly);
  g_Config.CacertPath(s_CacertPath);

  if (!s_RedirectIpv4.empty()) {
    if (g_Config.RedirectIpv4(s_RedirectIpv4) != 0) {
      logKernel(LL_Fatal, "Invalid redirect_ipv4 value: %s", s_RedirectIpv4.c_str());
      return 1;
    }
  }
  if (!s_RedirectIpv6.empty()) {
    if (g_Config.RedirectIpv6(s_RedirectIpv6) != 0) {
      logKernel(LL_Fatal, "Invalid redirect_ipv6 value: %s", s_RedirectIpv6.c_str());
      return 1;
    }
  }
  if (s_Ttl >= 0) {
    if (g_Config.DefaultTtl(s_Ttl) != 0) {
      logKernel(LL_Fatal, "Invalid ttl value: %d", s_Ttl);
      return 1;
    }
  }

  g_Config.Initialize(s_ZonesPath);

  // Apply post-init overrides
  if (!s_DohResolvers.empty()) {
    if (g_Config.DohResolvers(s_DohResolvers) != 0) {
      logKernel(LL_Fatal, "No valid doh_resolvers provided");
      return 1;
    }
  }
  if (s_DohTimeout >= 0) {
    if (g_Config.DohTimeoutMs(s_DohTimeout) != 0) {
      logKernel(LL_Fatal, "Invalid doh_timeout_ms value: %d", s_DohTimeout);
      return 1;
    }
  }
  if (!s_UserAgent.empty()) {
    if (g_Config.Useragent(s_UserAgent) != 0) {
      logKernel(LL_Fatal, "Invalid user_agent value");
      return 1;
    }
  }
  if (!s_DnsIp.empty()) {
    if (g_Config.DnsIpAddress(s_DnsIp) != 0) {
      logKernel(LL_Fatal, "Invalid dns_ip value: %s", s_DnsIp.c_str());
      return 1;
    }
  }
  if (s_DnsPort >= 0) {
    if (g_Config.DnsPort(static_cast<uint16_t>(s_DnsPort)) != 0) {
      logKernel(LL_Fatal, "Invalid dns_port value: %d", s_DnsPort);
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
