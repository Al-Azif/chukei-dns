// Self
#include "utils.h"

// C
#if defined(__ORBIS__) || defined(__PROSPERO__)
// `sys/types.h` must precede `sys/sysctl.h` as it's not self contained
#include <sys/types.h>  // u_int
#endif

#include <arpa/inet.h>  // inet_pton
#include <sys/socket.h> // AF_INET, AF_INET
#if defined(__ORBIS__) || defined(__PROSPERO__)
#include <sys/sysctl.h> // sysctlbyname
#endif

// C++
#include <cstdint> // uint8_t, uint16_t, uint32_t
#include <cstdio>  // std::snprintf
#include <cstring> // std::memset
#include <string>  // std::getline, std::string
#include <vector>  // std::vector

// Other libraries

// This Project's
#include "constants.h"

// Logging
#include "libLog.h"

// Banned
#include "banned.h"

int Ipv4ToHex(const std::string &p_Input, std::vector<char> &p_Output) {
  if (p_Output.size() < Constants::Network::IPV4_BINARY_SIZE) {
    return -1;
  }
  if (inet_pton(AF_INET, p_Input.c_str(), p_Output.data()) != 1) {
    return -1;
  }
  return 0;
}

int Ipv6ToHex(const std::string &p_Input, std::vector<char> &p_Output) {
  if (p_Output.size() < Constants::Network::IPV6_BINARY_SIZE) {
    return -1;
  }
  if (inet_pton(AF_INET6, p_Input.c_str(), p_Output.data()) != 1) {
    return -1;
  }
  return 0;
}

#if defined(__ORBIS__) || defined(__PROSPERO__)
static int GetIntSysctlByName(const char *p_Name) {
  int s_Ver = 0;
  size_t s_VerLen = sizeof(s_Ver);
  if (sysctlbyname(const_cast<char *>(p_Name), &s_Ver, &s_VerLen, nullptr, 0) != 0) {
    logKernel(LL_Debug, "sysctlbyname(%s) failed", p_Name);
    return -1;
  }
  return s_Ver;
}

static inline uint8_t BcdToDecimal(uint8_t p_Bcd) {
  return (p_Bcd >> 4) * 10 + (p_Bcd & 0x0F);
}

static double ConvertVersionToDouble(uint32_t p_Version) {
  return BcdToDecimal(p_Version >> 24) + BcdToDecimal(p_Version >> 16) / 100.0;
}

uint32_t GetFirmware() {
  int s_UpdVer = 0;
  s_UpdVer = GetIntSysctlByName("machdep.upd_version");
  if (s_UpdVer < 0) {
    logKernel(LL_Debug, "Error retrieving firmware version");
    return 0;
  }
  return static_cast<uint32_t>(s_UpdVer);
}

double GetFirmwareDouble() {
  uint32_t s_Ver = GetFirmware();
  if (s_Ver == 0) {
    return 0.0;
  }
  return ConvertVersionToDouble(s_Ver);
}

int GetFirmwareString(char *p_Output, size_t p_OutputLen) {
  if (!p_Output || p_OutputLen < 5) {
    return -1;
  }
  std::memset(p_Output, '\0', p_OutputLen);

  uint32_t s_Ver = GetFirmware();
  if (s_Ver == 0) {
    return -1;
  }

  int s_RequiredLen = std::snprintf(nullptr, 0, "%.2f", ConvertVersionToDouble(s_Ver)) + 1;
  if (static_cast<size_t>(s_RequiredLen) > p_OutputLen) {
    return -1;
  }

  std::snprintf(p_Output, p_OutputLen, "%.2f", ConvertVersionToDouble(s_Ver));
  return 0;
}
#endif

#if defined(__ORBIS__)
std::string GetOrbisVersion() {
  char s_Version[6]{}; // Flawfinder: ignore - We only use it below and check for 5 chars + null terminator, so 6 is sufficient
  if (GetFirmwareString(s_Version, sizeof(s_Version)) == 0) {
    return s_Version;
  }
  return "UNK";
}
#endif

#if defined(__PROSPERO__)
std::string GetProsperoVersion() {
  char s_Version[6]{}; // Flawfinder: ignore - We only use it below and check for 5 chars + null terminator, so 6 is sufficient
  if (GetFirmwareString(s_Version, sizeof(s_Version)) == 0) {
    return s_Version;
  }
  return "UNK";
}
#endif

#if defined(_WIN32)
#include <libloaderapi.h> // GetModuleHandleW, GetProcAddress
#include <windows.h>
// HMODULE, RtlGetVersionPtr, RTL_OSVERSIONINFOW, PRTL_OSVERSIONINFOW

typedef LONG(WINAPI *RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

std::string GetWindowsVersion() {
  HMODULE s_Module{::GetModuleHandleW(L"ntdll.dll")};
  if (s_Module) {
    RtlGetVersionPtr s_FxPtr{(RtlGetVersionPtr)::GetProcAddress(s_Module, "RtlGetVersion")};
    if (s_FxPtr != nullptr) {
      RTL_OSVERSIONINFOW s_Rovi{{0}};
      s_Rovi.dwOSVersionInfoSize = sizeof(s_Rovi);
      if (s_FxPtr(&s_Rovi) == 0) {
        if (s_Rovi.dwMajorVersion == 10 && s_Rovi.dwMinorVersion == 0) {
          if (s_Rovi.dwBuildNumber >= 22000) {
            return "11";
          } else {
            return "10";
          }
        } else if (s_Rovi.dwMajorVersion == 6 && s_Rovi.dwMinorVersion == 1) {
          return "7";
        } else if (s_Rovi.dwMajorVersion == 6 && s_Rovi.dwMinorVersion == 2) {
          return "8";
        } else if (s_Rovi.dwMajorVersion == 6 && s_Rovi.dwMinorVersion == 3) {
          return "8.1";
        }
        return "";
      }
    }
  }
  return "";
}
#endif

#if defined(__APPLE__) && defined(__MACH__)
#include <cstdio> // fgets, pclose, popen

std::string GetMacOSVersion() {
  std::string s_Version{};
  FILE *s_Pipe{popen("sw_vers -productVersion", "r")}; // Flawfinder: ignore
  if (!s_Pipe) {
    return "";
  }
  char s_Buffer[128]{}; // Flawfinder: ignore
  if (fgets(s_Buffer, sizeof(s_Buffer), s_Pipe)) {
    s_Version = s_Buffer;
    if (!s_Version.empty() && s_Version.back() == '\n') {
      s_Version.pop_back();
    }
  }
  pclose(s_Pipe);
  return s_Version;
}
#endif

#if defined(__linux__)
#include <fstream> // std::ifstream

std::string GetLinuxDistro() {
  std::ifstream s_File("/etc/os-release");
  std::string s_Line{}, s_Distro{};
  while (std::getline(s_File, s_Line)) {
    if (s_Line.find("NAME=") == 0 && s_Line.find("PRETTY_NAME=") != 0) {
      s_Distro = s_Line.substr(5);
      if (!s_Distro.empty() && s_Distro.front() == '"') {
        s_Distro.erase(0, 1);
      }
      if (!s_Distro.empty() && s_Distro.back() == '"') {
        s_Distro.pop_back();
      }
      break;
    }
  }
  return s_Distro;
}

std::string GetLinuxVersion() {
  std::ifstream s_File("/etc/os-release");
  std::string s_Line{}, s_Version{};
  while (std::getline(s_File, s_Line)) {
    if (s_Line.find("VERSION=") == 0) {
      s_Version = s_Line.substr(8);
      if (!s_Version.empty() && s_Version.front() == '"') {
        s_Version.erase(0, 1);
      }
      if (!s_Version.empty() && s_Version.back() == '"') {
        s_Version.pop_back();
      }
      break;
    }
  }
  return s_Version;
}
#endif

void LogDnsResponseRecords(const char *p_Data, std::size_t p_Length) {
  if (!p_Data || p_Length < 12) {
    return;
  }

  const uint8_t *s_Pkt{reinterpret_cast<const uint8_t *>(p_Data)};
  uint16_t s_Qdcount{static_cast<uint16_t>((s_Pkt[4] << 8) | s_Pkt[5])};
  uint16_t s_Ancount{static_cast<uint16_t>((s_Pkt[6] << 8) | s_Pkt[7])};
  uint16_t s_Rcode{static_cast<uint16_t>(s_Pkt[3] & 0x0F)};

  if (s_Ancount == 0) {
    logKernel(LL_Debug, "Response: %u answer(s), rcode=%u", s_Ancount, s_Rcode);
    return;
  }

  // Skip past header (12 bytes) + question section
  std::size_t s_Offset{12};
  for (uint16_t l_Index{0}; l_Index < s_Qdcount && s_Offset < p_Length; ++l_Index) {
    // Skip QNAME
    while (s_Offset < p_Length) {
      uint8_t s_Len{s_Pkt[s_Offset]};
      if ((s_Len & 0xC0) == 0xC0) {
        s_Offset += 2;
        break;
      }
      if (s_Len == 0) {
        s_Offset += 1;
        break;
      }
      s_Offset += 1 + s_Len;
    }
    s_Offset += 4; // QTYPE + QCLASS
  }

  logKernel(LL_Debug, "Response: %u answer(s), rcode=%u", s_Ancount, s_Rcode);

  // Parse and log each answer record
  for (uint16_t l_Index{0}; l_Index < s_Ancount && s_Offset < p_Length; ++l_Index) {
    // Skip NAME
    while (s_Offset < p_Length) {
      uint8_t s_Len{s_Pkt[s_Offset]};
      if ((s_Len & 0xC0) == 0xC0) {
        s_Offset += 2;
        break;
      }
      if (s_Len == 0) {
        s_Offset += 1;
        break;
      }
      s_Offset += 1 + s_Len;
    }

    if (s_Offset + 10 > p_Length) {
      break;
    }

    uint16_t s_Type{static_cast<uint16_t>((s_Pkt[s_Offset] << 8) | s_Pkt[s_Offset + 1])};
    uint16_t s_Class{static_cast<uint16_t>((s_Pkt[s_Offset + 2] << 8) | s_Pkt[s_Offset + 3])};
    uint32_t s_Ttl{static_cast<uint32_t>((s_Pkt[s_Offset + 4] << 24) | (s_Pkt[s_Offset + 5] << 16) | (s_Pkt[s_Offset + 6] << 8) | s_Pkt[s_Offset + 7])};
    uint16_t s_Rdlength{static_cast<uint16_t>((s_Pkt[s_Offset + 8] << 8) | s_Pkt[s_Offset + 9])};
    s_Offset += 10;

    if (s_Offset + s_Rdlength > p_Length) {
      break;
    }

    char s_DataBuf[128]{}; // Flawfinder: ignore
    if (s_Type == 1 && s_Rdlength == 4) {
      // A record - IPv4
      std::snprintf(s_DataBuf, sizeof(s_DataBuf), "%u.%u.%u.%u", s_Pkt[s_Offset], s_Pkt[s_Offset + 1], s_Pkt[s_Offset + 2], s_Pkt[s_Offset + 3]);
      logKernel(LL_Debug, "  Answer[%u]: type=A class=%u ttl=%u data=%s", l_Index, s_Class, s_Ttl, s_DataBuf);
    } else if (s_Type == 28 && s_Rdlength == 16) {
      // AAAA record - IPv6
      std::snprintf(s_DataBuf, sizeof(s_DataBuf), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", s_Pkt[s_Offset], s_Pkt[s_Offset + 1], s_Pkt[s_Offset + 2], s_Pkt[s_Offset + 3], s_Pkt[s_Offset + 4], s_Pkt[s_Offset + 5], s_Pkt[s_Offset + 6], s_Pkt[s_Offset + 7], s_Pkt[s_Offset + 8], s_Pkt[s_Offset + 9], s_Pkt[s_Offset + 10], s_Pkt[s_Offset + 11], s_Pkt[s_Offset + 12], s_Pkt[s_Offset + 13], s_Pkt[s_Offset + 14], s_Pkt[s_Offset + 15]);
      logKernel(LL_Debug, "  Answer[%u]: type=AAAA class=%u ttl=%u data=%s", l_Index, s_Class, s_Ttl, s_DataBuf);
    } else {
      const char *s_TypeStr{"OTHER"};
      switch (s_Type) {
      case 2:
        s_TypeStr = "NS";
        break;
      case 5:
        s_TypeStr = "CNAME";
        break;
      case 6:
        s_TypeStr = "SOA";
        break;
      case 12:
        s_TypeStr = "PTR";
        break;
      case 15:
        s_TypeStr = "MX";
        break;
      case 16:
        s_TypeStr = "TXT";
        break;
      case 33:
        s_TypeStr = "SRV";
        break;
      case 41:
        s_TypeStr = "OPT";
        break;
      }
      logKernel(LL_Debug, "  Answer[%u]: type=%s(%u) class=%u ttl=%u rdlen=%u", l_Index, s_TypeStr, s_Type, s_Class, s_Ttl, s_Rdlength);
    }

    s_Offset += s_Rdlength;
  }
}
