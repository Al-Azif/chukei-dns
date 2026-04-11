/** @file utils.h
 *  @brief Byte-order utilities, IP address conversion helpers, and platform detection functions.
 */

#ifndef UTILS_H_
#define UTILS_H_

#include <cstddef>     // std::size_t
#include <cstdint>     // uint8_t
#include <string>      // std::string
#include <type_traits> // std::is_integral_v, std::is_pointer_v, std::is_unsigned_v, std::make_unsigned_t
#include <vector>      // std::vector

/**
 * @brief Silence unused-variable warnings for intentionally unused parameters
 * @tparam T Type of the unused value.
 */
template <typename T>
constexpr void UNUSED(T &&) noexcept {
}

/**
 * @brief Reverse the byte order of an integral value
 * @tparam T Integral type wider than one byte.
 * @param p_Input Value to byte-swap.
 * @return Byte-swapped value.
 */
template <typename T>
constexpr T SwapEndian(T p_Input) {
  static_assert(std::is_integral_v<T>, "SwapEndian only works with integral types");
  static_assert(!std::is_pointer_v<T>, "Cannot swap endian of pointer types");
  static_assert(sizeof(T) > 1, "Cannot swap endian of single-byte types");

  using U = std::make_unsigned_t<T>;
  U s_Val{static_cast<U>(p_Input)};
  U s_Result{0};

  for (std::size_t l_Index{0}; l_Index < sizeof(T); l_Index++) {
    s_Result = static_cast<U>((s_Result << 8) | (s_Val & 0xFF));
    s_Val >>= 8;
  }

  return static_cast<T>(s_Result);
}

/**
 * @brief Reverse all bits in an integral value
 * @tparam T Integral type.
 * @param p_Input Value whose bits are to be reversed.
 * @return Bit-reversed value.
 */
template <typename T>
constexpr T ReverseBits(T p_Input) {
  static_assert(std::is_integral_v<T>, "ReverseBits only works with integral types");

  T s_Output{};
  constexpr std::size_t bits{sizeof(T) * 8};

  for (std::size_t l_Index{0}; l_Index < bits; l_Index++) {
    s_Output = (s_Output << 1) | (p_Input & 1);
    p_Input >>= 1;
  }

  return s_Output;
}

/**
 * @brief Convert a value from host byte order to network (big-endian) byte order
 * @tparam T Integral type.
 * @param p_Value Value in host byte order.
 * @return Value in network byte order.
 */
template <typename T>
constexpr T HostToNetwork(T p_Value) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return SwapEndian(p_Value);
#elif defined(__LITTLE_ENDIAN__) || defined(_WIN32) || defined(__i386__) || defined(__x86_64__)
  return SwapEndian(p_Value); // Assume little-endian on common platforms
#else
  return p_Value; // Assume big-endian
#endif
}

/**
 * @brief Convert a value from network (big-endian) byte order to host byte order
 * @tparam T Integral type.
 * @param p_Value Value in network byte order.
 * @return Value in host byte order.
 * @note Identical to HostToNetwork since the swap operation is symmetric.
 */
template <typename T>
constexpr T NetworkToHost(T p_Value) {
  return HostToNetwork(p_Value); // Same operation
}

/**
 * @brief Convert an IPv4 address string to its 4-byte binary representation
 * @param p_Input IPv4 address string (e.g., "192.168.1.1").
 * @param p_Output Output vector that must be pre-sized to at least 4 bytes.
 * @return 0 on success, -1 on invalid input or insufficient buffer.
 */
int Ipv4ToHex(const std::string &p_Input, std::vector<char> &p_Output);

/**
 * @brief Convert an IPv6 address string to its 16-byte binary representation
 * @param p_Input IPv6 address string (e.g., "2001:db8::1").
 * @param p_Output Output vector that must be pre-sized to at least 16 bytes.
 * @return 0 on success, -1 on invalid input or insufficient buffer.
 */
int Ipv6ToHex(const std::string &p_Input, std::vector<char> &p_Output);

#if defined(__ORBIS__)
/** @brief Get the Orbis (PS4) firmware version string. */
std::string GetOrbisVersion();
#endif

#if defined(__PROSPERO__)
/** @brief Get the Prospero (PS5) firmware version string. */
std::string GetProsperoVersion();
#endif

#if defined(_WIN32)
/** @brief Get the Windows version string. */
std::string GetWindowsVersion();
#endif

#if defined(__APPLE__) && defined(__MACH__)
/** @brief Get the macOS version string. */
std::string GetMacOSVersion();
#endif

#if defined(__linux__)
/** @brief Get the Linux distribution name. */
std::string GetLinuxDistro();
/** @brief Get the Linux kernel version string. */
std::string GetLinuxVersion();
#endif

/**
 * @brief Log individual answer records from a DNS wire-format response
 *
 * Parses the response packet and logs each answer record at LL_Debug level,
 * showing the record name, type, TTL, class, and decoded data where possible
 * (IPv4/IPv6 addresses).
 *
 * @param p_Data   Pointer to the DNS response packet.
 * @param p_Length  Length of the packet in bytes.
 */
void LogDnsResponseRecords(const char *p_Data, std::size_t p_Length);

#endif
