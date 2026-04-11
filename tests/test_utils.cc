// Tests for utility functions: SwapEndian, ReverseBits, HostToNetwork, Ipv4ToHex, Ipv6ToHex
#include "test_framework.h"

#include "utils.h"

#include <cstdint>
#include <vector>

// ============================================================================
// SwapEndian tests
// ============================================================================

TEST(SwapEndian_uint16) {
  ASSERT_EQ(SwapEndian<uint16_t>(0x0102), static_cast<uint16_t>(0x0201));
}

TEST(SwapEndian_uint32) {
  ASSERT_EQ(SwapEndian<uint32_t>(0x01020304), static_cast<uint32_t>(0x04030201));
}

TEST(SwapEndian_uint16_zero) {
  ASSERT_EQ(SwapEndian<uint16_t>(0x0000), static_cast<uint16_t>(0x0000));
}

TEST(SwapEndian_uint16_ffff) {
  ASSERT_EQ(SwapEndian<uint16_t>(0xFFFF), static_cast<uint16_t>(0xFFFF));
}

TEST(SwapEndian_roundtrip_uint16) {
  uint16_t s_Val{0x1234};
  ASSERT_EQ(SwapEndian(SwapEndian(s_Val)), s_Val);
}

TEST(SwapEndian_roundtrip_uint32) {
  uint32_t s_Val{0xDEADBEEF};
  ASSERT_EQ(SwapEndian(SwapEndian(s_Val)), s_Val);
}

// ============================================================================
// ReverseBits tests
// ============================================================================

TEST(ReverseBits_uint8) {
  // 0b10000000 -> 0b00000001
  ASSERT_EQ(ReverseBits<uint8_t>(0x80), static_cast<uint8_t>(0x01));
}

TEST(ReverseBits_uint8_zero) {
  ASSERT_EQ(ReverseBits<uint8_t>(0x00), static_cast<uint8_t>(0x00));
}

TEST(ReverseBits_uint8_ff) {
  ASSERT_EQ(ReverseBits<uint8_t>(0xFF), static_cast<uint8_t>(0xFF));
}

TEST(ReverseBits_uint16_roundtrip) {
  uint16_t s_Val{0xABCD};
  ASSERT_EQ(ReverseBits(ReverseBits(s_Val)), s_Val);
}

TEST(ReverseBits_uint16_specific) {
  // 0x8000 = 1000000000000000 -> 0000000000000001 = 0x0001
  ASSERT_EQ(ReverseBits<uint16_t>(0x8000), static_cast<uint16_t>(0x0001));
}

// ============================================================================
// HostToNetwork / NetworkToHost tests
// ============================================================================

TEST(HostToNetwork_roundtrip_uint16) {
  uint16_t s_Val{0x1234};
  ASSERT_EQ(NetworkToHost(HostToNetwork(s_Val)), s_Val);
}

TEST(HostToNetwork_roundtrip_uint32) {
  uint32_t s_Val{0xDEADBEEF};
  ASSERT_EQ(NetworkToHost(HostToNetwork(s_Val)), s_Val);
}

// On little-endian (x86), HostToNetwork should swap bytes
TEST(HostToNetwork_swaps_on_LE) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  ASSERT_EQ(HostToNetwork<uint16_t>(0x0102), static_cast<uint16_t>(0x0201));
#else
  // On big-endian, no swap
  ASSERT_EQ(HostToNetwork<uint16_t>(0x0102), static_cast<uint16_t>(0x0102));
#endif
}

// ============================================================================
// Ipv4ToHex tests
// ============================================================================

TEST(Ipv4ToHex_valid) {
  std::vector<char> s_Output(4);
  ASSERT_EQ(Ipv4ToHex("192.168.1.1", s_Output), 0);
  ASSERT_EQ(static_cast<unsigned char>(s_Output[0]), 192u);
  ASSERT_EQ(static_cast<unsigned char>(s_Output[1]), 168u);
  ASSERT_EQ(static_cast<unsigned char>(s_Output[2]), 1u);
  ASSERT_EQ(static_cast<unsigned char>(s_Output[3]), 1u);
}

TEST(Ipv4ToHex_loopback) {
  std::vector<char> s_Output(4);
  ASSERT_EQ(Ipv4ToHex("127.0.0.1", s_Output), 0);
  ASSERT_EQ(static_cast<unsigned char>(s_Output[0]), 127u);
  ASSERT_EQ(static_cast<unsigned char>(s_Output[1]), 0u);
  ASSERT_EQ(static_cast<unsigned char>(s_Output[2]), 0u);
  ASSERT_EQ(static_cast<unsigned char>(s_Output[3]), 1u);
}

TEST(Ipv4ToHex_zeros) {
  std::vector<char> s_Output(4);
  ASSERT_EQ(Ipv4ToHex("0.0.0.0", s_Output), 0);
  for (int l_Index = 0; l_Index < 4; ++l_Index) {
    ASSERT_EQ(s_Output[l_Index], 0);
  }
}

TEST(Ipv4ToHex_invalid) {
  std::vector<char> s_Output(4);
  ASSERT_EQ(Ipv4ToHex("not.an.ip.addr", s_Output), -1);
}

TEST(Ipv4ToHex_empty) {
  std::vector<char> s_Output(4);
  ASSERT_EQ(Ipv4ToHex("", s_Output), -1);
}

TEST(Ipv4ToHex_broadcast) {
  std::vector<char> s_Output(4);
  ASSERT_EQ(Ipv4ToHex("255.255.255.255", s_Output), 0);
  for (int l_Index = 0; l_Index < 4; ++l_Index) {
    ASSERT_EQ(static_cast<unsigned char>(s_Output[l_Index]), 255u);
  }
}

// ============================================================================
// Ipv6ToHex tests
// ============================================================================

TEST(Ipv6ToHex_loopback) {
  std::vector<char> s_Output(16);
  ASSERT_EQ(Ipv6ToHex("::1", s_Output), 0);
  for (int l_Index = 0; l_Index < 15; ++l_Index) {
    ASSERT_EQ(s_Output[l_Index], 0);
  }
  ASSERT_EQ(static_cast<unsigned char>(s_Output[15]), 1u);
}

TEST(Ipv6ToHex_all_zeros) {
  std::vector<char> s_Output(16);
  ASSERT_EQ(Ipv6ToHex("::", s_Output), 0);
  for (int l_Index = 0; l_Index < 16; ++l_Index) {
    ASSERT_EQ(s_Output[l_Index], 0);
  }
}

TEST(Ipv6ToHex_invalid) {
  std::vector<char> s_Output(16);
  ASSERT_EQ(Ipv6ToHex("not_an_ipv6", s_Output), -1);
}

TEST(Ipv6ToHex_full) {
  std::vector<char> s_Output(16);
  ASSERT_EQ(Ipv6ToHex("2001:0db8:85a3:0000:0000:8a2e:0370:7334", s_Output), 0);
  ASSERT_EQ(static_cast<unsigned char>(s_Output[0]), 0x20u);
  ASSERT_EQ(static_cast<unsigned char>(s_Output[1]), 0x01u);
}

TEST(Ipv4ToHex_undersized_buffer) {
  std::vector<char> s_Output(2); // Too small for 4-byte IPv4
  ASSERT_EQ(Ipv4ToHex("192.168.1.1", s_Output), -1);
}

TEST(Ipv6ToHex_undersized_buffer) {
  std::vector<char> s_Output(8); // Too small for 16-byte IPv6
  ASSERT_EQ(Ipv6ToHex("::1", s_Output), -1);
}

// ============================================================================
// UNUSED macro test
// ============================================================================

TEST(UNUSED_compiles) {
  int s_X{42};
  UNUSED(s_X);
  ASSERT_TRUE(true); // If we get here, UNUSED compiled fine
}

// ============================================================================
// SwapEndian - constexpr verification (bit-shift implementation)
// ============================================================================

TEST(SwapEndian_constexpr_uint16) {
  // Verify constexpr evaluation works (compile-time check)
  constexpr uint16_t s_Val{SwapEndian(static_cast<uint16_t>(0x0102))};
  ASSERT_EQ(s_Val, static_cast<uint16_t>(0x0201));
}

TEST(SwapEndian_constexpr_uint32) {
  constexpr uint32_t s_Val{SwapEndian(static_cast<uint32_t>(0x01020304))};
  ASSERT_EQ(s_Val, static_cast<uint32_t>(0x04030201));
}
