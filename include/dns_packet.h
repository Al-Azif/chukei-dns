/** @file dns_packet.h
 *  @brief DnsRequestPacket and DnsResponsePacket classes for DNS wire-format packet representation.
 */

#ifndef DNS_PACKET_H_
#define DNS_PACKET_H_

#include <array>    // std::array
#include <cstddef>  // std::size_t
#include <cstdint>  // uint8_t, uint16_t
#include <optional> // std::optional
#include <ostream>  // std::ostream
#include <string>   // std::string
#include <vector>   // std::vector

#include "dns_edns0.h"
#include "dns_packet_answer.h"
#include "dns_packet_header.h"
#include "dns_packet_question.h"

/**
 * @brief DNS Request Packet class for building and parsing DNS queries
 *
 * This class represents a complete DNS query packet containing a header and
 * questions. It provides methods for constructing queries, parsing from wire
 * format, and serializing to wire format.
 *
 * @note Follows RFC 1035 DNS message format
 */
class DnsRequestPacket {
public:
  /// @name STL Container Type Aliases
  /// @{
  using size_type = std::size_t;          ///< Type used for sizes and counts
  using difference_type = std::ptrdiff_t; ///< Type used for pointer arithmetic
  /// @}

  /// @name Constructors and Destructor
  /// @{

  /**
   * @brief Default constructor - creates empty request packet
   */
  DnsRequestPacket() = default;

  /**
   * @brief Construct from wire format data
   * @param p_Data Pointer to DNS packet data
   * @param p_Size Size of packet data in bytes
   * @throws std::invalid_argument if data is invalid or insufficient
   */
  DnsRequestPacket(const char *p_Data, size_type p_Size);

  /**
   * @brief Construct from string containing wire format data
   * @param p_Data String containing DNS packet data
   * @throws std::invalid_argument if data is invalid or insufficient
   */
  explicit DnsRequestPacket(const std::string &p_Data);

  /**
   * @brief Construct from vector containing wire format data
   * @param p_Data Vector containing DNS packet data
   * @throws std::invalid_argument if data is invalid or insufficient
   */
  explicit DnsRequestPacket(const std::vector<char> &p_Data);

  /**
   * @brief Construct from std::vector<unsigned char> containing wire format data
   * @param p_Data Vector containing DNS packet data
   * @throws std::invalid_argument if data is invalid or insufficient
   */
  explicit DnsRequestPacket(const std::vector<unsigned char> &p_Data);

  /**
   * @brief Construct from C array containing wire format data
   * @tparam N Size of the array
   * @param p_Data C array containing DNS packet data
   * @throws std::invalid_argument if data is invalid or insufficient
   */
  template <size_type N>
  explicit DnsRequestPacket(const char (&p_Data)[N]) {
    if (!FromWire(p_Data, N, *this)) {
      throw std::invalid_argument("DnsRequestPacket: invalid packet data");
    }
  }

  /**
   * @brief Construct from std::array<char> containing wire format data
   * @tparam N Size of the array
   * @param p_Data Array containing DNS packet data
   * @throws std::invalid_argument if data is invalid or insufficient
   */
  template <size_type N>
  explicit DnsRequestPacket(const std::array<char, N> &p_Data) {
    if (!FromWire(p_Data.data(), N, *this)) {
      throw std::invalid_argument("DnsRequestPacket: invalid packet data");
    }
  }

  /**
   * @brief Construct from std::array<unsigned char> containing wire format data
   * @tparam N Size of the array
   * @param p_Data Array containing DNS packet data
   * @throws std::invalid_argument if data is invalid or insufficient
   */
  template <size_type N>
  explicit DnsRequestPacket(const std::array<unsigned char, N> &p_Data) {
    if (!FromWire(reinterpret_cast<const char *>(p_Data.data()), N, *this)) {
      throw std::invalid_argument("DnsRequestPacket: invalid packet data");
    }
  }

  /**
   * @brief Construct request packet with header and questions
   * @param p_Header DNS header
   * @param p_Questions Vector of questions
   */
  DnsRequestPacket(const DnsHeader &p_Header, const std::vector<DnsQuestion> &p_Questions);
  /// @}

  /// @name Field Getters
  /// @{

  /**
   * @brief Get the DNS header
   * @return Reference to the DNS header
   */
  const DnsHeader &Header() const noexcept;

  /**
   * @brief Get the questions vector
   * @return Reference to the questions vector
   */
  const std::vector<DnsQuestion> &Questions() const noexcept;

  /**
   * @brief Get EDNS0 data if OPT was present in the request
   * @return Optional containing parsed EDNS0 data, or std::nullopt
   */
  const std::optional<EdnsData> &Edns() const noexcept;

  /**
   * @brief Get the EDNS0 parsing status
   * @return EdnsParseStatus indicating parse result
   */
  EdnsParseStatus EdnsStatus() const noexcept;

  /**
   * @brief Check if request included a valid EDNS0 OPT record
   * @return true if EDNS0 was present and parsed (may still be bad version)
   */
  [[nodiscard]] bool HasEdns() const noexcept;
  /// @}

  /// @name Field Setters
  /// @{

  /**
   * @brief Set the DNS header
   * @param p_Header New header
   */
  void SetHeader(const DnsHeader &p_Header);

  /**
   * @brief Add a question to the packet
   * @param p_Question Question to add
   */
  void AddQuestion(const DnsQuestion &p_Question);

  /**
   * @brief Clear all questions
   */
  void ClearQuestions();

  /**
   * @brief Set EDNS0 data and status
   * @param p_Edns EDNS0 metadata
   * @param p_Status EDNS0 parse status
   */
  void SetEdns(const EdnsData &p_Edns, EdnsParseStatus p_Status = EdnsParseStatus::Ok);

  /**
   * @brief Set EDNS0 status without data (for error cases)
   * @param p_Status EDNS0 parse status
   */
  void SetEdnsStatus(EdnsParseStatus p_Status);
  /// @}

  /// @name Static Factory Methods
  /// @{

  /**
   * @brief Create a simple A record query
   * @param p_Id Query ID
   * @param p_DomainName Domain name to query
   * @param p_RecursionDesired Enable recursion
   * @return DnsRequestPacket for A record query
   */
  [[nodiscard]] static DnsRequestPacket MakeAQuery(uint16_t p_Id, const std::string &p_DomainName, bool p_RecursionDesired = true);

  /**
   * @brief Create a simple AAAA record query
   * @param p_Id Query ID
   * @param p_DomainName Domain name to query
   * @param p_RecursionDesired Enable recursion
   * @return DnsRequestPacket for AAAA record query
   */
  [[nodiscard]] static DnsRequestPacket MakeAaaaQuery(uint16_t p_Id, const std::string &p_DomainName, bool p_RecursionDesired = true);

  /**
   * @brief Create a PTR record query (reverse DNS)
   * @param p_Id Query ID
   * @param p_IpAddress IP address to reverse lookup
   * @param p_RecursionDesired Enable recursion
   * @return DnsRequestPacket for PTR record query
   */
  [[nodiscard]] static DnsRequestPacket MakePtrQuery(uint16_t p_Id, const std::string &p_IpAddress, bool p_RecursionDesired = true);
  /// @}

  /// @name STL-like Member Functions
  /// @{

  /**
   * @brief Efficiently swap contents with another packet
   * @param p_Other Other packet to swap with
   * @note Constant time operation using member swap functions
   * @note No copying or allocation - just pointer/reference swapping
   * @note Provides strong exception safety guarantee (nothrow)
   * @see std::swap(DnsRequestPacket&, DnsRequestPacket&)
   */
  void swap(DnsRequestPacket &p_Other) noexcept;

  /**
   * @brief Check if packet has no questions
   * @return true if no questions exist
   */
  [[nodiscard]] bool empty() const noexcept;

  /**
   * @brief Get number of questions in packet
   * @return Number of questions
   */
  [[nodiscard]] size_type size() const noexcept;

  /**
   * @brief Get the maximum possible number of questions
   * @return Maximum size of the questions vector
   */
  [[nodiscard]] size_type max_size() const noexcept;

  /**
   * @brief Clear all fields and reset to defaults
   * @note Clears header and all questions, then updates header counts
   */
  void clear() noexcept;
  /// @}

  /// @name Validation
  /// @{

  /**
   * @brief Check if packet is valid
   * @return true if packet is valid
   */
  [[nodiscard]] bool Valid() const noexcept;
  /// @}

  /// @name Hash Support
  /// @{

  /**
   * @brief Calculate hash value for the packet
   * @return Hash value suitable for use in hash tables (std::unordered_map, std::unordered_set)
   * @note Hash is computed from header and all questions using consistent algorithm
   * @note Two packets that compare equal will always have the same hash
   * @see std::hash<DnsRequestPacket> specialization for STL compatibility
   */
  [[nodiscard]] size_type Hash() const noexcept;
  /// @}

  /// @name Wire Format Helpers
  /// @{

  /**
   * @brief Calculate wire format size
   * @return Size in bytes when serialized to wire format
   * @note Includes DNS header (12 bytes) plus all question sizes
   * @note Result suitable for buffer allocation before calling ToWire()
   */
  [[nodiscard]] size_type WireSize() const noexcept;

  /**
   * @brief Parse from wire format data
   * @param p_Data Pointer to wire format data
   * @param p_Size Size of data in bytes
   * @param p_OutPacket Output packet
   * @return true if successfully parsed
   */
  static bool FromWire(const char *p_Data, size_type p_Size, DnsRequestPacket &p_OutPacket);

  /**
   * @brief Serialize to wire format
   * @param p_Buffer Output buffer
   * @param p_BufferSize Buffer size in bytes
   * @return Number of bytes written, 0 on error
   */
  size_type ToWire(void *p_Buffer, size_type p_BufferSize) const noexcept;
  /// @}

  /// @name Comparison Operators
  /// @{

  /**
   * @brief Test equality with another DnsRequestPacket
   * @param p_Other The DnsRequestPacket to compare with
   * @return true if all fields are equal
   */
  [[nodiscard]] bool operator==(const DnsRequestPacket &p_Other) const noexcept;

  /**
   * @brief Test inequality with another DnsRequestPacket
   * @param p_Other The DnsRequestPacket to compare with
   * @return true if any field differs
   */
  [[nodiscard]] bool operator!=(const DnsRequestPacket &p_Other) const noexcept;

  /**
   * @brief Test less-than relationship for ordering
   * @param p_Other The DnsRequestPacket to compare with
   * @return true if this packet is lexicographically less than p_Other
   * @note First compares headers, then questions in order
   */
  [[nodiscard]] bool operator<(const DnsRequestPacket &p_Other) const noexcept;
  /// @}

  /**
   * @brief Stream output operator for debugging and logging
   * @param p_OutputStream Output stream to write to
   * @param p_Packet DNS request packet to output
   * @return Reference to the output stream
   */
  friend std::ostream &operator<<(std::ostream &p_OutputStream, const DnsRequestPacket &p_Packet);

private:
  /// @name Private Member Variables
  /// @{
  DnsHeader m_Header_{};                                ///< DNS header containing packet metadata
  std::vector<DnsQuestion> m_Questions_{};              ///< Vector of question records
  std::optional<EdnsData> m_Edns_{};                    ///< Parsed EDNS0 data (if OPT present)
  EdnsParseStatus m_EdnsStatus_{EdnsParseStatus::None}; ///< EDNS0 parse status
  /// @}

  /**
   * @brief Update header record counts to match current vectors
   * @note Synchronizes qdcount in header with m_Questions_ size
   * @note Called automatically by modification methods to maintain consistency
   */
  void UpdateHeaderCounts() noexcept;
};

/**
 * @brief Non-member swap function for DnsRequestPacket objects
 * @param p_LeftSide Left-hand side DnsRequestPacket to swap
 * @param p_RightSide Right-hand side DnsRequestPacket to swap
 * @note This function enables argument-dependent lookup (ADL) for swap operations
 * @note Provides STL-compatible swap interface for use with algorithms
 * @see std::swap for general swap documentation
 */
inline void swap(DnsRequestPacket &p_LeftSide, DnsRequestPacket &p_RightSide) noexcept {
  p_LeftSide.swap(p_RightSide);
}

/**
 * @brief DNS Response Packet class for building and parsing DNS responses
 *
 * This class represents a complete DNS response packet containing a header,
 * questions, answers, authority records, and additional records. It provides
 * methods for constructing responses, parsing from wire format, and serializing
 * to wire format.
 *
 * @note Follows RFC 1035 DNS message format
 */
class DnsResponsePacket {
public:
  /// @name STL Container Type Aliases
  /// @{
  using size_type = std::size_t;          ///< Type used for sizes and counts
  using difference_type = std::ptrdiff_t; ///< Type used for pointer arithmetic
  /// @}

  /// @name Constructors and Destructor
  /// @{

  /**
   * @brief Default constructor - creates empty response packet
   */
  DnsResponsePacket() = default;

  /**
   * @brief Construct from wire format data
   * @param p_Data Pointer to DNS packet data
   * @param p_Size Size of packet data in bytes
   * @throws std::invalid_argument if data is invalid or insufficient
   */
  DnsResponsePacket(const char *p_Data, size_type p_Size);

  /**
   * @brief Construct from string containing wire format data
   * @param p_Data String containing DNS packet data
   * @throws std::invalid_argument if data is invalid or insufficient
   */
  explicit DnsResponsePacket(const std::string &p_Data);

  /**
   * @brief Construct from std::vector<char> containing wire format data
   * @param p_Data Vector containing DNS packet data
   * @throws std::invalid_argument if data is invalid or insufficient
   */
  explicit DnsResponsePacket(const std::vector<char> &p_Data);

  /**
   * @brief Construct from std::vector<unsigned char> containing wire format data
   * @param p_Data Vector containing DNS packet data
   * @throws std::invalid_argument if data is invalid or insufficient
   */
  explicit DnsResponsePacket(const std::vector<unsigned char> &p_Data);

  /**
   * @brief Construct from C array containing wire format data
   * @tparam N Size of the array
   * @param p_Data C array containing DNS packet data
   * @throws std::invalid_argument if data is invalid or insufficient
   */
  template <size_type N>
  explicit DnsResponsePacket(const char (&p_Data)[N]) {
    if (!FromWire(p_Data, N, *this)) {
      throw std::invalid_argument("DnsResponsePacket: invalid packet data");
    }
  }

  /**
   * @brief Construct from std::array<char> containing wire format data
   * @tparam N Size of the array
   * @param p_Data Array containing DNS packet data
   * @throws std::invalid_argument if data is invalid or insufficient
   */
  template <size_type N>
  explicit DnsResponsePacket(const std::array<char, N> &p_Data) {
    if (!FromWire(p_Data.data(), N, *this)) {
      throw std::invalid_argument("DnsResponsePacket: invalid packet data");
    }
  }

  /**
   * @brief Construct from std::array<unsigned char> containing wire format data
   * @tparam N Size of the array
   * @param p_Data Array containing DNS packet data
   * @throws std::invalid_argument if data is invalid or insufficient
   */
  template <size_type N>
  explicit DnsResponsePacket(const std::array<unsigned char, N> &p_Data) {
    if (!FromWire(p_Data.data(), N, *this)) {
      throw std::invalid_argument("DnsResponsePacket: invalid packet data");
    }
  }

  /**
   * @brief Construct response packet with all sections
   * @param p_Header DNS header
   * @param p_Questions Vector of questions
   * @param p_Answers Vector of answers
   * @param p_Authority Vector of authority records
   * @param p_Additional Vector of additional records
   */
  DnsResponsePacket(const DnsHeader &p_Header, const std::vector<DnsQuestion> &p_Questions, const std::vector<DnsAnswer> &p_Answers = {}, const std::vector<DnsAnswer> &p_Authority = {}, const std::vector<DnsAnswer> &p_Additional = {});
  /// @}

  /// @name Field Getters
  /// @{

  /**
   * @brief Get the DNS header
   * @return Reference to the DNS header
   */
  const DnsHeader &Header() const noexcept;

  /**
   * @brief Get the questions vector
   * @return Reference to the questions vector
   */
  const std::vector<DnsQuestion> &Questions() const noexcept;

  /**
   * @brief Get the answers vector
   * @return Reference to the answers vector
   */
  const std::vector<DnsAnswer> &Answers() const noexcept;

  /**
   * @brief Get the authority records vector
   * @return Reference to the authority records vector
   */
  const std::vector<DnsAnswer> &Authority() const noexcept;

  /**
   * @brief Get the additional records vector
   * @return Reference to the additional records vector
   */
  const std::vector<DnsAnswer> &Additional() const noexcept;
  /// @}

  /// @name Field Setters
  /// @{

  /**
   * @brief Set the DNS header
   * @param p_Header New header
   */
  void SetHeader(const DnsHeader &p_Header);

  /**
   * @brief Add a question to the packet
   * @param p_Question Question to add
   */
  void AddQuestion(const DnsQuestion &p_Question);

  /**
   * @brief Add an answer to the packet
   * @param p_Answer Answer to add
   */
  void AddAnswer(const DnsAnswer &p_Answer);

  /**
   * @brief Add an authority record to the packet
   * @param p_Authority Authority record to add
   */
  void AddAuthority(const DnsAnswer &p_Authority);

  /**
   * @brief Add an additional record to the packet
   * @param p_Additional Additional record to add
   */
  void AddAdditional(const DnsAnswer &p_Additional);

  /**
   * @brief Clear all questions
   */
  void ClearQuestions();

  /**
   * @brief Clear all answers
   */
  void ClearAnswers();

  /**
   * @brief Clear all authority records
   */
  void ClearAuthority();

  /**
   * @brief Clear all additional records
   */
  void ClearAdditional();
  /// @}

  /// @name Static Factory Methods
  /// @{

  /**
   * @brief Create response from request packet
   * @param p_Request Original request packet
   * @param p_Rcode Response code (0 = success)
   * @param p_Authoritative Is authoritative response
   * @param p_RecursionAvailable Recursion available
   * @return DnsResponsePacket with matching header
   */
  [[nodiscard]] static DnsResponsePacket MakeResponse(const DnsRequestPacket &p_Request, uint8_t p_Rcode = 0, bool p_Authoritative = false, bool p_RecursionAvailable = true);

  /**
   * @brief Create error response
   * @param p_Request Original request packet
   * @param p_ErrorCode Error code (1-5)
   * @return DnsResponsePacket with error
   */
  [[nodiscard]] static DnsResponsePacket MakeErrorResponse(const DnsRequestPacket &p_Request, uint8_t p_ErrorCode);
  /// @}

  /// @name STL-like Member Functions
  /// @{

  /**
   * @brief Efficiently swap contents with another packet
   * @param p_Other Other packet to swap with
   * @note Constant time operation using member swap functions
   * @note No copying or allocation - just pointer/reference swapping
   * @note Swaps all sections: header, questions, answers, authority, additional
   * @note Provides strong exception safety guarantee (nothrow)
   * @see std::swap(DnsResponsePacket&, DnsResponsePacket&)
   */
  void swap(DnsResponsePacket &p_Other) noexcept;

  /**
   * @brief Check if packet has no records
   * @return true if no questions, answers, authority, or additional records exist
   */
  [[nodiscard]] bool empty() const noexcept;

  /**
   * @brief Get total number of records in packet
   * @return Total number of questions, answers, authority, and additional records
   */
  [[nodiscard]] size_type size() const noexcept;

  /**
   * @brief Get the maximum possible number of records
   * @return Maximum size of the questions vector
   */
  [[nodiscard]] size_type max_size() const noexcept;

  /**
   * @brief Clear all fields and reset to defaults
   * @note Clears header and all sections (questions, answers, authority, additional), then updates header counts
   */
  void clear() noexcept;
  /// @}

  /// @name Validation
  /// @{

  /**
   * @brief Check if packet is valid
   * @return true if packet is valid
   */
  [[nodiscard]] bool Valid() const noexcept;
  /// @}

  /// @name Hash Support
  /// @{

  /**
   * @brief Calculate hash value for the packet
   * @return Hash value suitable for use in hash tables (std::unordered_map, std::unordered_set)
   * @note Hash is computed from header and all sections (questions, answers, authority, additional)
   * @note Two packets that compare equal will always have the same hash
   * @note Uses consistent algorithm combining all record hashes
   * @see std::hash<DnsResponsePacket> specialization for STL compatibility
   */
  [[nodiscard]] size_type Hash() const noexcept;
  /// @}

  /// @name Wire Format Helpers
  /// @{

  /**
   * @brief Calculate wire format size
   * @return Size in bytes when serialized to wire format
   * @note Includes DNS header (12 bytes) plus all question and answer record sizes
   * @note Result suitable for buffer allocation before calling ToWire()
   */
  [[nodiscard]] size_type WireSize() const noexcept;

  /**
   * @brief Parse from wire format data
   * @param p_Data Pointer to wire format data
   * @param p_Size Size of data in bytes
   * @param p_OutPacket Output packet
   * @return true if successfully parsed
   */
  static bool FromWire(const void *p_Data, size_type p_Size, DnsResponsePacket &p_OutPacket);

  /**
   * @brief Serialize to wire format
   * @param p_Buffer Output buffer
   * @param p_BufferSize Buffer size in bytes
   * @return Number of bytes written, 0 on error
   */
  size_type ToWire(void *p_Buffer, size_type p_BufferSize) const noexcept;
  /// @}

  /// @name Comparison Operators
  /// @{

  /**
   * @brief Test equality with another DnsResponsePacket
   * @param p_Other The DnsResponsePacket to compare with
   * @return true if all fields are equal
   */
  [[nodiscard]] bool operator==(const DnsResponsePacket &p_Other) const noexcept;

  /**
   * @brief Test inequality with another DnsResponsePacket
   * @param p_Other The DnsResponsePacket to compare with
   * @return true if any field differs
   */
  [[nodiscard]] bool operator!=(const DnsResponsePacket &p_Other) const noexcept;

  /**
   * @brief Test less-than relationship for ordering
   * @param p_Other The DnsResponsePacket to compare with
   * @return true if this packet is lexicographically less than p_Other
   * @note Compares headers first, then sections in order: questions, answers, authority, additional
   */
  [[nodiscard]] bool operator<(const DnsResponsePacket &p_Other) const noexcept;
  /// @}

  /**
   * @brief Stream output operator for debugging and logging
   * @param p_OutputStream Output stream to write to
   * @param p_Packet DNS response packet to output
   * @return Reference to the output stream
   */
  friend std::ostream &operator<<(std::ostream &p_OutputStream, const DnsResponsePacket &p_Packet);

private:
  /// @name Private Member Variables
  /// @{
  DnsHeader m_Header_{};                   ///< DNS header containing packet metadata and record counts
  std::vector<DnsQuestion> m_Questions_{}; ///< Vector of question records (query section)
  std::vector<DnsAnswer> m_Answers_{};     ///< Vector of answer records (answer section)
  std::vector<DnsAnswer> m_Authority_{};   ///< Vector of authority records (authority section)
  std::vector<DnsAnswer> m_Additional_{};  ///< Vector of additional records (additional section)
  /// @}

  /**
   * @brief Update header record counts to match current vectors
   * @note Synchronizes qdcount, ancount, nscount, arcount in header with vector sizes
   * @note Called automatically by modification methods to maintain consistency
   * @note Ensures header accurately reflects actual record counts for wire format
   */
  void UpdateHeaderCounts() noexcept;
};

/**
 * @brief Non-member swap function for DnsResponsePacket objects
 * @param p_LeftSide Left-hand side DnsResponsePacket to swap
 * @param p_RightSide Right-hand side DnsResponsePacket to swap
 * @note This function enables argument-dependent lookup (ADL) for swap operations
 * @note Provides STL-compatible swap interface for use with algorithms
 * @see std::swap for general swap documentation
 */
inline void swap(DnsResponsePacket &p_LeftSide, DnsResponsePacket &p_RightSide) noexcept {
  p_LeftSide.swap(p_RightSide);
}

/**
 * @brief STL hash specializations for DNS packet classes
 * @note Enables use of DnsRequestPacket and DnsResponsePacket as keys in
 *       std::unordered_map and std::unordered_set
 */
namespace std {
template <>
struct hash<DnsRequestPacket> {
    /**
   * @brief Calculate hash value for a DnsRequestPacket object
   * @param p_Packet The DnsRequestPacket object to hash
   * @return Hash value suitable for use in hash containers
   * @note Uses the DnsRequestPacket::Hash() method for consistent hashing
   * @note Complexity: O(n) where n is the number of labels
   */
  std::size_t operator()(const DnsRequestPacket &p_Packet) const noexcept {
    return p_Packet.Hash();
  }
};
template <>
struct hash<DnsResponsePacket> {
    /**
   * @brief Calculate hash value for a DnsResponsePacket object
   * @param p_Packet The DnsResponsePacket object to hash
   * @return Hash value suitable for use in hash containers
   * @note Uses the DnsResponsePacket::Hash() method for consistent hashing
   * @note Complexity: O(n) where n is the number of labels
   */
  std::size_t operator()(const DnsResponsePacket &p_Packet) const noexcept {
    return p_Packet.Hash();
  }
};
} // namespace std

#endif // DNS_PACKET_H_
