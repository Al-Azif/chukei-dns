/** @file dns_packet_header.h
 *  @brief DnsHeader class representing the 12-byte DNS packet header (RFC 1035 Section 4.1.1).
 */

#ifndef DNS_PACKET_HEADER_H_
#define DNS_PACKET_HEADER_H_

#include <array>   // std::array
#include <cstddef> // std::size_t, std::ptrdiff_t
#include <cstdint> // uint8_t, uint16_t, uint32_t
#include <ostream> // std::ostream
#include <string>  // std::string
#include <vector>  // std::vector

#include "constants.h"

/** Header section format

The header contains the following fields:

                                1  1  1  1  1  1
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

where:

ID       - A 16 bit identifier assigned by the program that generates any kind of query. This identifier is copied the corresponding reply and can be used by the requester to match up replies to outstanding queries.
QR       - A one bit field that specifies whether this message is a query (0), or a response (1).
OPCODE   - A four bit field that specifies kind of query in this message. This value is set by the originator of a query and copied into the response. The values are:
            0        a standard query (QUERY) (most common)
            1        an inverse query (IQUERY) (obsolete)
            2        a server status request (STATUS)
            3-15     reserved for future use
AA        - Authoritative Answer - this bit is valid in responses, and specifies that the responding name
            Note that the contents of the answer section may have multiple owner names because of aliases. The AA bit corresponds to the name which matches the query name, or the first owner name in the answer section.
TC        - TrunCation - specifies that this message was truncated due to length greater than that permitted on the transmission channel.
RD        - Recursion Desired - this bit may be set in a query and is copied into the response. If RD is set, it directs the name server to pursue the query recursively. Recursive query support is optional.
RA        - Recursion Available - this be is set or cleared in a response, and denotes whether recursive query support is available in the name server.
Z         - Reserved for future use. Must be zero in all queries and responses.
AD        - Authentic Data - this bit is set in responses when data has been cryptographically verified (DNSSEC)
CD        - Checking Disabled - this bit may be set in queries to accept non-verified data (disables DNSSEC validation)
RCODE     - Response code - this 4 bit field is set as part of responses. The values have the following interpretation:
            0        NOERROR - No error condition
            1        FORMERR - Format error - The name server was unable to interpret the query.
            2        SERVFAIL - Server failure - The name server was unable to process this query due to a problem with the name server.
            3        NXDOMAIN - Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.
            4        NOTIMP - Not Implemented - The name server does not support the requested kind of query.
            5        REFUSED - Refused - The name server refuses to perform the specified operation for policy reasons. For example, a name server may not wish to provide the information to the particular requester, or a name server may not wish to perform a particular operation (e.g., zone transfer) for particular data.
            6-15     Reserved for future use.
QDCOUNT   - an unsigned 16 bit integer specifying the number of entries in the question section.
ANCOUNT   - an unsigned 16 bit integer specifying the number of resource records in the answer section.
NSCOUNT   - an unsigned 16 bit integer specifying the number of name server resource records in the authority records section.
ARCOUNT   - an unsigned 16 bit integer specifying the number of resource records in the additional records section.

Common Values for Standard Queries:
- QR=0, OPCODE=0, RD=1, Z=0, RCODE=0, QDCOUNT=1, others=0
*/

/**
 * @brief DNS Header class implementing RFC 1035 DNS packet header format
 *
 * This class represents a 12-byte DNS header with support for both raw network
 * byte order and host byte order operations. It provides an STL-like interface
 * with comprehensive flag manipulation capabilities.
 *
 * The DNS header contains identification, flags, and counts for each section
 * of a DNS message (questions, answers, authority, additional).
 *
 * @note All network data is stored internally in network byte order
 * @see RFC 1035 Section 4.1.1 for DNS header format specification
 */
class DnsHeader {
public:
  /// @name STL Container Type Aliases
  /// @{
  using value_type = uint16_t;              ///< Type of values stored in header fields
  using size_type = std::size_t;            ///< Type used for sizes and counts
  using difference_type = std::ptrdiff_t;   ///< Type used for pointer arithmetic
  using pointer = uint16_t *;               ///< Pointer to header field
  using const_pointer = const uint16_t *;   ///< Const pointer to header field
  using reference = uint16_t &;             ///< Reference to header field
  using const_reference = const uint16_t &; ///< Const reference to header field
  /// @}

  /// @name Constructors and Destructor
  /// @{

  /**
   * @brief Default constructor - initializes all fields to zero
   */
  DnsHeader() = default;

  /**
   * @brief Copy constructor
   * @param other The DnsHeader to copy from
   */
  DnsHeader(const DnsHeader &) = default;

  /**
   * @brief Move constructor
   * @param other The DnsHeader to move from
   */
  DnsHeader(DnsHeader &&) = default;

  /**
   * @brief Copy assignment operator
   * @param other The DnsHeader to copy from
   * @return Reference to this object
   */
  DnsHeader &operator=(const DnsHeader &) = default;

  /**
   * @brief Move assignment operator
   * @param other The DnsHeader to move from
   * @return Reference to this object
   */
  DnsHeader &operator=(DnsHeader &&) = default;

  /**
   * @brief Destructor
   */
  ~DnsHeader() = default;

  /**
   * @brief Construct from raw data pointer (assumes exactly 12 bytes)
   * @param p_Data Pointer to 12 bytes of DNS header data in network byte order
   * @throws std::invalid_argument if p_Data is nullptr
   * @note No size validation - caller must ensure 12 bytes are available
   * @warning Undefined behavior if p_Data points to less than 12 bytes
   */
  explicit DnsHeader(const char *p_Data);

  /**
   * @brief Construct from raw data pointer with size validation
   * @param p_Data Pointer to DNS header data in network byte order
   * @param p_Size Size of available data in bytes
   * @throws std::invalid_argument if p_Data is nullptr or p_Size < 12
   * @note Validates that at least 12 bytes are available
   */
  DnsHeader(const char *p_Data, size_type p_Size);

  /**
   * @brief Construct from std::string containing raw header data
   * @param p_Data String containing DNS header data in network byte order
   * @throws std::invalid_argument if string size < 12 bytes
   * @note Uses the first 12 bytes of the string
   */
  explicit DnsHeader(const std::string &p_Data);

  /**
   * @brief Construct from std::vector<char> containing raw header data
   * @param p_Data Vector containing DNS header data in network byte order
   * @throws std::invalid_argument if vector size < 12 bytes
   * @note Uses the first 12 bytes of the vector
   */
  explicit DnsHeader(const std::vector<char> &p_Data);

  /**
   * @brief Construct from std::vector<unsigned char> containing raw header data
   * @param p_Data Vector containing DNS header data in network byte order
   * @throws std::invalid_argument if vector size < 12 bytes
   * @note Uses the first 12 bytes of the vector
   */
  explicit DnsHeader(const std::vector<unsigned char> &p_Data);

  /**
   * @brief Construct from C-style array with compile-time size checking
   * @tparam N Array size (must be >= 12)
   * @param p_Data Array containing DNS header data in network byte order
   * @note Compile-time size validation ensures safety
   */
  template <size_type N>
  explicit DnsHeader(const char (&p_Data)[N]) {
    static_assert(N >= HeaderSize, "Array must contain at least 12 bytes");
    if (!FromWire(p_Data, N, *this)) {
      throw std::invalid_argument("DnsHeader: invalid data format");
    }
  }

  /**
   * @brief Construct from std::array containing raw header data
   * @tparam N Array size (must be >= 12)
   * @param p_Data Array containing DNS header data in network byte order
   * @note Compile-time size validation ensures safety
   */
  template <size_type N>
  explicit DnsHeader(const std::array<char, N> &p_Data) {
    static_assert(N >= HeaderSize, "Array must contain at least 12 bytes");
    if (!FromWire(p_Data.data(), N, *this)) {
      throw std::invalid_argument("DnsHeader: invalid data format");
    }
  }

  /**
   * @brief Construct from std::array<unsigned char> containing raw header data
   * @tparam N Array size (must be >= 12)
   * @param p_Data Array containing DNS header data in network byte order
   * @note Compile-time size validation ensures safety
   */
  template <size_type N>
  explicit DnsHeader(const std::array<unsigned char, N> &p_Data) {
    static_assert(N >= HeaderSize, "Array must contain at least 12 bytes");
    if (!FromWire(p_Data.data(), N, *this)) {
      throw std::invalid_argument("DnsHeader: invalid data format");
    }
  }

  /**
   * @brief Construct header with specific field values
   * @param p_Id Message identifier
   * @param p_Flags Combined flags field
   * @param p_Qdcount Question count
   * @param p_Ancount Answer count
   * @param p_Nscount Authority count
   * @param p_Arcount Additional count
   * @note All values are assumed to be in host byte order and will be converted
   */
  explicit DnsHeader(uint16_t p_Id, uint16_t p_Flags, uint16_t p_Qdcount = 0, uint16_t p_Ancount = 0, uint16_t p_Nscount = 0, uint16_t p_Arcount = 0);

  /**
   * @brief Construct query header with convenient parameters
   * @param p_Id Message identifier
   * @param p_Opcode Operation code (default: 0 = standard query)
   * @param p_RecursionDesired Whether to request recursion (default: true)
   * @param p_QuestionCount Number of questions (default: 1)
   * @note Creates a standard query header with commonly used flags
   */
  [[nodiscard]] static DnsHeader MakeQueryHeader(uint16_t p_Id, uint8_t p_Opcode = 0, bool p_RecursionDesired = true, uint16_t p_QuestionCount = 1);

  /**
   * @brief Construct response header based on a query
   * @param p_QueryHeader The original query header
   * @param p_Rcode Response code (default: 0 = no error)
   * @param p_Authoritative Whether this is an authoritative response (default: false)
   * @param p_RecursionAvailable Whether recursion is available (default: true)
   * @note Copies ID and opcode from query, sets appropriate response flags
   */
  [[nodiscard]] static DnsHeader MakeResponseHeader(const DnsHeader &p_QueryHeader, uint8_t p_Rcode = 0, bool p_Authoritative = false, bool p_RecursionAvailable = true);
  /// @}

  /// @name Field Getters
  /// @{

  /**
   * @brief Get the message identifier
   * @param p_Raw If true, returns raw network byte order; if false, converts to host order
   * @return 16-bit message identifier used to match queries with responses
   * @note Should be a random value for each new query to prevent spoofing
   */
  [[nodiscard]] uint16_t Id(bool p_Raw = false) const noexcept;

  /**
   * @brief Get the flags field containing all control bits
   * @param p_Raw If true, returns raw network byte order; if false, converts to host order
   * @return 16-bit flags field containing QR, OPCODE, AA, TC, RD, RA, Z, AD, CD, RCODE
   */
  [[nodiscard]] uint16_t Flags(bool p_Raw = false) const noexcept;

  /**
   * @brief Get the number of questions in the question section
   * @param p_Raw If true, returns raw network byte order; if false, converts to host order
   * @return Number of entries in the question section
   */
  [[nodiscard]] uint16_t Qdcount(bool p_Raw = false) const noexcept;

  /**
   * @brief Get the number of answers in the answer section
   * @param p_Raw If true, returns raw network byte order; if false, converts to host order
   * @return Number of resource records in the answer section
   */
  [[nodiscard]] uint16_t Ancount(bool p_Raw = false) const noexcept;

  /**
   * @brief Get the number of name servers in the authority section
   * @param p_Raw If true, returns raw network byte order; if false, converts to host order
   * @return Number of name server records in the authority section
   */
  [[nodiscard]] uint16_t Nscount(bool p_Raw = false) const noexcept;

  /**
   * @brief Get the number of records in the additional section
   * @param p_Raw If true, returns raw network byte order; if false, converts to host order
   * @return Number of records in the additional records section
   */
  [[nodiscard]] uint16_t Arcount(bool p_Raw = false) const noexcept;
  /// @}

  /// @name Flag Bit Getters
  /// @{

  /**
   * @brief Get the Query/Response flag
   * @param p_Raw If true, uses raw network byte order flags; if false, converts to host order
   * @return true if this is a response (1), false if this is a query (0)
   */
  [[nodiscard]] bool Qr(bool p_Raw = false) const noexcept;

  /**
   * @brief Get the operation code
   * @param p_Raw If true, uses raw network byte order flags; if false, converts to host order
   * @return 4-bit operation code (0=standard query, 1=inverse query, 2=status request)
   */
  [[nodiscard]] uint8_t Opcode(bool p_Raw = false) const noexcept;

  /**
   * @brief Get the Authoritative Answer flag
   * @param p_Raw If true, uses raw network byte order flags; if false, converts to host order
   * @return true if the responding server is authoritative for the queried domain
   */
  [[nodiscard]] bool Aa(bool p_Raw = false) const noexcept;

  /**
   * @brief Get the Truncation flag
   * @param p_Raw If true, uses raw network byte order flags; if false, converts to host order
   * @return true if the message was truncated due to size limitations
   */
  [[nodiscard]] bool Tc(bool p_Raw = false) const noexcept;

  /**
   * @brief Get the Recursion Desired flag
   * @param p_Raw If true, uses raw network byte order flags; if false, converts to host order
   * @return true if recursive resolution is requested
   */
  [[nodiscard]] bool Rd(bool p_Raw = false) const noexcept;

  /**
   * @brief Get the Recursion Available flag
   * @param p_Raw If true, uses raw network byte order flags; if false, converts to host order
   * @return true if the server supports recursive queries
   */
  [[nodiscard]] bool Ra(bool p_Raw = false) const noexcept;

  /**
   * @brief Get the reserved Z flag
   * @param p_Raw If true, uses raw network byte order flags; if false, converts to host order
   * @return Reserved bit that must be zero in all queries and responses
   * @note This bit is reserved for future use and must always be 0
   */
  [[nodiscard]] bool Z(bool p_Raw = false) const noexcept;

  /**
   * @brief Get the Authentic Data flag
   * @param p_Raw If true, uses raw network byte order flags; if false, converts to host order
   * @return true if the data has been cryptographically verified (DNSSEC)
   */
  [[nodiscard]] bool Ad(bool p_Raw = false) const noexcept;

  /**
   * @brief Get the Checking Disabled flag
   * @param p_Raw If true, uses raw network byte order flags; if false, converts to host order
   * @return true if DNSSEC validation should be disabled
   */
  [[nodiscard]] bool Cd(bool p_Raw = false) const noexcept;

  /**
   * @brief Get the response code
   * @param p_Raw If true, uses raw network byte order flags; if false, converts to host order
   * @return 4-bit response code (0=NOERROR, 1=FORMERR, 2=SERVFAIL, 3=NXDOMAIN, etc.)
   */
  [[nodiscard]] uint8_t Rcode(bool p_Raw = false) const noexcept;
  /// @}

  /// @name Field Setters
  /// @{

  /**
   * @brief Set the message identifier
   * @param p_Value The identifier value to set
   * @param p_Raw If true, treats p_Value as network byte order; if false, converts from host order
   */
  void SetId(uint16_t p_Value, bool p_Raw = false) noexcept;

  /**
   * @brief Set the flags field
   * @param p_Value The flags value to set
   * @param p_Raw If true, treats p_Value as network byte order; if false, converts from host order
   */
  void SetFlags(uint16_t p_Value, bool p_Raw = false) noexcept;

  /**
   * @brief Set the question count
   * @param p_Value The number of questions
   * @param p_Raw If true, treats p_Value as network byte order; if false, converts from host order
   */
  void SetQdcount(uint16_t p_Value, bool p_Raw = false) noexcept;

  /**
   * @brief Set the answer count
   * @param p_Value The number of answers
   * @param p_Raw If true, treats p_Value as network byte order; if false, converts from host order
   */
  void SetAncount(uint16_t p_Value, bool p_Raw = false) noexcept;

  /**
   * @brief Set the name server count
   * @param p_Value The number of name servers
   * @param p_Raw If true, treats p_Value as network byte order; if false, converts from host order
   */
  void SetNscount(uint16_t p_Value, bool p_Raw = false) noexcept;

  /**
   * @brief Set the additional record count
   * @param p_Value The number of additional records
   * @param p_Raw If true, treats p_Value as network byte order; if false, converts from host order
   */
  void SetArcount(uint16_t p_Value, bool p_Raw = false) noexcept;
  /// @}

  /// @name Flag Bit Setters
  /// @{

  /**
   * @brief Set the Query/Response flag
   * @param p_Value true for response, false for query
   * @param p_Raw If true, operates on raw network byte order flags; if false, converts to/from host order
   */
  void SetQr(bool p_Value, bool p_Raw = false) noexcept;

  /**
   * @brief Set the operation code
   * @param p_Value 4-bit operation code (0-15)
   * @param p_Raw If true, operates on raw network byte order flags; if false, converts to/from host order
   * @note Values > 15 will be automatically masked to fit in 4 bits
   */
  void SetOpcode(uint8_t p_Value, bool p_Raw = false) noexcept;

  /**
   * @brief Set the Authoritative Answer flag
   * @param p_Value true if server is authoritative, false otherwise
   * @param p_Raw If true, operates on raw network byte order flags; if false, converts to/from host order
   */
  void SetAa(bool p_Value, bool p_Raw = false) noexcept;

  /**
   * @brief Set the Truncation flag
   * @param p_Value true if message was truncated, false otherwise
   * @param p_Raw If true, operates on raw network byte order flags; if false, converts to/from host order
   */
  void SetTc(bool p_Value, bool p_Raw = false) noexcept;

  /**
   * @brief Set the Recursion Desired flag
   * @param p_Value true to request recursive resolution, false otherwise
   * @param p_Raw If true, operates on raw network byte order flags; if false, converts to/from host order
   */
  void SetRd(bool p_Value, bool p_Raw = false) noexcept;

  /**
   * @brief Set the Recursion Available flag
   * @param p_Value true if server supports recursion, false otherwise
   * @param p_Raw If true, operates on raw network byte order flags; if false, converts to/from host order
   */
  void SetRa(bool p_Value, bool p_Raw = false) noexcept;

  /**
   * @brief Set the reserved Z flag
   * @param p_Value Must be false (reserved bit must be 0)
   * @param p_Raw If true, operates on raw network byte order flags; if false, converts to/from host order
   * @warning This bit must always be set to false per RFC 1035
   */
  void SetZ(bool p_Value, bool p_Raw = false) noexcept;

  /**
   * @brief Set the Authentic Data flag
   * @param p_Value true if data is cryptographically verified, false otherwise
   * @param p_Raw If true, operates on raw network byte order flags; if false, converts to/from host order
   */
  void SetAd(bool p_Value, bool p_Raw = false) noexcept;

  /**
   * @brief Set the Checking Disabled flag
   * @param p_Value true to disable DNSSEC validation, false otherwise
   * @param p_Raw If true, operates on raw network byte order flags; if false, converts to/from host order
   */
  void SetCd(bool p_Value, bool p_Raw = false) noexcept;

  /**
   * @brief Set the response code
   * @param p_Value 4-bit response code (0-15)
   * @param p_Raw If true, operates on raw network byte order flags; if false, converts to/from host order
   * @note Values > 15 will be automatically masked to fit in 4 bits
   */
  void SetRcode(uint8_t p_Value, bool p_Raw = false) noexcept;
  /// @}

  /// @name STL-like Member Functions
  /// @{

  /**
   * @brief Swap contents with another DnsHeader
   * @param p_Other The DnsHeader to swap with
   */
  void swap(DnsHeader &p_Other) noexcept;

  /**
   * @brief Check if header is "empty" (has no meaningful data)
   * @return true if flags and all counts are zero (ID can be non-zero)
   * @note An "empty" header can still have a non-zero ID
   */
  [[nodiscard]] bool empty() const noexcept;

  /**
   * @brief Get the size of the DNS header in bytes
   * @return Always returns 12 (DNS headers are fixed size)
   */
  [[nodiscard]] static size_type size() noexcept;

  /**
   * @brief Get the maximum size of the DNS header in bytes
   * @return Always returns 12 (DNS headers are fixed size)
   */
  [[nodiscard]] static size_type max_size() noexcept;
  /// @}

  /// @name Convenience Functions
  /// @{

  /**
   * @brief Update all count fields based on packet contents
   * @param p_QuestionCount Number of questions in packet
   * @param p_AnswerCount Number of answers in packet
   * @param p_AuthorityCount Number of authority records in packet
   * @param p_AdditionalCount Number of additional records in packet
   * @note Convenience method to update all counts at once
   */
  void UpdateCounts(uint16_t p_QuestionCount, uint16_t p_AnswerCount = 0, uint16_t p_AuthorityCount = 0, uint16_t p_AdditionalCount = 0) noexcept;

  /**
   * @brief Check if header counts match actual packet contents
   * @param p_ActualQuestions Actual number of questions in packet
   * @param p_ActualAnswers Actual number of answers in packet
   * @param p_ActualAuthority Actual number of authority records in packet
   * @param p_ActualAdditional Actual number of additional records in packet
   * @return true if all counts match
   */
  [[nodiscard]] bool CountsMatch(uint16_t p_ActualQuestions, uint16_t p_ActualAnswers = 0, uint16_t p_ActualAuthority = 0, uint16_t p_ActualAdditional = 0) const noexcept;

  /**
   * @brief Get total number of records in all sections
   * @return Sum of all count fields
   */
  [[nodiscard]] uint32_t TotalRecords() const noexcept;

  /**
   * @brief Auto-increment a count field (useful for packet building)
   * @param p_Section Which section to increment ('q'=question, 'a'=answer, 'n'=authority, 'r'=additional)
   * @return New count value, or 0 if invalid section
   */
  uint16_t IncrementCount(char p_Section) noexcept;

  /**
   * @brief Initialize header as a DNS response based on a query
   * @param p_Query The original query header to respond to
   * @note Copies ID and OPCODE from query, sets QR=1, RA=1
   */
  void MakeResponse(const DnsHeader &p_Query) noexcept;

  /**
   * @brief Initialize as error response with specified error code
   * @param p_QueryHeader The original query header
   * @param p_ErrorCode Error code (FORMERR=1, SERVFAIL=2, NXDOMAIN=3, etc.)
   * @note Creates a response with no records and the specified error
   */
  void MakeErrorResponse(const DnsHeader &p_QueryHeader, uint8_t p_ErrorCode) noexcept;

  /**
   * @brief Clear all header fields to zero
   */
  void clear() noexcept;
  /// @}

  /// @name Status Check Functions
  /// @{

  /**
   * @brief Check if header is valid according to DNS specifications
   * @return true if Z bit is 0 (as required by RFC 1035)
   */
  [[nodiscard]] bool Valid() const noexcept;

  /**
   * @brief Check if this is a DNS query
   * @return true if QR bit is 0 (query)
   */
  [[nodiscard]] bool IsQuery() const noexcept;

  /**
   * @brief Check if this is a simple query (1 question, no answers)
   * @return true if qdcount=1 and all other counts are 0
   */
  [[nodiscard]] bool IsSimpleQuery() const noexcept;

  /**
   * @brief Check if this is a DNS response
   * @return true if QR bit is 1 (response)
   */
  [[nodiscard]] bool IsResponse() const noexcept;

  /**
   * @brief Check if response indicates an error
   * @return true if RCODE is non-zero
   */
  [[nodiscard]] bool HasError() const noexcept;

  /**
   * @brief Check if this is a standard query
   * @return true if OPCODE is 0 (standard query)
   */
  [[nodiscard]] bool IsStandardQuery() const noexcept;
  /// @}

  /// @name Hash Support
  /// @{

  /**
   * @brief Calculate hash value for use in hash containers
   * @return Hash value suitable for std::unordered_map and std::unordered_set
   */
  [[nodiscard]] size_type Hash() const noexcept;
  /// @}

  /// @name Size and Direct Data Access
  /// @{

  /// DNS header size in bytes (always 12)
  static constexpr size_type HeaderSize{Constants::Dns::DNS_HEADER_SIZE};

  /**
   * @brief Get read-only pointer to raw header data
   * @return Const pointer to the first byte of header data
   * @note Data is in network byte order
   */
  [[nodiscard]] const void *data() const noexcept;

  /**
   * @brief Get writable pointer to raw header data
   * @return Pointer to the first byte of header data
   * @note Data is in network byte order
   * @warning Direct manipulation bypasses validation
   */
  [[nodiscard]] void *data() noexcept;
  /// @}

  /// @name Wire Format Helpers
  /// @{

  /**
   * @brief Get the size required for wire format serialization
   * @return Number of bytes needed for wire format (always 12)
   */
  [[nodiscard]] static size_type WireSize() noexcept;

  /**
   * @brief Create header from raw network data with validation
   * @param p_Data Pointer to raw data
   * @param p_Size Size of available data
   * @param p_OutHeader Output header object
   * @return true if successfully parsed and valid
   */
  [[nodiscard]] static bool FromWire(const void *p_Data, size_type p_Size, DnsHeader &p_OutHeader) noexcept;

  /**
   * @brief Serialize header to buffer with size checking
   * @param p_Data Output buffer
   * @param p_Size Size of output buffer
   * @return Number of bytes written, or 0 on error
   */
  [[nodiscard]] size_type ToWire(void *p_Data, size_type p_Size) const noexcept;
  /// @}

  /// @name Comparison Operators
  /// @{

  /**
   * @brief Test equality with another DnsHeader
   * @param p_Other The DnsHeader to compare with
   * @return true if all fields are equal
   */
  [[nodiscard]] bool operator==(const DnsHeader &p_Other) const noexcept;

  /**
   * @brief Test inequality with another DnsHeader
   * @param p_Other The DnsHeader to compare with
   * @return true if any field differs
   */
  [[nodiscard]] bool operator!=(const DnsHeader &p_Other) const noexcept;

  /**
   * @brief Lexicographic less-than for strict weak ordering
   * @param p_Other The DnsHeader to compare with
   * @return true if this header is less than the other
   */
  [[nodiscard]] bool operator<(const DnsHeader &p_Other) const noexcept;
  /// @}

  /**
   * @brief Stream output operator for debugging and logging
   * @param p_OutputStream Output stream to write to
   * @param p_Header DnsHeader to output
   * @return Reference to the output stream
   */
  friend std::ostream &operator<<(std::ostream &p_OutputStream, const DnsHeader &p_Header);

private:
  /// @name Private Member Variables
  /// @{
  uint16_t m_Id_{};      ///< Message identifier (network byte order)
  uint16_t m_Flags_{};   ///< Flags field (network byte order)
  uint16_t m_Qdcount_{}; ///< Number of questions (network byte order)
  uint16_t m_Ancount_{}; ///< Number of answers (network byte order)
  uint16_t m_Nscount_{}; ///< Number of name server records (network byte order)
  uint16_t m_Arcount_{}; ///< Number of additional records (network byte order)
  /// @}

  /**
   * @brief Set or clear a single bit in the flags field
   * @param p_Bit Bit position (0-15, where 15 is MSB)
   * @param p_Value true to set bit, false to clear bit
   * @param p_Raw If true, operates on raw network byte order; if false, converts to/from host order
   * @note Automatically validates bit position (ignores invalid positions)
   */
  void SetFlagBit(uint8_t p_Bit, bool p_Value, bool p_Raw) noexcept;

  /**
   * @brief Set a multi-bit value in the flags field
   * @param p_BitPos Starting bit position (0-15, where 15 is MSB)
   * @param p_Mask Bitmask defining the field width (e.g., 0xF for 4 bits)
   * @param p_Value Value to set (automatically masked to fit the field)
   * @param p_Raw If true, operates on raw network byte order; if false, converts to/from host order
   * @note Automatically validates bit position and masks the value to prevent overflow
   */
  void SetFlagValue(uint8_t p_BitPos, uint16_t p_Mask, uint8_t p_Value, bool p_Raw) noexcept;
};

/**
 * @brief Non-member swap function for DnsHeader objects
 * @param p_LeftSide Left-hand side DnsHeader to swap
 * @param p_RightSide Right-hand side DnsHeader to swap
 * @note This function enables argument-dependent lookup (ADL) for swap operations
 * @note Provides STL-compatible swap interface for use with algorithms
 * @see std::swap for general swap documentation
 */
void swap(DnsHeader &p_LeftSide, DnsHeader &p_RightSide) noexcept;

/**
 * @brief Standard library hash specialization for DnsHeader
 *
 * This specialization allows DnsHeader objects to be used as keys in
 * hash-based containers like std::unordered_map and std::unordered_set.
 *
 * @note The hash function combines all header fields to provide good distribution
 * @note Two DnsHeader objects that compare equal will have the same hash value
 * @note Hash collision resistance is provided by combining multiple fields
 *
 * Example usage:
 * @code
 * std::unordered_map<DnsHeader, std::string> headerMap;
 * std::unordered_set<DnsHeader> headerSet;
 * @endcode
 */
namespace std {
template <>
struct hash<DnsHeader> {
    /**
   * @brief Calculate hash value for a DnsHeader object
   * @param p_Header The DnsHeader object to hash
   * @return Hash value suitable for use in hash containers
   * @note Uses the DnsHeader::Hash() method for consistent hashing
   * @note Complexity: O(1) constant time
   */
  DnsHeader::size_type operator()(const DnsHeader &p_Header) const noexcept;
};
} // namespace std

#endif // DNS_PACKET_HEADER_H_
