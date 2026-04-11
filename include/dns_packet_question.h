/** @file dns_packet_question.h
 *  @brief DnsQuestion class representing a DNS question section entry (RFC 1035 Section 4.1.2).
 */

#ifndef DNS_PACKET_QUESTION_H_
#define DNS_PACKET_QUESTION_H_

#include <array>     // std::array
#include <cstddef>   // std::size_t, std::ptrdiff_t
#include <cstdint>   // uint16_t
#include <ostream>   // std::ostream
#include <stdexcept> // std::invalid_argument
#include <string>    // std::string
#include <vector>    // std::vector

/** Question section format

The question section is used to carry the "question" in most queries, i.e., the parameters that define what is being asked.  The section contains QDCOUNT (usually 1) entries, each of the following format:

                                1  1  1  1  1  1
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                     QNAME                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QTYPE                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QCLASS                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

where:

QNAME     - a domain name represented as a sequence of labels, where each label consists of a length octet followed by that number of octets. The domain name terminates with the zero length octet for the null label of the root. Note that this field may be an odd number of octets; no padding is used.
            Each label consists of:
              - 1 byte: Length of the label (0-63)
              - N bytes: Label data
              - Terminated with a zero byte (null label)

              Example: "www.example.com" becomes:
              [3]www[7]example[3]com[0]
QTYPE     - a two octet code which specifies the type of the query. The values for this field include all codes valid for a TYPE field, together with some more general codes which can match more than one type of RR.
            Common query types:
              0x0001 (1)   = A     - IPv4 address
              0x0002 (2)   = NS    - Name server
              0x0005 (5)   = CNAME - Canonical name
              0x0006 (6)   = SOA   - Start of authority
              0x000C (12)  = PTR   - Pointer (reverse lookup)
              0x000F (15)  = MX    - Mail exchange
              0x0010 (16)  = TXT   - Text record
              0x001C (28)  = AAAA  - IPv6 address
              0x0021 (33)  = SRV   - Service locator
              0x00FF (255) = ANY   - All records (deprecated)
QCLASS    - a two octet code that specifies the class of the query. For example, the QCLASS field is IN for the Internet.
            Common query classes:
              0x0001 (1)   = IN    - Internet (most common)
              0x0003 (3)   = CH    - Chaos
              0x0004 (4)   = HS    - Hesiod
              0x00FF (255) = ANY   - Any class

Common Question Format:
- Most DNS queries use QCLASS=1 (Internet)
- QTYPE=1 (A records) and QTYPE=28 (AAAA records) are most common
- QNAME encoding must follow DNS label format exactly

QNAME Encoding Rules:
- Maximum label length: 63 bytes
- Maximum total name length: 255 bytes
- Labels are case-insensitive
- Compression may be used (see DNS compression format)
*/

/**
 * @brief DNS Question class implementing RFC 1035 DNS question section format
 *
 * This class represents a DNS question entry with support for both raw network
 * byte order and host byte order operations. It provides an STL-like interface
 * for managing domain names, query types, and query classes.
 *
 * The DNS question contains a domain name (QNAME), query type (QTYPE), and
 * query class (QCLASS) as specified in RFC 1035.
 *
 * @note All network data is stored internally in network byte order
 * @see RFC 1035 Section 4.1.2 for DNS question format specification
 */
class DnsQuestion {
public:
  /// @name STL Container Type Aliases
  /// @{
  using value_type = std::string;                                                  ///< Type of values stored in label vector
  using size_type = std::size_t;                                                   ///< Type used for sizes and counts
  using difference_type = std::ptrdiff_t;                                          ///< Type used for pointer arithmetic
  using pointer = std::string *;                                                   ///< Pointer to label
  using const_pointer = const std::string *;                                       ///< Const pointer to label
  using reference = std::string &;                                                 ///< Reference to label
  using const_reference = const std::string &;                                     ///< Const reference to label
  using iterator = std::vector<std::string>::iterator;                             ///< Iterator type
  using const_iterator = std::vector<std::string>::const_iterator;                 ///< Const iterator type
  using reverse_iterator = std::vector<std::string>::reverse_iterator;             ///< Reverse iterator type
  using const_reverse_iterator = std::vector<std::string>::const_reverse_iterator; ///< Const reverse iterator type
  /// @}

  /// @name Constructors and Destructor
  /// @{

  /**
   * @brief Default constructor - initializes empty question
   */
  DnsQuestion() = default;

  /**
   * @brief Copy constructor
   * @param p_Other The DnsQuestion to copy from
   */
  DnsQuestion(const DnsQuestion &) = default;

  /**
   * @brief Move constructor
   * @param p_Other The DnsQuestion to move from
   */
  DnsQuestion(DnsQuestion &&) = default;

  /**
   * @brief Copy assignment operator
   * @param p_Other The DnsQuestion to copy from
   * @return Reference to this object
   */
  DnsQuestion &operator=(const DnsQuestion &) = default;

  /**
   * @brief Move assignment operator
   * @param p_Other The DnsQuestion to move from
   * @return Reference to this object
   */
  DnsQuestion &operator=(DnsQuestion &&) = default;

  /**
   * @brief Destructor
   */
  ~DnsQuestion() = default;

  /**
   * @brief Construct from raw data pointer with size validation
   * @param p_Data Pointer to DNS question data in network byte order
   * @param p_Size Size of available data in bytes
   * @throws std::invalid_argument if p_Data is nullptr or insufficient data
   * @note Validates that enough data is available for parsing
   */
  DnsQuestion(const char *p_Data, size_type p_Size);

  /**
   * @brief Construct from raw data pointer with size validation and offset tracking
   * @param p_Data Pointer to DNS question data in network byte order
   * @param p_Size Size of available data in bytes
   * @param p_Offset Starting offset (will be updated to point after question)
   * @throws std::invalid_argument if p_Data is nullptr or insufficient data
   * @note Validates that enough data is available for parsing
   */
  DnsQuestion(const char *p_Data, size_type p_Size, size_type &p_Offset);

  /**
   * @brief Construct from std::string containing raw question data
   * @param p_Data String containing DNS question data in network byte order
   * @throws std::invalid_argument if string is too short or contains invalid data
   * @note Parses the question from the beginning of the string
   */
  explicit DnsQuestion(const std::string &p_Data);

  /**
   * @brief Construct from std::string with offset tracking
   * @param p_Data String containing DNS question data in network byte order
   * @param p_Offset Starting offset (will be updated to point after question)
   * @throws std::invalid_argument if string is too short or contains invalid data
   * @note Parses the question from the beginning of the string
   */
  explicit DnsQuestion(const std::string &p_Data, size_type &p_Offset);

  /**
   * @brief Construct from std::vector<char> containing raw question data
   * @param p_Data Vector containing DNS question data in network byte order
   * @throws std::invalid_argument if vector is too short or contains invalid data
   * @note Parses the question from the beginning of the vector
   */
  explicit DnsQuestion(const std::vector<char> &p_Data);

  /**
   * @brief Construct from std::vector<char> with offset tracking
   * @param p_Data Vector containing DNS question data in network byte order
   * @param p_Offset Starting offset (will be updated to point after question)
   * @throws std::invalid_argument if vector is too short or contains invalid data
   * @note Parses the question from the beginning of the vector
   */
  explicit DnsQuestion(const std::vector<char> &p_Data, size_type &p_Offset);

  /**
   * @brief Construct from std::vector<unsigned char> containing raw question data
   * @param p_Data Vector containing DNS question data in network byte order
   * @throws std::invalid_argument if vector is too short or contains invalid data
   * @note Parses the question from the beginning of the vector
   */
  explicit DnsQuestion(const std::vector<unsigned char> &p_Data);

  /**
   * @brief Construct from std::vector<unsigned char> with offset tracking
   * @param p_Data Vector containing DNS question data in network byte order
   * @param p_Offset Starting offset (will be updated to point after question)
   * @throws std::invalid_argument if vector is too short or contains invalid data
   * @note Parses the question from the beginning of the vector
   */
  explicit DnsQuestion(const std::vector<unsigned char> &p_Data, size_type &p_Offset);

  /**
   * @brief Construct from C-style array with compile-time size checking
   * @tparam N Array size (must be >= minimum question size)
   * @param p_Data Array containing DNS question data in network byte order
   * @throws std::invalid_argument if array contains invalid data
   * @note Compile-time size validation ensures some safety
   */
  template <size_type N>
  explicit DnsQuestion(const char (&p_Data)[N]) {
    static_assert(N >= 5, "Array must contain at least 5 bytes (minimum question size)");
    size_type s_Offset{0};
    if (!FromWire(p_Data, N, s_Offset, *this)) {
      throw std::invalid_argument("DnsQuestion: invalid array data");
    }
  }

  /**
   * @brief Construct from C-style array with offset tracking
   * @tparam N Array size (must be >= minimum question size)
   * @param p_Data Array containing DNS question data in network byte order
   * @param p_Offset Starting offset (will be updated to point after question)
   * @throws std::invalid_argument if array contains invalid data
   */
  template <size_type N>
  explicit DnsQuestion(const char (&p_Data)[N], size_type &p_Offset) {
    static_assert(N >= 5, "Array must contain at least 5 bytes (minimum question size)");
    if (!FromWire(p_Data, N, p_Offset, *this)) {
      throw std::invalid_argument("DnsQuestion: invalid array data");
    }
  }

  /**
   * @brief Construct from std::array<char> containing raw question data
   * @tparam N Array size (must be >= minimum question size)
   * @param p_Data Array containing DNS question data in network byte order
   * @throws std::invalid_argument if array contains invalid data
   * @note Compile-time size validation ensures some safety
   */
  template <size_type N>
  explicit DnsQuestion(const std::array<char, N> &p_Data) {
    static_assert(N >= 5, "Array must contain at least 5 bytes (minimum question size)");
    size_type s_Offset{0};
    if (!FromWire(p_Data.data(), N, s_Offset, *this)) {
      throw std::invalid_argument("DnsQuestion: invalid array data");
    }
  }

  /**
   * @brief Construct from std::array<char> with offset tracking
   * @tparam N Array size (must be >= minimum question size)
   * @param p_Data Array containing DNS question data in network byte order
   * @param p_Offset Starting offset (will be updated to point after question)
   * @throws std::invalid_argument if array contains invalid data
   */
  template <size_type N>
  explicit DnsQuestion(const std::array<char, N> &p_Data, size_type &p_Offset) {
    static_assert(N >= 5, "Array must contain at least 5 bytes (minimum question size)");
    if (!FromWire(p_Data.data(), N, p_Offset, *this)) {
      throw std::invalid_argument("DnsQuestion: invalid array data");
    }
  }

  /**
   * @brief Construct from std::array<unsigned char> containing raw question data
   * @tparam N Array size (must be >= minimum question size)
   * @param p_Data Array containing DNS question data in network byte order
   * @throws std::invalid_argument if array contains invalid data
   * @note Compile-time size validation ensures some safety
   */
  template <size_type N>
  explicit DnsQuestion(const std::array<unsigned char, N> &p_Data) {
    static_assert(N >= 5, "Array must contain at least 5 bytes (minimum question size)");
    size_type s_Offset{0};
    if (!FromWire(reinterpret_cast<const char *>(p_Data.data()), N, s_Offset, *this)) {
      throw std::invalid_argument("DnsQuestion: invalid array data");
    }
  }

  /**
   * @brief Construct from std::array<unsigned char> with offset tracking
   * @tparam N Array size (must be >= minimum question size)
   * @param p_Data Array containing DNS question data in network byte order
   * @param p_Offset Starting offset (will be updated to point after question)
   * @throws std::invalid_argument if array contains invalid data
   */
  template <size_type N>
  explicit DnsQuestion(const std::array<unsigned char, N> &p_Data, size_type &p_Offset) {
    static_assert(N >= 5, "Array must contain at least 5 bytes (minimum question size)");
    if (!FromWire(reinterpret_cast<const char *>(p_Data.data()), N, p_Offset, *this)) {
      throw std::invalid_argument("DnsQuestion: invalid array data");
    }
  }

  /**
   * @brief Construct question with specific field values
   * @param p_DomainName Full domain name (e.g., "www.example.com")
   * @param p_Type Query type
   * @param p_Class Query class
   */
  explicit DnsQuestion(const std::string &p_DomainName, uint16_t p_Type, uint16_t p_Class);

  /**
   * @brief Construct question with specific field values
   * @param p_Labels Domain name labels
   * @param p_Type Query type
   * @param p_Class Query class
   * @note All values are assumed to be in host byte order and will be converted
   */
  explicit DnsQuestion(std::vector<std::string> p_Labels, uint16_t p_Type, uint16_t p_Class);

  /**
   * @brief Construct query for A record with convenient syntax
   * @param p_DomainName Domain name to query
   * @return DnsQuestion configured for A record lookup
   */
  [[nodiscard]] static DnsQuestion MakeAQuery(const std::string &p_DomainName);

  /**
   * @brief Construct query for NS record
   * @param p_DomainName Domain name to query
   * @return DnsQuestion configured for NS record lookup
   */
  [[nodiscard]] static DnsQuestion MakeNsQuery(const std::string &p_DomainName);

  /**
   * @brief Construct query for CNAME record
   * @param p_DomainName Domain name to query
   * @return DnsQuestion configured for CNAME record lookup
   */
  [[nodiscard]] static DnsQuestion MakeCnameQuery(const std::string &p_DomainName);

  /**
   * @brief Construct query for SOA record
   * @param p_DomainName Domain name to query
   * @return DnsQuestion configured for SOA record lookup
   */
  [[nodiscard]] static DnsQuestion MakeSoaQuery(const std::string &p_DomainName);

  /**
   * @brief Construct query for PTR record (reverse lookup)
   * @param p_IpAddress IP address for reverse lookup
   * @return DnsQuestion configured for PTR record lookup
   */
  [[nodiscard]] static DnsQuestion MakePtrQuery(const std::string &p_IpAddress);

  /**
   * @brief Construct query for MX record
   * @param p_DomainName Domain name to query
   * @return DnsQuestion configured for MX record lookup
   */
  [[nodiscard]] static DnsQuestion MakeMxQuery(const std::string &p_DomainName);

  /**
   * @brief Construct query for TXT record
   * @param p_DomainName Domain name to query
   * @return DnsQuestion configured for TXT record lookup
   */
  [[nodiscard]] static DnsQuestion MakeTxtQuery(const std::string &p_DomainName);

  /**
   * @brief Construct query for AAAA record with convenient syntax
   * @param p_DomainName Domain name to query
   * @return DnsQuestion configured for AAAA record lookup
   */
  [[nodiscard]] static DnsQuestion MakeAaaaQuery(const std::string &p_DomainName);

  /**
   * @brief Construct query for SRV record
   * @param p_DomainName Service domain name to query (e.g. "_sip._tcp.example.com")
   * @return DnsQuestion configured for SRV record lookup
   */
  [[nodiscard]] static DnsQuestion MakeSrvQuery(const std::string &p_DomainName);
  /// @}

  /// @name Field Getters
  /// @{

  /**
   * @brief Get the domain name labels
   * @return Const reference to vector of domain name labels
   * @note Labels are stored without the trailing dot
   * @note Example: "www.example.com" returns {"www", "example", "com"}
   */
  [[nodiscard]] const std::vector<std::string> &Qname() const noexcept;

  /**
   * @brief Get the query type
   * @param p_Raw If true, returns raw network byte order; if false, converts to host order
   * @return 16-bit query type (1=A, 2=NS, 5=CNAME, 15=MX, 28=AAAA, etc.)
   */
  [[nodiscard]] uint16_t Qtype(bool p_Raw = false) const noexcept;

  /**
   * @brief Get the query class
   * @param p_Raw If true, returns raw network byte order; if false, converts to host order
   * @return 16-bit query class (1=Internet, 3=Chaos, 4=Hesiod)
   */
  [[nodiscard]] uint16_t Qclass(bool p_Raw = false) const noexcept;

  /**
   * @brief Get the full domain name as a string
   * @return Domain name with dots between labels (e.g., "www.example.com")
   * @note Does not include trailing dot
   */
  [[nodiscard]] std::string QnameAsString() const;

  /**
   * @brief Get the full qualified domain name (FQDN) as a string
   * @return Domain name with trailing dot (e.g., "www.example.com.")
   */
  [[nodiscard]] std::string Fqdn() const;
  /// @}

  /// @name Field Setters
  /// @{

  /**
   * @brief Set the domain name labels
   * @param p_Labels Vector of domain name labels
   * @note Labels should not contain dots or be empty
   * @note Invalid labels will be skipped
   */
  void SetQname(const std::vector<std::string> &p_Labels);

  /**
   * @brief Set domain name from a dot-separated string
   * @param p_DomainName Domain name string (e.g., "www.example.com")
   * @note Trailing dot is automatically removed
   * @note Empty labels are skipped
   */
  void SetQnameFromString(const std::string &p_DomainName);

  /**
   * @brief Set the query type
   * @param p_Type Query type value
   * @param p_Raw If true, treats p_Type as network byte order; if false, converts from host order
   */
  void SetQtype(uint16_t p_Type, bool p_Raw = false) noexcept;

  /**
   * @brief Set the query class
   * @param p_Class Query class value
   * @param p_Raw If true, treats p_Class as network byte order; if false, converts from host order
   */
  void SetQclass(uint16_t p_Class, bool p_Raw = false) noexcept;
  /// @}

  /// @name Label Management
  /// @{

  /**
   * @brief Add a label to the end of the domain name
   * @param p_Label Label to add (must be valid DNS label)
   * @return true if label was added, false if invalid
   */
  bool AddLabel(const std::string &p_Label);

  /**
   * @brief Insert a label at the beginning of the domain name
   * @param p_Label Label to prepend
   * @return true if label was added, false if invalid
   */
  bool PrependLabel(const std::string &p_Label);

  /**
   * @brief Remove the last label from the domain name
   * @return true if a label was removed, false if empty
   */
  bool PopLabel() noexcept;

  /**
   * @brief Remove the first label from the domain name
   * @return true if a label was removed, false if empty
   */
  bool RemoveFirstLabel() noexcept;
  /// @}

  /// @name STL-like Member Functions
  /// @{

  /**
   * @brief Swap contents with another DnsQuestion
   * @param p_Other The DnsQuestion to swap with
   */
  void swap(DnsQuestion &p_Other) noexcept;

  /**
   * @brief Check if question has no domain name labels
   * @return true if no labels are present
   */
  [[nodiscard]] bool empty() const noexcept;

  /**
   * @brief Get the number of domain name labels
   * @return Number of labels in the domain name
   */
  [[nodiscard]] size_type size() const noexcept;

  /**
   * @brief Get the maximum possible number of labels
   * @return Maximum size of the label vector
   */
  [[nodiscard]] size_type max_size() const noexcept;

  /**
   * @brief Reserve space for labels
   * @param p_Size Number of labels to reserve space for
   */
  void reserve(size_type p_Size);

  /**
   * @brief Clear all labels and reset type/class to defaults
   */
  void clear() noexcept;

  /**
   * @brief Resize the label vector
   * @param p_Size New size
   * @param p_Value Value to fill new elements with
   */
  void resize(size_type p_Size, const std::string &p_Value = std::string());
  /// @}

  /// @name Iterator Support
  /// @{

  /**
   * @brief Get iterator to first label
   * @return Iterator to beginning of labels
   */
  [[nodiscard]] iterator begin() noexcept;

  /**
   * @brief Get const iterator to first label
   * @return Const iterator to beginning of labels
   */
  [[nodiscard]] const_iterator begin() const noexcept;

  /**
   * @brief Get const iterator to first label
   * @return Const iterator to beginning of labels
   */
  [[nodiscard]] const_iterator cbegin() const noexcept;

  /**
   * @brief Get iterator to past-the-end
   * @return Iterator to end of labels
   */
  [[nodiscard]] iterator end() noexcept;

  /**
   * @brief Get const iterator to past-the-end
   * @return Const iterator to end of labels
   */
  [[nodiscard]] const_iterator end() const noexcept;

  /**
   * @brief Get const iterator to past-the-end
   * @return Const iterator to end of labels
   */
  [[nodiscard]] const_iterator cend() const noexcept;

  /**
   * @brief Get reverse iterator to last label
   * @return Reverse iterator to end of labels
   */
  [[nodiscard]] reverse_iterator rbegin() noexcept;

  /**
   * @brief Get const reverse iterator to last label
   * @return Const reverse iterator to end of labels
   */
  [[nodiscard]] const_reverse_iterator rbegin() const noexcept;

  /**
   * @brief Get const reverse iterator to last label
   * @return Const reverse iterator to end of labels
   */
  [[nodiscard]] const_reverse_iterator crbegin() const noexcept;

  /**
   * @brief Get reverse iterator to before first label
   * @return Reverse iterator to beginning of labels
   */
  [[nodiscard]] reverse_iterator rend() noexcept;

  /**
   * @brief Get const reverse iterator to before first label
   * @return Const reverse iterator to beginning of labels
   */
  [[nodiscard]] const_reverse_iterator rend() const noexcept;

  /**
   * @brief Get const reverse iterator to before first label
   * @return Const reverse iterator to beginning of labels
   */
  [[nodiscard]] const_reverse_iterator crend() const noexcept;
  /// @}

  /// @name Element Access
  /// @{

  /**
   * @brief Access label at specified position with bounds checking
   * @param p_Index Position of label to access
   * @return Reference to the label at specified position
   * @throws std::out_of_range if p_Index >= size()
   */
  [[nodiscard]] reference at(size_type p_Index);

  /**
   * @brief Access label at specified position with bounds checking
   * @param p_Index Position of label to access
   * @return Const reference to the label at specified position
   * @throws std::out_of_range if p_Index >= size()
   */
  [[nodiscard]] const_reference at(size_type p_Index) const;

  /**
   * @brief Access label at specified position without bounds checking
   * @param p_Index Position of label to access
   * @return Reference to the label at specified position
   * @note Undefined behavior if p_Index >= size()
   */
  [[nodiscard]] reference operator[](size_type p_Index) noexcept;

  /**
   * @brief Access label at specified position without bounds checking
   * @param p_Index Position of label to access
   * @return Const reference to the label at specified position
   * @note Undefined behavior if p_Index >= size()
   */
  [[nodiscard]] const_reference operator[](size_type p_Index) const noexcept;

  /**
   * @brief Access first label
   * @return Reference to the first label
   * @note Undefined behavior if empty()
   */
  [[nodiscard]] reference front() noexcept;

  /**
   * @brief Access first label
   * @return Const reference to the first label
   * @note Undefined behavior if empty()
   */
  [[nodiscard]] const_reference front() const noexcept;

  /**
   * @brief Access last label
   * @return Reference to the last label
   * @note Undefined behavior if empty()
   */
  [[nodiscard]] reference back() noexcept;

  /**
   * @brief Access last label
   * @return Const reference to the last label
   * @note Undefined behavior if empty()
   */
  [[nodiscard]] const_reference back() const noexcept;
  /// @}

  /// @name Validation
  /// @{

  /**
   * @brief Check if the question is valid according to DNS specifications
   * @return true if all labels are valid and within size limits
   */
  [[nodiscard]] bool Valid() const noexcept;

  // Do we really need these shortcuts? What about ALL the other record types?
  // /**
  //  * @brief Check if this represents the DNS root domain
  //  * @return true if this is the root domain (empty label list)
  //  */
  // [[nodiscard]] bool is_root() const noexcept;
  //
  // /**
  //  * @brief Check if this is a query for an A record
  //  * @return true if QTYPE is 1 (A record)
  //  */
  // [[nodiscard]] bool isAQuery() const noexcept;
  //
  // /**
  //  * @brief Check if this is a query for an AAAA record
  //  * @return true if QTYPE is 28 (AAAA record)
  //  */
  // [[nodiscard]] bool isAAAAQuery() const noexcept;
  //
  // /**
  //  * @brief Check if this is an Internet class query
  //  * @return true if QCLASS is 1 (Internet)
  //  */
  // [[nodiscard]] bool isInternetClass() const noexcept;
  //
  // /**
  //  * @brief Check if this is a PTR (reverse lookup) query
  //  * @return true if QTYPE is 12 (PTR record)
  //  */
  // [[nodiscard]] bool isPTRQuery() const noexcept;
  /// @}

  /// @name Hash Support
  /// @{

  /**
   * @brief Calculate hash value for use in hash containers
   * @return Hash value suitable for std::unordered_map and std::unordered_set
   */
  [[nodiscard]] size_type Hash() const noexcept;
  /// @}

  /// @name Direct Data Access
  /// @{

  /**
   * @brief Get pointer to underlying label array
   * @return Pointer to the underlying array
   */
  [[nodiscard]] void *data() noexcept;

  /**
   * @brief Get pointer to underlying label array
   * @return Const pointer to the underlying array
   */
  [[nodiscard]] const void *data() const noexcept;
  /// @}

  /// @name Wire Format Helpers
  /// @{

  /**
   * @brief Calculate the wire format size of this question
   * @return Size in bytes when serialized
   */
  [[nodiscard]] size_type WireSize() const noexcept;

  /**
   * @brief Create question from raw network data with validation
   * @param p_Data Pointer to raw data
   * @param p_Size Size of available data
   * @param p_Offset Starting offset (updated to point after question)
   * @param p_OutQuestion Output question object
   * @return true if successfully parsed and valid
   */
  [[nodiscard]] static bool FromWire(const void *p_Data, size_type p_Size, size_type &p_Offset, DnsQuestion &p_OutQuestion);

  /**
   * @brief Serialize question to buffer with size checking
   * @param p_Data Output buffer
   * @param p_Size Size of output buffer
   * @return Number of bytes written, or 0 on error
   */
  [[nodiscard]] size_type ToWire(void *p_Data, size_type p_Size) const noexcept;
  /// @}

  /// @name Comparison Operators
  /// @{

  /**
   * @brief Test equality with another DnsQuestion
   * @param p_Other The DnsQuestion to compare with
   * @return true if all fields are equal
   */
  [[nodiscard]] bool operator==(const DnsQuestion &p_Other) const noexcept;

  /**
   * @brief Test inequality with another DnsQuestion
   * @param p_Other The DnsQuestion to compare with
   * @return true if any field differs
   */
  [[nodiscard]] bool operator!=(const DnsQuestion &p_Other) const noexcept;

  /**
   * @brief Test less-than relationship for ordering
   * @param p_Other The DnsQuestion to compare with
   * @return true if this question is lexicographically less than p_Other
   */
  [[nodiscard]] bool operator<(const DnsQuestion &p_Other) const noexcept;
  /// @}

  /**
   * @brief Stream output operator for debugging and logging
   * @param p_OutputStream Output stream to write to
   * @param p_Question DnsQuestion to output
   * @return Reference to the output stream
   */
  friend std::ostream &operator<<(std::ostream &p_OutputStream, const DnsQuestion &p_Question);

private:
  /// @name Private Member Variables
  /// @{
  std::vector<std::string> m_Qname_{}; ///< Domain name labels
  uint16_t m_Qtype_{};                 ///< Query type (network byte order)
  uint16_t m_Qclass_{};                ///< Query class (network byte order)
  /// @}

  /**
   * @brief Validate a DNS label according to RFC specifications
   * @param p_Label The label to validate
   * @return true if the label is valid
   */
  [[nodiscard]] static bool IsValidLabel(const std::string &p_Label) noexcept;

  /**
   * @brief Calculate the size needed for QnameAsString()
   * @return Estimated string size for optimization
   */
  [[nodiscard]] size_type CalculateStringSize() const noexcept;

  /**
   * @brief Parse domain name from binary data
   * @param p_Data Binary data
   * @param p_Size Data size
   * @param p_Offset Current offset (updated)
   * @param p_Labels Output labels
   * @return true if successful
   */
  static bool ParseDomainName(const void *p_Data, size_type p_Size, size_type &p_Offset, std::vector<std::string> &p_Labels);

  /**
   * @brief Set PTR query from IP address
   * @param p_IpAddress IP address string
   */
  void SetPTRFromIp(const std::string &p_IpAddress);
};

/**
 * @brief Non-member swap function for DnsQuestion objects
 * @param p_LeftSide Left-hand side DnsQuestion to swap
 * @param p_RightSide Right-hand side DnsQuestion to swap
 * @note This function enables argument-dependent lookup (ADL) for swap operations
 * @note Provides STL-compatible swap interface for use with algorithms
 * @see std::swap for general swap documentation
 */
void swap(DnsQuestion &p_LeftSide, DnsQuestion &p_RightSide) noexcept;

/**
 * @brief Standard library hash specialization for DnsQuestion
 *
 * This specialization allows DnsQuestion objects to be used as keys in
 * hash-based containers like std::unordered_map and std::unordered_set.
 *
 * @note The hash function combines domain name, type, and class for good distribution
 * @note Two DnsQuestion objects that compare equal will have the same hash value
 * @note Hash collision resistance is provided by combining multiple fields
 *
 * Example usage:
 * @code
 * std::unordered_map<DnsQuestion, std::string> questionMap;
 * std::unordered_set<DnsQuestion> questionSet;
 * @endcode
 */
namespace std {
template <>
struct hash<DnsQuestion> {
    /**
   * @brief Calculate hash value for a DnsQuestion object
   * @param p_Question The DnsQuestion object to hash
   * @return Hash value suitable for use in hash containers
   * @note Uses the DnsQuestion::Hash() method for consistent hashing
   * @note Complexity: O(n) where n is the number of labels
   */
  DnsQuestion::size_type operator()(const DnsQuestion &p_Question) const noexcept;
};
} // namespace std

#endif // DNS_PACKET_QUESTION_H_
