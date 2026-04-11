/** @file dns_packet_answer.h
 *  @brief DnsAnswer class representing a DNS resource record (RFC 1035 Section 4.1.3).
 */

#ifndef DNS_PACKET_ANSWER_H_
#define DNS_PACKET_ANSWER_H_

#include <array>     // std::array
#include <cstddef>   // std::size_t, std::ptrdiff_t
#include <cstdint>   // uint16_t, uint32_t
#include <ostream>   // std::ostream
#include <stdexcept> // std::invalid_argument
#include <string>    // std::string
#include <vector>    // std::vector

/** Answer/Resource record format

The answer, authority, and additional sections all share the same format: a variable number of resource records, where the number of records is specified in the corresponding count field in the header. Each resource record has the following format:

                                1  1  1  1  1  1
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                                               /
/                      NAME                     /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TYPE                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     CLASS                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TTL                      |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   RDLENGTH                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
/                     RDATA                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

where:

NAME      - a domain name to which this resource record pertains.
            Encoded in DNS label format (same as QNAME).
            May use compression pointers to reduce packet size.
            Can be a hostname, FQDN, or compressed reference.
TYPE      - two octets containing one of the RR type codes. This field specifies the meaning of the data in the RDATA field.
            Common record types:
              0x0001 (1)   = A     - IPv4 address (4 bytes)
              0x0002 (2)   = NS    - Name server (domain name)
              0x0005 (5)   = CNAME - Canonical name (domain name)
              0x0006 (6)   = SOA   - Start of authority
              0x000C (12)  = PTR   - Pointer (domain name)
              0x000F (15)  = MX    - Mail exchange (priority + domain)
              0x0010 (16)  = TXT   - Text record (variable text)
              0x001C (28)  = AAAA  - IPv6 address (16 bytes)
              0x0021 (33)  = SRV   - Service locator
CLASS     - two octets which specify the class of the data in the RDATA field.
            Common record classes:
              0x0001 (1)   = IN    - Internet (standard)
              0x0003 (3)   = CH    - Chaos
              0x0004 (4)   = HS    - Hesiod
TTL       - a 32 bit unsigned integer that specifies the time interval (in seconds) that the resource record may be cached before it should be discarded. Zero values are interpreted to mean that the RR can only be used for the transaction in progress, and should not be cached.
            Examples:
              0     = Do not cache
              300   = 5 minutes
              3600  = 1 hour
              86400 = 1 day
RDLENGTH  - an unsigned 16 bit integer that specifies the length in octets of the RDATA field.
            Must match the actual RDATA size.
            Used to skip over records when parsing.
RDATA     - a variable length string of octets that describes the resource. The format of this information varies according to the TYPE and CLASS of the resource record. For example, the if the TYPE is A and the CLASS is IN, the RDATA field is a 4 octet ARPA Internet address.
            Common type fields:
              A Record:     4 bytes (IPv4 address)
              AAAA Record:  16 bytes (IPv6 address)
              CNAME/NS/PTR: Domain name (DNS label format)
              MX Record:    2 bytes priority + domain name
              TXT Record:   Length-prefixed text strings
              SOA Record:   Multiple fields (see SOA format)

Common RDATA Formats:
- A:     [192][168][1][100] (4 bytes for 192.168.1.100)
- AAAA:  16 bytes of IPv6 address
- CNAME: DNS-encoded domain name
- MX:    [priority][domain name]
- TXT:   [length][text data] (may have multiple strings)

Compression Notes:
- NAME field often uses compression pointers (0xC0xx format)
- Domain names in RDATA may also be compressed
- Compression reduces packet size significantly
*/

/**
 * @brief DNS Answer/Resource Record class implementing RFC 1035 DNS resource record format
 *
 * This class represents a DNS resource record (RR) with support for both raw network
 * byte order and host byte order operations. It provides an STL-like interface
 * for managing domain names, record types, classes, TTL, and resource data.
 *
 * The DNS resource record contains a domain name (NAME), record type (TYPE),
 * record class (CLASS), time-to-live (TTL), data length (RDLENGTH), and
 * resource data (RDATA) as specified in RFC 1035.
 *
 * @note All network data is stored internally in network byte order
 * @see RFC 1035 Section 3.2.1 for DNS resource record format specification
 */
class DnsAnswer {
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
   * @brief Default constructor - initializes empty resource record
   */
  DnsAnswer() = default;

  /**
   * @brief Copy constructor
   * @param p_Other The DnsAnswer to copy from
   */
  DnsAnswer(const DnsAnswer &) = default;

  /**
   * @brief Move constructor
   * @param p_Other The DnsAnswer to move from
   */
  DnsAnswer(DnsAnswer &&) = default;

  /**
   * @brief Copy assignment operator
   * @param p_Other The DnsAnswer to copy from
   * @return Reference to this object
   */
  DnsAnswer &operator=(const DnsAnswer &) = default;

  /**
   * @brief Move assignment operator
   * @param p_Other The DnsAnswer to move from
   * @return Reference to this object
   */
  DnsAnswer &operator=(DnsAnswer &&) = default;

  /**
   * @brief Destructor
   */
  ~DnsAnswer() = default;

  /**
   * @brief Construct from raw data pointer with size validation
   * @param p_Data Pointer to DNS resource record data in network byte order
   * @param p_Size Size of available data in bytes
   * @throws std::invalid_argument if p_Data is nullptr or insufficient data
   * @note Validates that enough data is available for parsing
   */
  DnsAnswer(const char *p_Data, size_type p_Size);

  /**
   * @brief Construct from raw data pointer with size validation and offset tracking
   * @param p_Data Pointer to DNS resource record data in network byte order
   * @param p_Size Size of available data in bytes
   * @param p_Offset Starting offset (will be updated to point after record)
   * @throws std::invalid_argument if p_Data is nullptr or insufficient data
   * @note Validates that enough data is available for parsing
   */
  DnsAnswer(const char *p_Data, size_type p_Size, size_type &p_Offset);

  /**
   * @brief Construct from std::string containing raw record data
   * @param p_Data String containing DNS resource record data in network byte order
   * @throws std::invalid_argument if string is too short or contains invalid data
   * @note Parses the record from the beginning of the string
   */
  explicit DnsAnswer(const std::string &p_Data);

  /**
   * @brief Construct from std::string with offset tracking
   * @param p_Data String containing DNS resource record data in network byte order
   * @param p_Offset Starting offset (will be updated to point after record)
   * @throws std::invalid_argument if string is too short or contains invalid data
   * @note Parses the record from the beginning of the string
   */
  explicit DnsAnswer(const std::string &p_Data, size_type &p_Offset);

  /**
   * @brief Construct from std::vector<char> containing raw record data
   * @param p_Data Vector containing DNS resource record data in network byte order
   * @throws std::invalid_argument if vector is too short or contains invalid data
   * @note Parses the record from the beginning of the vector
   */
  explicit DnsAnswer(const std::vector<char> &p_Data);

  /**
   * @brief Construct from std::vector<char> with offset tracking
   * @param p_Data Vector containing DNS resource record data in network byte order
   * @param p_Offset Starting offset (will be updated to point after record)
   * @throws std::invalid_argument if vector is too short or contains invalid data
   * @note Parses the record from the beginning of the vector
   */
  explicit DnsAnswer(const std::vector<char> &p_Data, size_type &p_Offset);

  /**
   * @brief Construct from std::vector<unsigned char> containing raw record data
   * @param p_Data Vector containing DNS resource record data in network byte order
   * @throws std::invalid_argument if vector is too short or contains invalid data
   * @note Parses the record from the beginning of the vector
   */
  explicit DnsAnswer(const std::vector<unsigned char> &p_Data);

  /**
   * @brief Construct from std::vector<unsigned char> with offset tracking
   * @param p_Data Vector containing DNS resource record data in network byte order
   * @param p_Offset Starting offset (will be updated to point after record)
   * @throws std::invalid_argument if vector is too short or contains invalid data
   * @note Parses the record from the beginning of the vector
   */
  explicit DnsAnswer(const std::vector<unsigned char> &p_Data, size_type &p_Offset);

  /**
   * @brief Construct from C-style array with compile-time size checking
   * @tparam N Array size (must be >= minimum record size)
   * @param p_Data Array containing DNS resource record data in network byte order
   * @throws std::invalid_argument if array contains invalid data
   * @note Compile-time size validation ensures some safety
   */
  template <size_type N>
  explicit DnsAnswer(const char (&p_Data)[N]) {
    static_assert(N >= 10, "Array must contain at least 10 bytes (minimum record size)");
    size_type s_Offset{0};
    if (!FromWire(p_Data, N, s_Offset, *this)) {
      throw std::invalid_argument("DnsAnswer: invalid array data");
    }
  }

  /**
   * @brief Construct from C-style array with offset tracking
   * @tparam N Array size (must be >= minimum record size)
   * @param p_Data Array containing DNS resource record data in network byte order
   * @param p_Offset Starting offset (will be updated to point after record)
   * @throws std::invalid_argument if array contains invalid data
   */
  template <size_type N>
  explicit DnsAnswer(const char (&p_Data)[N], size_type &p_Offset) {
    static_assert(N >= 10, "Array must contain at least 10 bytes (minimum record size)");
    if (!FromWire(p_Data, N, p_Offset, *this)) {
      throw std::invalid_argument("DnsAnswer: invalid array data");
    }
  }

  /**
   * @brief Construct from std::array<char> containing raw record data
   * @tparam N Array size (must be >= minimum record size)
   * @param p_Data Array containing DNS resource record data in network byte order
   * @throws std::invalid_argument if array contains invalid data
   * @note Compile-time size validation ensures some safety
   */
  template <size_type N>
  explicit DnsAnswer(const std::array<char, N> &p_Data) {
    static_assert(N >= 10, "Array must contain at least 10 bytes (minimum record size)");
    size_type s_Offset{0};
    if (!FromWire(p_Data.data(), N, s_Offset, *this)) {
      throw std::invalid_argument("DnsAnswer: invalid array data");
    }
  }

  /**
   * @brief Construct from std::array<char> with offset tracking
   * @tparam N Array size (must be >= minimum record size)
   * @param p_Data Array containing DNS resource record data in network byte order
   * @param p_Offset Starting offset (will be updated to point after record)
   * @throws std::invalid_argument if array contains invalid data
   */
  template <size_type N>
  explicit DnsAnswer(const std::array<char, N> &p_Data, size_type &p_Offset) {
    static_assert(N >= 10, "Array must contain at least 10 bytes (minimum record size)");
    if (!FromWire(p_Data.data(), N, p_Offset, *this)) {
      throw std::invalid_argument("DnsAnswer: invalid array data");
    }
  }

  /**
   * @brief Construct from std::array<unsigned char> containing raw record data
   * @tparam N Array size (must be >= minimum record size)
   * @param p_Data Array containing DNS resource record data in network byte order
   * @throws std::invalid_argument if array contains invalid data
   * @note Compile-time size validation ensures some safety
   */
  template <size_type N>
  explicit DnsAnswer(const std::array<unsigned char, N> &p_Data) {
    static_assert(N >= 10, "Array must contain at least 10 bytes (minimum record size)");
    size_type s_Offset{0};
    if (!FromWire(reinterpret_cast<const char *>(p_Data.data()), N, s_Offset, *this)) {
      throw std::invalid_argument("DnsAnswer: invalid array data");
    }
  }

  /**
   * @brief Construct from std::array<unsigned char> with offset tracking
   * @tparam N Array size (must be >= minimum record size)
   * @param p_Data Array containing DNS resource record data in network byte order
   * @param p_Offset Starting offset (will be updated to point after record)
   * @throws std::invalid_argument if array contains invalid data
   */
  template <size_type N>
  explicit DnsAnswer(const std::array<unsigned char, N> &p_Data, size_type &p_Offset) {
    static_assert(N >= 10, "Array must contain at least 10 bytes (minimum record size)");
    if (!FromWire(reinterpret_cast<const char *>(p_Data.data()), N, p_Offset, *this)) {
      throw std::invalid_argument("DnsAnswer: invalid array data");
    }
  }

  /**
   * @brief Construct resource record with specific field values
   * @param p_Name Domain name labels
   * @param p_Type Record type
   * @param p_Class Record class
   * @param p_Ttl Time-to-live in seconds
   * @param p_RData Resource data
   */
  explicit DnsAnswer(std::vector<std::string> p_Name, uint16_t p_Type, uint16_t p_Class, uint32_t p_Ttl, std::vector<char> p_RData);

  /**
   * @brief Construct resource record with specific field values
   * @param p_Name Domain name string (e.g., "www.example.com")
   * @param p_Type Record type
   * @param p_Class Record class
   * @param p_Ttl Time-to-live in seconds
   * @param p_RData Resource data
   */
  explicit DnsAnswer(const std::string &p_Name, uint16_t p_Type, uint16_t p_Class, uint32_t p_Ttl, std::vector<char> p_RData);

  /**
   * @brief Create A record with IPv4 address
   * @param p_Name Domain name
   * @param p_Ipv4Address IPv4 address as string (e.g., "192.168.1.1")
   * @param p_Ttl Time-to-live in seconds (default: 300)
   * @return DnsAnswer configured as A record
   */
  [[nodiscard]] static DnsAnswer MakeARecord(const std::string &p_Name, const std::string &p_Ipv4Address, uint32_t p_Ttl = 300);

  /**
   * @brief Create AAAA record with IPv6 address
   * @param p_Name Domain name
   * @param p_Ipv6Address IPv6 address as string (e.g., "2001:db8::1")
   * @param p_Ttl Time-to-live in seconds (default: 300)
   * @return DnsAnswer configured as AAAA record
   */
  [[nodiscard]] static DnsAnswer MakeAaaaRecord(const std::string &p_Name, const std::string &p_Ipv6Address, uint32_t p_Ttl = 300);

  /**
   * @brief Create CNAME record
   * @param p_Name Domain name
   * @param p_CanonicalName Canonical domain name
   * @param p_Ttl Time-to-live in seconds (default: 300)
   * @return DnsAnswer configured as CNAME record
   */
  [[nodiscard]] static DnsAnswer MakeCnameRecord(const std::string &p_Name, const std::string &p_CanonicalName, uint32_t p_Ttl = 300);

  /**
   * @brief Create MX record
   * @param p_Name Domain name
   * @param p_MailServer Mail server domain name
   * @param p_Priority Priority (lower values have higher priority)
   * @param p_Ttl Time-to-live in seconds (default: 300)
   * @return DnsAnswer configured as MX record
   */
  [[nodiscard]] static DnsAnswer MakeMxRecord(const std::string &p_Name, const std::string &p_MailServer, uint16_t p_Priority, uint32_t p_Ttl = 300);

  /**
   * @brief Create TXT record
   * @param p_Name Domain name
   * @param p_TextData Text data
   * @param p_Ttl Time-to-live in seconds (default: 300)
   * @return DnsAnswer configured as TXT record
   */
  [[nodiscard]] static DnsAnswer MakeTxtRecord(const std::string &p_Name, const std::string &p_TextData, uint32_t p_Ttl = 300);

  /**
   * @brief Create PTR record
   * @param p_Name Reverse DNS name (e.g., "1.1.168.192.in-addr.arpa")
   * @param p_TargetName Target domain name
   * @param p_Ttl Time-to-live in seconds (default: 300)
   * @return DnsAnswer configured as PTR record
   */
  [[nodiscard]] static DnsAnswer MakePtrRecord(const std::string &p_Name, const std::string &p_TargetName, uint32_t p_Ttl = 300);

  /**
   * @brief Create NS record
   * @param p_Name Domain name
   * @param p_NameServer Name server domain name
   * @param p_Ttl Time-to-live in seconds (default: 86400)
   * @return DnsAnswer configured as NS record
   */
  [[nodiscard]] static DnsAnswer MakeNsRecord(const std::string &p_Name, const std::string &p_NameServer, uint32_t p_Ttl = 86400);
  /// @}

  /// @name Field Getters
  /// @{

  /**
   * @brief Get the domain name labels
   * @return Const reference to vector of domain name labels
   * @note Labels are stored without the trailing dot
   * @note Example: "www.example.com" returns {"www", "example", "com"}
   */
  [[nodiscard]] const std::vector<std::string> &Name() const noexcept;

  /**
   * @brief Get the record type
   * @param p_Raw If true, returns raw network byte order; if false, converts to host order
   * @return 16-bit record type (1=A, 2=NS, 5=CNAME, 15=MX, 28=AAAA, etc.)
   */
  [[nodiscard]] uint16_t Type(bool p_Raw = false) const noexcept;

  /**
   * @brief Get the record class
   * @param p_Raw If true, returns raw network byte order; if false, converts to host order
   * @return 16-bit record class (1=Internet, 3=Chaos, 4=Hesiod)
   */
  [[nodiscard]] uint16_t Rclass(bool p_Raw = false) const noexcept;

  /**
   * @brief Get the time-to-live
   * @param p_Raw If true, returns raw network byte order; if false, converts to host order
   * @return 32-bit TTL value in seconds
   */
  [[nodiscard]] uint32_t Ttl(bool p_Raw = false) const noexcept;

  /**
   * @brief Get the resource data length
   * @param p_Raw If true, returns raw network byte order; if false, converts to host order
   * @return 16-bit length of the resource data in bytes
   */
  [[nodiscard]] uint16_t Rdlength(bool p_Raw = false) const noexcept;

  /**
   * @brief Get the resource data
   * @return Const reference to vector containing raw resource data
   */
  [[nodiscard]] const std::vector<char> &Rdata() const noexcept;

  /**
   * @brief Get the full domain name as a string
   * @return Domain name with dots between labels (e.g., "www.example.com")
   * @note Does not include trailing dot
   */
  [[nodiscard]] std::string NameAsString() const;

  /**
   * @brief Get the full qualified domain name (FQDN) as a string
   * @return Domain name with trailing dot (e.g., "www.example.com.")
   */
  [[nodiscard]] std::string Fqdn() const;

  /**
   * @brief Get resource data as IPv4 address string (for A records)
   * @return IPv4 address string (e.g., "192.168.1.1")
   * @throws std::invalid_argument if not an A record or invalid data
   */
  [[nodiscard]] std::string RdataAsIpv4() const;

  /**
   * @brief Get resource data as IPv6 address string (for AAAA records)
   * @return IPv6 address string (e.g., "2001:db8::1")
   * @throws std::invalid_argument if not an AAAA record or invalid data
   */
  [[nodiscard]] std::string RdataAsIpv6() const;

  /**
   * @brief Get resource data as domain name string (for CNAME/NS/PTR records)
   * @return Domain name string
   * @throws std::invalid_argument if not a domain name record type
   */
  [[nodiscard]] std::string RdataAsDomainName() const;

  /**
   * @brief Get resource data as text string (for TXT records)
   * @return Text string
   * @throws std::invalid_argument if not a TXT record
   */
  [[nodiscard]] std::string RdataAsText() const;
  /// @}

  /// @name Field Setters
  /// @{

  /**
   * @brief Set the domain name labels
   * @param p_Labels Vector of domain name labels
   * @note Labels should not contain dots or be empty
   * @note Invalid labels will be skipped
   */
  void SetName(const std::vector<std::string> &p_Labels);

  /**
   * @brief Set domain name from a dot-separated string
   * @param p_Name Domain name string (e.g., "www.example.com")
   * @note Trailing dot is automatically removed
   * @note Empty labels are skipped
   */
  void SetNameFromString(const std::string &p_Name);

  /**
   * @brief Set the record type
   * @param p_Type Record type value
   * @param p_Raw If true, treats p_Type as network byte order; if false, converts from host order
   */
  void SetType(uint16_t p_Type, bool p_Raw = false) noexcept;

  /**
   * @brief Set the record class
   * @param p_Class Record class value
   * @param p_Raw If true, treats p_Class as network byte order; if false, converts from host order
   */
  void SetRclass(uint16_t p_Class, bool p_Raw = false) noexcept;

  /**
   * @brief Set the time-to-live
   * @param p_Ttl TTL value in seconds
   * @param p_Raw If true, treats p_Ttl as network byte order; if false, converts from host order
   */
  void SetTtl(uint32_t p_Ttl, bool p_Raw = false) noexcept;

  /**
   * @brief Set the resource data
   * @param p_Data Resource data bytes
   * @note Automatically updates RDLENGTH field
   */
  void SetRdata(const std::vector<char> &p_Data);

  /**
   * @brief Set resource data from IPv4 address string (for A records)
   * @param p_Ipv4Address IPv4 address string (e.g., "192.168.1.1")
   * @throws std::invalid_argument if invalid IPv4 address format
   */
  void SetRdataIpv4(const std::string &p_Ipv4Address);

  /**
   * @brief Set resource data from IPv6 address string (for AAAA records)
   * @param p_Ipv6Address IPv6 address string (e.g., "2001:db8::1")
   * @throws std::invalid_argument if invalid IPv6 address format
   */
  void SetRdataIpv6(const std::string &p_Ipv6Address);

  /**
   * @brief Set resource data from domain name string (for CNAME/NS/PTR records)
   * @param p_DomainName Domain name string
   */
  void SetRdataDomainName(const std::string &p_DomainName);

  /**
   * @brief Set resource data from text string (for TXT records)
   * @param p_Text Text string
   */
  void SetRdataText(const std::string &p_Text);
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
   * @brief Swap contents with another DnsAnswer
   * @param p_Other The DnsAnswer to swap with
   */
  void swap(DnsAnswer &p_Other) noexcept;

  /**
   * @brief Check if record has no domain name labels
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
   * @brief Clear all fields and reset to defaults
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
   * @brief Check if the resource record is valid according to DNS specifications
   * @return true if all labels are valid and within size limits
   */
  [[nodiscard]] bool Valid() const noexcept;
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
   * @brief Calculate the wire format size of this resource record
   * @return Size in bytes when serialized
   */
  [[nodiscard]] size_type WireSize() const noexcept;

  /**
   * @brief Create resource record from raw network data with validation
   * @param p_Data Pointer to raw data
   * @param p_Size Size of available data
   * @param p_Offset Starting offset (updated to point after record)
   * @param p_OutAnswer Output answer object
   * @return true if successfully parsed and valid
   */
  [[nodiscard]] static bool FromWire(const void *p_Data, size_type p_Size, size_type &p_Offset, DnsAnswer &p_OutAnswer);

  /**
   * @brief Serialize resource record to buffer with size checking
   * @param p_Data Output buffer
   * @param p_BufferSize Size of output buffer
   * @return Number of bytes written, or 0 on error
   */
  [[nodiscard]] size_type ToWire(void *p_Data, size_type p_Size) const noexcept;
  /// @}

  /// @name Comparison Operators
  /// @{

  /**
   * @brief Test equality with another DnsAnswer
   * @param p_Other The DnsAnswer to compare with
   * @return true if all fields are equal
   */
  [[nodiscard]] bool operator==(const DnsAnswer &p_Other) const noexcept;

  /**
   * @brief Test inequality with another DnsAnswer
   * @param p_Other The DnsAnswer to compare with
   * @return true if any field differs
   */
  [[nodiscard]] bool operator!=(const DnsAnswer &p_Other) const noexcept;

  /**
   * @brief Test less-than relationship for ordering
   * @param p_Other The DnsAnswer to compare with
   * @return true if this record is lexicographically less than p_Other
   */
  [[nodiscard]] bool operator<(const DnsAnswer &p_Other) const noexcept;
  /// @}

  /**
   * @brief Stream output operator for debugging and logging
   * @param p_OutputStream Output stream to write to
   * @param p_Answer DnsAnswer to output
   * @return Reference to the output stream
   */
  friend std::ostream &operator<<(std::ostream &p_OutputStream, const DnsAnswer &p_Answer);

private:
  /// @name Private Member Variables
  /// @{
  std::vector<std::string> m_Name_{}; ///< Domain name labels
  uint16_t m_Type_{};                 ///< Record type (network byte order)
  uint16_t m_Class_{};                ///< Record class (network byte order)
  uint32_t m_Ttl_{};                  ///< Time-to-live (network byte order)
  uint16_t m_Rdlength_{};             ///< Resource data length (network byte order)
  std::vector<char> m_Rdata_{};       ///< Resource data
  /// @}

  /**
   * @brief Validate a DNS label according to RFC specifications
   * @param p_Label The label to validate
   * @return true if the label is valid
   */
  [[nodiscard]] static bool IsValidLabel(const std::string &p_Label) noexcept;

  /**
   * @brief Calculate the size needed for NameAsString()
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
   * @brief Encode domain name labels into uncompressed wire format
   * @param p_Labels Labels to encode
   * @param p_Output Output buffer receiving encoded bytes
   */
  static void EncodeDomainLabels(const std::vector<std::string> &p_Labels, std::vector<char> &p_Output);

  /**
   * @brief Decompress RDATA domain names using the full packet buffer
   *
   * For record types that contain domain names in RDATA (NS, CNAME, SOA, PTR, MX, SRV),
   * compression pointers reference offsets in the full original packet. This method
   * resolves those pointers and re-encodes domain names without compression so the
   * resulting RDATA buffer is self-contained.
   *
   * @param p_Data Full packet data (for resolving compression pointers)
   * @param p_Size Full packet size
   * @param p_RdataOffset Offset where RDATA starts in the full packet
   * @param p_TypeHost Record type in host byte order
   * @param p_RData RDATA buffer to decompress in-place
   * @return true if decompression succeeded, false on error or non-applicable type
   */
  static bool DecompressRDATA(const void *p_Data, size_type p_Size, size_type p_RdataOffset, uint16_t p_TypeHost, std::vector<char> &p_RData);

  /**
   * @brief Update RDLENGTH field based on current RDATA size
   */
  void UpdateRDLENGTH() noexcept;
};

/**
 * @brief Non-member swap function for DnsAnswer objects
 * @param p_LeftSide Left-hand side DnsAnswer to swap
 * @param p_RightSide Right-hand side DnsAnswer to swap
 * @note This function enables argument-dependent lookup (ADL) for swap operations
 * @note Provides STL-compatible swap interface for use with algorithms
 * @see std::swap for general swap documentation
 */
void swap(DnsAnswer &p_LeftSide, DnsAnswer &p_RightSide) noexcept;

/**
 * @brief Standard library hash specialization for DnsAnswer
 *
 * This specialization allows DnsAnswer objects to be used as keys in
 * hash-based containers like std::unordered_map and std::unordered_set.
 *
 * @note The hash function combines domain name, type, class, and TTL for good distribution
 * @note Two DnsAnswer objects that compare equal will have the same hash value
 * @note Hash collision resistance is provided by combining multiple fields
 *
 * Example usage:
 * @code
 * std::unordered_map<DnsAnswer, std::string> answerMap;
 * std::unordered_set<DnsAnswer> answerSet;
 * @endcode
 */
namespace std {
template <>
struct hash<DnsAnswer> {
    /**
   * @brief Calculate hash value for a DnsAnswer object
   * @param p_Answer The DnsAnswer object to hash
   * @return Hash value suitable for use in hash containers
   * @note Uses the DnsAnswer::Hash() method for consistent hashing
   * @note Complexity: O(n) where n is the number of labels plus RDATA size
   */
  DnsAnswer::size_type operator()(const DnsAnswer &p_Answer) const noexcept;
};
} // namespace std

#endif // DNS_PACKET_ANSWER_H_
