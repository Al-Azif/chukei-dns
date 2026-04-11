/** @file dns_over_https.h
 *  @brief DNS-over-HTTPS client with connection pooling and automatic resolver failover.
 */

#ifndef DNS_OVER_HTTPS_H_
#define DNS_OVER_HTTPS_H_

#include <cstddef> // std::size_t
#include <mutex>   // std::mutex
#include <random>  // std::mt19937
#include <string>  // std::string
#include <vector>  // std::vector

// Forward declare CURL opaque types to avoid including curl headers here
typedef void CURL;
typedef void CURLM;
struct curl_slist;

/**
 * @brief DNS-over-HTTPS resolution client using libcurl (RFC 8484)
 *
 * Support both POST and GET methods, HTTP/2 multiplexing, and automatic
 * failover across a shuffled list of resolver URLs. Manage a persistent
 * CURL multi handle for connection reuse.
 *
 * @note Non-copyable because it owns a CURL multi handle and header lists.
 */
class DnsOverHttps {
public:
  // clang-format off

  /** @brief Enumeration of possible outcomes of a DoH resolution attempt. */
  enum class ResolveResult : int {
    Success = 0,
    InvalidInput = -1,
    CurlError = -2,            // CURL library error
    BadRequest = -3,           // HTTP 400: Invalid DNS request message
    PayloadTooLarge = -4,      // HTTP 413: DNS query too large
    UnsupportedMediaType = -5, // HTTP 415: Unsupported content type
    TooManyRequests = -6,      // HTTP 429: Rate limited
    InternalServerError = -7,  // HTTP 500: Internal server error
    NotImplemented = -8,       // HTTP 501: Must be GET or POST
    BadGateway = -9,           // HTTP 502: DoH service could not contact DNS resolvers
    GatewayTimeout = -10,      // HTTP 504: Resolver timeout
    UnknownHttpError = -11     // Other HTTP error codes
  };

  // clang-format on

  /** @brief HTTP method selection for DoH wire-format queries. */
  enum class HttpMethod : int { POST = 0, GET = 1 };

  /**
   * @brief Construct a DoH client with the given user-agent and resolver list
   * @param p_Useragent HTTP User-Agent string for outgoing requests.
   * @param p_Resolvers One or more HTTPS resolver URLs.
   * @param p_CacertPath Optional path to a PEM CA bundle for TLS verification.
   *        If empty (default), the platform default is used: system cert store on
   *        PC, or the embedded Mozilla CA bundle on Orbis/Prospero.
   * @throws std::runtime_error if libcurl initialization fails.
   * @throws std::invalid_argument if p_Useragent is empty or p_Resolvers is empty.
   */
  DnsOverHttps(const std::string &p_Useragent, const std::vector<std::string> &p_Resolvers, const std::string &p_CacertPath = "", int p_DohTimeoutMs = 15000);

  /** @brief Destructor; release CURL handles and header lists. */
  ~DnsOverHttps();

  // Non-copyable (owns CURL multi handle)
  DnsOverHttps(const DnsOverHttps &) = delete;
  DnsOverHttps &operator=(const DnsOverHttps &) = delete;

  // Moveable
  DnsOverHttps(DnsOverHttps &&other) noexcept;
  DnsOverHttps &operator=(DnsOverHttps &&other) noexcept;

  /** @brief Get the current User-Agent string. */
  [[nodiscard]] const std::string &Useragent() const;
  /** @brief Get the configured resolver URL list. */
  [[nodiscard]] const std::vector<std::string> &Resolvers() const;
  /** @brief Get the HTTP method used for queries. */
  [[nodiscard]] HttpMethod Method() const;

  /** @brief Set the User-Agent string. */
  void Useragent(const std::string &p_Useragent);
  /** @brief Replace the resolver URL list. */
  void Resolvers(std::vector<std::string> p_Resolvers);
  /** @brief Set the HTTP method (POST or GET). */
  void Method(HttpMethod p_Method);

  /** @brief Get the total timeout budget in milliseconds for all resolver attempts. */
  [[nodiscard]] int DohTimeoutMs() const;

  /** @brief Set the total timeout budget in milliseconds (minimum 100, maximum 60000). */
  void DohTimeoutMs(int p_TimeoutMs);

  /** @brief Get the CA certificate bundle path. */
  [[nodiscard]] const std::string &CacertPath() const;
  /**
   * @brief Set the CA certificate bundle path for TLS peer verification
   *
   * On Orbis/Prospero: attempts to load the PEM file into memory immediately.
   * If the file cannot be read, a warning is logged and the embedded fallback
   * bundle compiled into the binary will be used instead.
   *
   * On other platforms: stores the path for use with CURLOPT_CAINFO;
   * if empty, curl uses the system certificate store.
   *
   * @param p_Path Filesystem path to a PEM CA bundle, or empty string for defaults.
   */
  void CacertPath(const std::string &p_Path);

  /**
   * @brief Resolve a DNS query via HTTPS
   *
   * Send the wire-format query to resolvers in shuffled order, retrying
   * on transient failures, and write the raw wire-format response into
   * p_Output on success.
   *
   * @param p_Data       Pointer to the DNS wire-format query.
   * @param p_DataLength Length of the query in bytes.
   * @param p_Output     Output vector receiving the wire-format response.
   * @return ResolveResult indicating success or the specific failure reason.
   */
  [[nodiscard]] ResolveResult Resolve(const char *p_Data, std::size_t p_DataLength, std::vector<char> &p_Output);

  /**
   * @brief Encode binary data using RFC 4648 base64url without padding
   *
   * Used for GET-method DoH queries per RFC 8484 section 4.1.
   *
   * @param p_Data   Pointer to raw binary data.
   * @param p_Length Length of the data in bytes.
   * @return Base64url-encoded string without padding characters.
   */
  [[nodiscard]] static std::string Base64UrlEncode(const char *p_Data, std::size_t p_Length);

private:
  struct CurlResponse {
    unsigned char *memory;
    std::size_t size;
  };

  std::vector<std::string> m_Resolvers_{};
  std::string m_Useragent_{};
  HttpMethod m_HttpMethod_{HttpMethod::POST};
  std::mt19937 m_RandomEngine_{};
  std::mutex m_RandomMutex_{};

  std::string m_CacertPath_{};
  std::vector<char> m_CacertContent_{}; // File-loaded PEM bundle (Orbis/Prospero)
  int m_DohTimeoutMs_{15000};

  // Persistent CURL multi handle - manages connection pool and HTTP/2 multiplexing
  CURLM *m_MultiHandle_{nullptr};
  curl_slist *m_PostHeaders_{nullptr};
  curl_slist *m_GetHeaders_{nullptr};

  void InitMultiHandle();
  void CleanupMultiHandle();

  CURL *CreateEasyHandle(const std::string &p_Url, const char *p_Data, std::size_t p_DataLen, CurlResponse *p_Response, long p_TimeoutMs) const;
  ResolveResult PerformSingleTransfer(CURL *p_Easy);
  std::vector<std::string> ShuffledResolvers();

  static bool IsRetryable(ResolveResult p_Result);
  static ResolveResult HttpCodeToResult(long p_HttpCode);
  static std::size_t WriteCallback(void *p_Pointer, std::size_t p_Size, std::size_t p_DataSize, void *p_Userdata);
};

#endif
