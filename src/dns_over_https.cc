// Self
#include "dns_over_https.h"

// C

// C++
#include <algorithm> // std::copy, std::shuffle
#include <chrono>    // std::chrono
#include <cstddef>   // std::size_t
#include <cstdint>   // SIZE_MAX
#include <cstdlib>   // std::realloc, std::free
#include <fstream>   // std::ifstream
#include <iterator>  // std::istreambuf_iterator
#include <memory>    // std::unique_ptr
#include <mutex>     // std::lock_guard, std::mutex
#include <random>    // std::random_device
#include <stdexcept> // std::invalid_argument, std::runtime_error
#include <string>    // std::string
#include <vector>    // std::vector

// Other libraries
#include "curl/curl.h"

// This Project's
#include "constants.h"

// Bundled CA certs for platforms without an accessible system cert store
#if defined(__ORBIS__) || defined(__PROSPERO__)
#include "cacert_bundle.h" // cppcheck-suppress missingInclude
#endif

// Logging
#include "libLog.h"

// Banned
#include "banned.h"

namespace {

// Global curl initialization state
bool g_CurlInitialized{false};
std::mutex g_CurlInitMutex{};

// Cleanup class that ensures curl_global_cleanup() is called
class CurlGlobalManager {
public:
  static CurlGlobalManager &GetInstance() {
    static CurlGlobalManager s_Instance;
    return s_Instance;
  }

  // Note: This method is intentionally non-static to maintain singleton pattern
  // and ensure proper lifecycle management with the destructor
  bool Initialize() {
    std::lock_guard<std::mutex> s_Lock(g_CurlInitMutex);
    if (!g_CurlInitialized) {
      CURLcode s_Result{curl_global_init(CURL_GLOBAL_ALL)};
      if (s_Result != CURLE_OK) {
        return false;
      }
      g_CurlInitialized = true;
    }
    return true;
  }

  ~CurlGlobalManager() {
    // No mutex lock during destruction - at static destruction time, the mutex
    // may already be destroyed. Nothing should be racing this destructor.
    if (g_CurlInitialized) {
      curl_global_cleanup();
      g_CurlInitialized = false;
    }
  }

private:
  CurlGlobalManager() = default;
  CurlGlobalManager(const CurlGlobalManager &) = delete;
  CurlGlobalManager &operator=(const CurlGlobalManager &) = delete;
};

} // namespace

DnsOverHttps::DnsOverHttps(const std::string &p_Useragent, const std::vector<std::string> &p_Resolvers, const std::string &p_CacertPath, int p_DohTimeoutMs) : m_RandomEngine_(std::random_device{}()) {

  // Initialize curl globally once using singleton pattern
  if (!CurlGlobalManager::GetInstance().Initialize()) {
    throw std::runtime_error("Failed to initialize libcurl");
  }

  Useragent(p_Useragent);
  Resolvers(p_Resolvers);
  DohTimeoutMs(p_DohTimeoutMs);
  if (!p_CacertPath.empty()) {
    CacertPath(p_CacertPath);
  }
  InitMultiHandle();
}

DnsOverHttps::~DnsOverHttps() {
  CleanupMultiHandle();
}

DnsOverHttps::DnsOverHttps(DnsOverHttps &&other) noexcept : m_Resolvers_(std::move(other.m_Resolvers_)), m_Useragent_(std::move(other.m_Useragent_)), m_HttpMethod_(other.m_HttpMethod_), m_RandomEngine_(std::move(other.m_RandomEngine_)), m_CacertPath_(std::move(other.m_CacertPath_)), m_CacertContent_(std::move(other.m_CacertContent_)), m_DohTimeoutMs_(other.m_DohTimeoutMs_), m_MultiHandle_(other.m_MultiHandle_), m_PostHeaders_(other.m_PostHeaders_), m_GetHeaders_(other.m_GetHeaders_) {
  other.m_MultiHandle_ = nullptr;
  other.m_PostHeaders_ = nullptr;
  other.m_GetHeaders_ = nullptr;
}

DnsOverHttps &DnsOverHttps::operator=(DnsOverHttps &&other) noexcept {
  if (this != &other) {
    CleanupMultiHandle();
    m_Resolvers_ = std::move(other.m_Resolvers_);
    m_Useragent_ = std::move(other.m_Useragent_);
    m_HttpMethod_ = other.m_HttpMethod_;
    m_RandomEngine_ = std::move(other.m_RandomEngine_);
    m_MultiHandle_ = other.m_MultiHandle_;
    m_PostHeaders_ = other.m_PostHeaders_;
    m_GetHeaders_ = other.m_GetHeaders_;
    m_CacertPath_ = std::move(other.m_CacertPath_);
    m_CacertContent_ = std::move(other.m_CacertContent_);
    m_DohTimeoutMs_ = other.m_DohTimeoutMs_;
    other.m_MultiHandle_ = nullptr;
    other.m_PostHeaders_ = nullptr;
    other.m_GetHeaders_ = nullptr;
  }
  return *this;
}

void DnsOverHttps::InitMultiHandle() {
  m_MultiHandle_ = curl_multi_init();
  if (!m_MultiHandle_) {
    throw std::runtime_error("Failed to create CURL multi handle");
  }

  // Enable HTTP/2 multiplexing on the multi handle
  curl_multi_setopt(m_MultiHandle_, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);

  // Build POST headers (Content-Type + Accept per RFC 8484 §4.1)
  struct curl_slist *s_Tmp{curl_slist_append(nullptr, "Content-Type: application/dns-message")};
  if (!s_Tmp) {
    curl_multi_cleanup(m_MultiHandle_);
    m_MultiHandle_ = nullptr;
    throw std::runtime_error("Failed to build CURL headers");
  }
  m_PostHeaders_ = curl_slist_append(s_Tmp, "Accept: application/dns-message");
  if (!m_PostHeaders_) {
    curl_slist_free_all(s_Tmp);
    curl_multi_cleanup(m_MultiHandle_);
    m_MultiHandle_ = nullptr;
    throw std::runtime_error("Failed to build CURL headers");
  }

  // Build GET headers (Accept only - no Content-Type for bodyless requests)
  m_GetHeaders_ = curl_slist_append(nullptr, "Accept: application/dns-message");
  if (!m_GetHeaders_) {
    curl_slist_free_all(m_PostHeaders_);
    m_PostHeaders_ = nullptr;
    curl_multi_cleanup(m_MultiHandle_);
    m_MultiHandle_ = nullptr;
    throw std::runtime_error("Failed to build CURL headers");
  }
}

void DnsOverHttps::CleanupMultiHandle() {
  if (m_PostHeaders_) {
    curl_slist_free_all(m_PostHeaders_);
    m_PostHeaders_ = nullptr;
  }
  if (m_GetHeaders_) {
    curl_slist_free_all(m_GetHeaders_);
    m_GetHeaders_ = nullptr;
  }
  if (m_MultiHandle_) {
    curl_multi_cleanup(m_MultiHandle_);
    m_MultiHandle_ = nullptr;
  }
}

const std::string &DnsOverHttps::Useragent() const {
  return m_Useragent_;
}

const std::vector<std::string> &DnsOverHttps::Resolvers() const {
  return m_Resolvers_;
}

void DnsOverHttps::Useragent(const std::string &p_Useragent) {
  if (p_Useragent.empty()) {
    throw std::invalid_argument("User agent cannot be empty");
  }
  m_Useragent_ = p_Useragent;
}

void DnsOverHttps::Resolvers(std::vector<std::string> p_Resolvers) {
  if (p_Resolvers.empty()) {
    throw std::invalid_argument("p_Resolvers argument must contain at least one resolver");
  }
  m_Resolvers_ = std::move(p_Resolvers);
}

DnsOverHttps::HttpMethod DnsOverHttps::Method() const {
  return m_HttpMethod_;
}

void DnsOverHttps::Method(HttpMethod p_Method) {
  m_HttpMethod_ = p_Method;
}

int DnsOverHttps::DohTimeoutMs() const {
  return m_DohTimeoutMs_;
}

void DnsOverHttps::DohTimeoutMs(int p_TimeoutMs) {
  if (p_TimeoutMs < 100) {
    p_TimeoutMs = 100;
  }
  if (p_TimeoutMs > 60000) {
    p_TimeoutMs = 60000;
  }
  m_DohTimeoutMs_ = p_TimeoutMs;
}

const std::string &DnsOverHttps::CacertPath() const {
  return m_CacertPath_;
}

void DnsOverHttps::CacertPath(const std::string &p_Path) {
  if (p_Path.empty()) {
    m_CacertPath_.clear();
#if defined(__ORBIS__) || defined(__PROSPERO__)
    m_CacertContent_.clear();
#endif
    return;
  }

  // Same CA bundle path already configured; avoid duplicate startup logging.
  if (p_Path == m_CacertPath_) {
    return;
  }

  std::ifstream s_File(p_Path, std::ios::binary);
  if (!s_File) {
    logKernel(LL_Warn, "DoH: CA cert file not found at %s - using platform default", p_Path.c_str());
    m_CacertPath_.clear();
#if defined(__ORBIS__) || defined(__PROSPERO__)
    m_CacertContent_.clear();
#endif
    return;
  }

#if defined(__ORBIS__) || defined(__PROSPERO__)
  m_CacertContent_.assign(std::istreambuf_iterator<char>(s_File), std::istreambuf_iterator<char>());
  if (m_CacertContent_.empty()) {
    logKernel(LL_Warn, "DoH: CA cert file is empty at %s - using embedded fallback", p_Path.c_str());
    m_CacertPath_.clear();
    return;
  }
#endif

  m_CacertPath_ = p_Path;
  logKernel(LL_Info, "DoH: using CA cert bundle from %s", p_Path.c_str());
}

CURL *DnsOverHttps::CreateEasyHandle(const std::string &p_Url, const char *p_Data, std::size_t p_DataLen, CurlResponse *p_Response, long p_TimeoutMs) const {
  CURL *s_Easy{curl_easy_init()};
  if (!s_Easy) {
    return nullptr;
  }

  // Convert ms to seconds, minimum 1 second
  long s_TimeoutSec{std::max(1L, p_TimeoutMs / 1000)};
  long s_ConnectTimeoutSec{std::max(1L, std::min(5L, s_TimeoutSec / 2))};

  curl_easy_setopt(s_Easy, CURLOPT_URL, p_Url.c_str());
  curl_easy_setopt(s_Easy, CURLOPT_WRITEFUNCTION, WriteCallback);
  curl_easy_setopt(s_Easy, CURLOPT_WRITEDATA, static_cast<void *>(p_Response));
  curl_easy_setopt(s_Easy, CURLOPT_USERAGENT, Useragent().c_str());
  curl_easy_setopt(s_Easy, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2);
  curl_easy_setopt(s_Easy, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(s_Easy, CURLOPT_MAXREDIRS, 3L);
  curl_easy_setopt(s_Easy, CURLOPT_TIMEOUT, s_TimeoutSec);
  curl_easy_setopt(s_Easy, CURLOPT_CONNECTTIMEOUT, s_ConnectTimeoutSec);
  curl_easy_setopt(s_Easy, CURLOPT_TCP_KEEPALIVE, 1L);

#if defined(__ORBIS__) || defined(__PROSPERO__)
  // On Orbis/Prospero the system cert store is inaccessible; use either the
  // user-supplied PEM bundle loaded from disk, or the Mozilla CA bundle that
  // was compiled into the binary as a fallback.
  {
    struct curl_blob s_CertBlob {};
    if (!m_CacertContent_.empty()) {
      s_CertBlob.data = const_cast<char *>(m_CacertContent_.data());
      s_CertBlob.len = m_CacertContent_.size();
    } else {
      s_CertBlob.data = const_cast<unsigned char *>(g_CacertBundle);
      s_CertBlob.len = g_CacertBundleLen;
    }
    s_CertBlob.flags = CURL_BLOB_NOCOPY;
    curl_easy_setopt(s_Easy, CURLOPT_CAINFO_BLOB, &s_CertBlob);
  }
#else
  if (!m_CacertPath_.empty()) {
    curl_easy_setopt(s_Easy, CURLOPT_CAINFO, m_CacertPath_.c_str());
  }
  // Otherwise let curl use the system certificate store
#endif

  if (m_HttpMethod_ == HttpMethod::POST) {
    curl_easy_setopt(s_Easy, CURLOPT_HTTPHEADER, m_PostHeaders_);
    curl_easy_setopt(s_Easy, CURLOPT_POSTFIELDSIZE, static_cast<long>(p_DataLen));
    curl_easy_setopt(s_Easy, CURLOPT_POSTFIELDS, p_Data);
  } else {
    curl_easy_setopt(s_Easy, CURLOPT_HTTPHEADER, m_GetHeaders_);
    curl_easy_setopt(s_Easy, CURLOPT_HTTPGET, 1L);
  }

  return s_Easy;
}

DnsOverHttps::ResolveResult DnsOverHttps::PerformSingleTransfer(CURL *p_Easy) {
  CURLMcode s_Mc{curl_multi_add_handle(m_MultiHandle_, p_Easy)};
  if (s_Mc != CURLM_OK) {
    logKernel(LL_Error, "DoH Resolve: curl_multi_add_handle failed: %s", curl_multi_strerror(s_Mc));
    return ResolveResult::CurlError;
  }

  int s_StillRunning{0};
  do {
    s_Mc = curl_multi_perform(m_MultiHandle_, &s_StillRunning);
    if (s_Mc != CURLM_OK) {
      logKernel(LL_Error, "DoH Resolve: curl_multi_perform failed: %s", curl_multi_strerror(s_Mc));
      curl_multi_remove_handle(m_MultiHandle_, p_Easy);
      return ResolveResult::CurlError;
    }
    if (s_StillRunning) {
      s_Mc = curl_multi_wait(m_MultiHandle_, nullptr, 0, 1000, nullptr);
      if (s_Mc != CURLM_OK) {
        logKernel(LL_Error, "DoH Resolve: curl_multi_wait failed: %s", curl_multi_strerror(s_Mc));
        curl_multi_remove_handle(m_MultiHandle_, p_Easy);
        return ResolveResult::CurlError;
      }
    }
  } while (s_StillRunning);

  // Read transfer result
  ResolveResult s_Result{ResolveResult::CurlError};
  int s_MsgsLeft{0};
  const CURLMsg *s_Msg;
  while ((s_Msg = curl_multi_info_read(m_MultiHandle_, &s_MsgsLeft))) {
    if (s_Msg->msg == CURLMSG_DONE) {
      if (s_Msg->data.result != CURLE_OK) {
        logKernel(LL_Warn, "DoH transfer failed: %s", curl_easy_strerror(s_Msg->data.result));
        s_Result = ResolveResult::CurlError;
      } else {
        long s_HttpCode{0};
        curl_easy_getinfo(p_Easy, CURLINFO_RESPONSE_CODE, &s_HttpCode);
        s_Result = HttpCodeToResult(s_HttpCode);
        if (s_Result != ResolveResult::Success) {
          logKernel(LL_Warn, "DoH server returned HTTP %ld", s_HttpCode);
        }
      }
    }
  }

  curl_multi_remove_handle(m_MultiHandle_, p_Easy);
  return s_Result;
}

DnsOverHttps::ResolveResult DnsOverHttps::Resolve(const char *p_Data, std::size_t p_DataLength, std::vector<char> &p_Output) {
  if (p_Data == nullptr || p_DataLength == 0) {
    logKernel(LL_Error, "DoH Resolve: Invalid input data (null pointer or zero length)");
    return ResolveResult::InvalidInput;
  }

  if (!m_MultiHandle_) {
    logKernel(LL_Error, "DoH Resolve: Multi handle not initialized");
    return ResolveResult::CurlError;
  }

  // For GET, pre-compute the base64url-encoded query (RFC 8484 §4.1)
  std::string s_Base64Query;
  if (m_HttpMethod_ == HttpMethod::GET) {
    s_Base64Query = Base64UrlEncode(p_Data, p_DataLength);
  }

  // Try resolvers in shuffled order for failover
  std::vector<std::string> s_Resolvers{ShuffledResolvers()};
  ResolveResult s_LastResult{ResolveResult::CurlError};
  std::chrono::steady_clock::time_point s_StartTime{std::chrono::steady_clock::now()};

  for (const std::string &s_ResolverUrl : s_Resolvers) {
    // Check remaining timeout budget
    std::chrono::milliseconds::rep s_Elapsed{std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - s_StartTime).count()};
    long s_RemainingMs{static_cast<long>(m_DohTimeoutMs_) - static_cast<long>(s_Elapsed)};
    if (s_RemainingMs <= 0) {
      logKernel(LL_Warn, "DoH timeout budget exhausted after %ld ms", static_cast<long>(s_Elapsed));
      break;
    }

    // Build URL (append ?dns= query parameter for GET)
    std::string s_Url{s_ResolverUrl};
    if (m_HttpMethod_ == HttpMethod::GET) {
      s_Url += (s_ResolverUrl.find('?') != std::string::npos) ? "&dns=" : "?dns=";
      s_Url += s_Base64Query;
    }

    // Prepare response buffer
    CurlResponse s_Buffer{};
    s_Buffer.memory = nullptr;
    s_Buffer.size = 0;

    // Create and configure easy handle for this attempt
    CURL *s_Easy{CreateEasyHandle(s_Url, p_Data, p_DataLength, &s_Buffer, s_RemainingMs)};
    if (!s_Easy) {
      logKernel(LL_Error, "DoH Resolve: Failed to create easy handle for %s", s_ResolverUrl.c_str());
      continue;
    }

    // Run transfer via multi interface (connection pooling + HTTP/2 multiplexing)
    ResolveResult s_Result{PerformSingleTransfer(s_Easy)};

    // Clean up easy handle (multi handle keeps connections pooled)
    curl_easy_cleanup(s_Easy);

    // Manage response buffer lifetime
    std::unique_ptr<unsigned char, decltype(&std::free)> s_BufferCleanup(s_Buffer.memory, std::free);

    s_LastResult = s_Result;
    if (s_Result == ResolveResult::Success) {
      if (s_Buffer.size > 0 && s_Buffer.memory) {
        p_Output.assign(s_Buffer.memory, s_Buffer.memory + s_Buffer.size);
      }
      return ResolveResult::Success;
    }

    // Non-retryable errors (client-side issues) stop immediately
    if (!IsRetryable(s_Result)) {
      return s_Result;
    }

    logKernel(LL_Warn, "DoH resolver %s failed, trying next resolver", s_ResolverUrl.c_str());
  }

  logKernel(LL_Error, "DoH Resolve: All %zu resolver(s) exhausted", s_Resolvers.size());
  return s_LastResult;
}

std::vector<std::string> DnsOverHttps::ShuffledResolvers() {
  std::vector<std::string> s_Copy{Resolvers()};
  if (s_Copy.size() > 1) {
    std::lock_guard<std::mutex> s_Lock(m_RandomMutex_);
    std::shuffle(s_Copy.begin(), s_Copy.end(), m_RandomEngine_);
  }
  return s_Copy;
}

bool DnsOverHttps::IsRetryable(ResolveResult p_Result) {
  switch (p_Result) {
  case ResolveResult::CurlError:
  case ResolveResult::InternalServerError:
  case ResolveResult::BadGateway:
  case ResolveResult::GatewayTimeout:
  case ResolveResult::TooManyRequests:
    return true;
  default:
    return false;
  }
}

DnsOverHttps::ResolveResult DnsOverHttps::HttpCodeToResult(long p_HttpCode) {
  switch (p_HttpCode) {
  case 200:
    return ResolveResult::Success;
  case 400:
    return ResolveResult::BadRequest;
  case 413:
    return ResolveResult::PayloadTooLarge;
  case 415:
    return ResolveResult::UnsupportedMediaType;
  case 429:
    return ResolveResult::TooManyRequests;
  case 500:
    return ResolveResult::InternalServerError;
  case 501:
    return ResolveResult::NotImplemented;
  case 502:
    return ResolveResult::BadGateway;
  case 504:
    return ResolveResult::GatewayTimeout;
  default:
    return ResolveResult::UnknownHttpError;
  }
}

std::string DnsOverHttps::Base64UrlEncode(const char *p_Data, std::size_t p_Length) {
  static constexpr char s_Table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string s_Result;
  s_Result.reserve(((p_Length + 2) / 3) * 4);

  const unsigned char *s_Input{reinterpret_cast<const unsigned char *>(p_Data)};

  for (std::size_t l_Index{0}; l_Index < p_Length; l_Index += 3) {
    unsigned int s_N{static_cast<unsigned int>(s_Input[l_Index]) << 16};
    if (l_Index + 1 < p_Length) {
      s_N |= static_cast<unsigned int>(s_Input[l_Index + 1]) << 8;
    }
    if (l_Index + 2 < p_Length) {
      s_N |= static_cast<unsigned int>(s_Input[l_Index + 2]);
    }

    s_Result += s_Table[(s_N >> 18) & 0x3F];
    s_Result += s_Table[(s_N >> 12) & 0x3F];
    if (l_Index + 1 < p_Length) {
      s_Result += s_Table[(s_N >> 6) & 0x3F];
    }
    if (l_Index + 2 < p_Length) {
      s_Result += s_Table[s_N & 0x3F];
    }
  }

  return s_Result;
}

std::size_t DnsOverHttps::WriteCallback(void *p_Pointer, std::size_t p_Size, std::size_t p_DataSize, void *p_Userdata) {
  // Check for overflow
  if (p_Size > 0 && p_DataSize > SIZE_MAX / p_Size) {
    return 0; // Signal error to curl
  }

  std::size_t s_RealSize{p_Size * p_DataSize};
  CurlResponse *s_Response{static_cast<CurlResponse *>(p_Userdata)};

  // Cap response size to prevent unbounded allocation from a malicious server
  if (s_Response->size + s_RealSize > Constants::Dns::MAX_DOH_RESPONSE_SIZE) {
    return 0; // Signal error to curl
  }

  // Check for overflow in realloc size calculation
  if (s_Response->size > SIZE_MAX - s_RealSize - 1) {
    return 0; // Signal error to curl
  }

  unsigned char *s_NewMemory{static_cast<unsigned char *>(std::realloc(s_Response->memory, s_Response->size + s_RealSize + 1))}; // +1 for null terminator

  if (s_NewMemory == nullptr) {
    return 0;
  }

  s_Response->memory = s_NewMemory;
  std::copy(static_cast<const unsigned char *>(p_Pointer), static_cast<const unsigned char *>(p_Pointer) + s_RealSize, &(s_Response->memory[s_Response->size]));
  s_Response->size += s_RealSize;
  s_Response->memory[s_Response->size] = '\0';

  return s_RealSize;
}
