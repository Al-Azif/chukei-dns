// Minimal test framework - no external dependencies
// Compatible with C++17, PS4 (Orbis), PS5 (Prospero), and PC
#ifndef TEST_FRAMEWORK_H_
#define TEST_FRAMEWORK_H_

#include <cstdio>
#include <cstdlib>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

namespace TestFramework {

struct TestCase {
  std::string m_Name_;
  std::function<void()> m_Func_;
};

struct TestResult {
  int m_Passed_{0};
  int m_Failed_{0};
  int m_Total_{0};
  std::vector<std::string> m_Failures_;
};

inline TestResult &GetResult() {
  static TestResult s_Result;
  return s_Result;
}

inline std::vector<TestCase> &GetTests() {
  static std::vector<TestCase> s_Tests;
  return s_Tests;
}

inline int RegisterTest(const char *p_Name, std::function<void()> p_Func) {
  GetTests().push_back({p_Name, std::move(p_Func)});
  return 0;
}

inline int RunAll() {
  std::vector<TestCase> &s_Tests = GetTests();
  TestResult &s_Result = GetResult();
  s_Result = {};

  std::printf("Running %zu test(s)...\n", s_Tests.size());
  std::printf("========================================\n");

  for (TestCase &l_TestCase : s_Tests) {
    s_Result.m_Total_++;
    try {
      l_TestCase.m_Func_();
      s_Result.m_Passed_++;
      std::printf("  [PASS] %s\n", l_TestCase.m_Name_.c_str());
    } catch (const std::exception &e) {
      s_Result.m_Failed_++;
      std::string s_Msg{l_TestCase.m_Name_ + ": " + e.what()};
      s_Result.m_Failures_.push_back(s_Msg);
      std::printf("  [FAIL] %s: %s\n", l_TestCase.m_Name_.c_str(), e.what());
    } catch (...) {
      s_Result.m_Failed_++;
      std::string s_Msg{l_TestCase.m_Name_ + ": unknown exception"};
      s_Result.m_Failures_.push_back(s_Msg);
      std::printf("  [FAIL] %s: unknown exception\n", l_TestCase.m_Name_.c_str());
    }
  }

  std::printf("========================================\n");
  std::printf("Results: %d passed, %d failed, %d total\n", s_Result.m_Passed_, s_Result.m_Failed_, s_Result.m_Total_);

  if (!s_Result.m_Failures_.empty()) {
    std::printf("\nFailures:\n");
    for (std::string &l_Failure : s_Result.m_Failures_) {
      std::printf("  - %s\n", l_Failure.c_str());
    }
  }

  return s_Result.m_Failed_ > 0 ? 1 : 0;
}

class AssertionError : public std::runtime_error {
public:
  explicit AssertionError(const std::string &msg) : std::runtime_error(msg) {
  }
};

} // namespace TestFramework

#define TEST(name)                                                              \
  static void test_##name();                                                    \
  static int test_reg_##name = TestFramework::RegisterTest(#name, test_##name); \
  static void test_##name()

#define ASSERT_TRUE(expr)                                                                                                             \
  do {                                                                                                                                \
    if (!(expr)) {                                                                                                                    \
      throw TestFramework::AssertionError(std::string(__FILE__) + ":" + std::to_string(__LINE__) + " ASSERT_TRUE(" #expr ") failed"); \
    }                                                                                                                                 \
  } while (0)

#define ASSERT_FALSE(expr) ASSERT_TRUE(!(expr))

#define ASSERT_EQ(a, b)                                                                                                                  \
  do {                                                                                                                                   \
    if ((a) != (b)) {                                                                                                                    \
      throw TestFramework::AssertionError(std::string(__FILE__) + ":" + std::to_string(__LINE__) + " ASSERT_EQ(" #a ", " #b ") failed"); \
    }                                                                                                                                    \
  } while (0)

#define ASSERT_NE(a, b)                                                                                                                  \
  do {                                                                                                                                   \
    if ((a) == (b)) {                                                                                                                    \
      throw TestFramework::AssertionError(std::string(__FILE__) + ":" + std::to_string(__LINE__) + " ASSERT_NE(" #a ", " #b ") failed"); \
    }                                                                                                                                    \
  } while (0)

#define ASSERT_THROW(expr, exception_type)                                                                                                                                 \
  do {                                                                                                                                                                     \
    bool s_Caught = false;                                                                                                                                                 \
    try {                                                                                                                                                                  \
      IGNORE_NODISCARD(expr);                                                                                                                                              \
    } catch (const exception_type &) {                                                                                                                                     \
      s_Caught = true;                                                                                                                                                     \
    } catch (...) {                                                                                                                                                        \
    }                                                                                                                                                                      \
    if (!s_Caught) {                                                                                                                                                       \
      throw TestFramework::AssertionError(std::string(__FILE__) + ":" + std::to_string(__LINE__) + " ASSERT_THROW(" #expr ", " #exception_type ") - no exception caught"); \
    }                                                                                                                                                                      \
  } while (0)

#define IGNORE_NODISCARD(expr) \
  do {                         \
    (void)(expr);              \
  } while (0)

#define ASSERT_NO_THROW(expr)                                                                                                                              \
  do {                                                                                                                                                     \
    try {                                                                                                                                                  \
      IGNORE_NODISCARD(expr);                                                                                                                              \
    } catch (const std::exception &e) {                                                                                                                    \
      throw TestFramework::AssertionError(std::string(__FILE__) + ":" + std::to_string(__LINE__) + " ASSERT_NO_THROW(" #expr ") threw: " + e.what());      \
    } catch (...) {                                                                                                                                        \
      throw TestFramework::AssertionError(std::string(__FILE__) + ":" + std::to_string(__LINE__) + " ASSERT_NO_THROW(" #expr ") threw unknown exception"); \
    }                                                                                                                                                      \
  } while (0)

#define ASSERT_GT(a, b)                                                                                                                  \
  do {                                                                                                                                   \
    if (!((a) > (b))) {                                                                                                                  \
      throw TestFramework::AssertionError(std::string(__FILE__) + ":" + std::to_string(__LINE__) + " ASSERT_GT(" #a ", " #b ") failed"); \
    }                                                                                                                                    \
  } while (0)

#define ASSERT_LT(a, b)                                                                                                                  \
  do {                                                                                                                                   \
    if (!((a) < (b))) {                                                                                                                  \
      throw TestFramework::AssertionError(std::string(__FILE__) + ":" + std::to_string(__LINE__) + " ASSERT_LT(" #a ", " #b ") failed"); \
    }                                                                                                                                    \
  } while (0)

#define ASSERT_GE(a, b)                                                                                                                  \
  do {                                                                                                                                   \
    if (!((a) >= (b))) {                                                                                                                 \
      throw TestFramework::AssertionError(std::string(__FILE__) + ":" + std::to_string(__LINE__) + " ASSERT_GE(" #a ", " #b ") failed"); \
    }                                                                                                                                    \
  } while (0)

#endif
