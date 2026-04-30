/**
 * @file FaultHandling.cpp
 * @brief fault::to_code 错误码映射测试
 * @details 验证 boost::system::error_code 和 std::error_code
 *          到 psm::fault::code 的映射正确性，包括：
 * 1. Boost.Asio EOF → fault::code::eof
 * 2. Boost.Asio operation_aborted → fault::code::canceled
 * 3. Boost.Asio timed_out → fault::code::timeout
 * 4. std::errc::connection_refused → fault::code::connection_refused
 * 5. std::errc::timed_out → fault::code::timeout
 * 6. 未映射错误码 fallback → fault::code::io_error
 */

#include <prism/fault/handling.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <boost/asio.hpp>
#include <format>
#include <string_view>

#ifdef WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

namespace net = boost::asio;

namespace
{
    psm::testing::TestRunner runner("FaultHandling");
}

/**
 * @brief 测试 boost::asio::error::eof 映射为 fault::code::eof
 */
void TestToCodeBoostEof()
{
    auto ec = boost::asio::error::make_error_code(boost::asio::error::eof);
    auto result = psm::fault::to_code(ec);
    runner.Check(result == psm::fault::code::eof,
                 "boost::asio::error::eof → fault::code::eof");
}

/**
 * @brief 测试 boost::asio::error::operation_aborted 映射为 fault::code::canceled
 */
void TestToCodeBoostAborted()
{
    auto ec = boost::asio::error::make_error_code(boost::asio::error::operation_aborted);
    auto result = psm::fault::to_code(ec);
    runner.Check(result == psm::fault::code::canceled,
                 "boost::asio::error::operation_aborted → fault::code::canceled");
}

/**
 * @brief 测试 boost::asio::error::timed_out 映射为 fault::code::timeout
 */
void TestToCodeBoostTimeout()
{
    auto ec = boost::asio::error::make_error_code(boost::asio::error::timed_out);
    auto result = psm::fault::to_code(ec);
    runner.Check(result == psm::fault::code::timeout,
                 "boost::asio::error::timed_out → fault::code::timeout");
}

/**
 * @brief 测试 std::errc::connection_refused 映射为 fault::code::connection_refused
 */
void TestToCodeStdConnectionRefused()
{
    auto ec = std::make_error_code(std::errc::connection_refused);
    auto result = psm::fault::to_code(ec);
    runner.Check(result == psm::fault::code::connection_refused,
                 "std::errc::connection_refused → fault::code::connection_refused");
}

/**
 * @brief 测试 std::errc::timed_out 映射为 fault::code::timeout
 */
void TestToCodeStdTimeout()
{
    auto ec = std::make_error_code(std::errc::timed_out);
    auto result = psm::fault::to_code(ec);
    runner.Check(result == psm::fault::code::timeout,
                 "std::errc::timed_out → fault::code::timeout");
}

/**
 * @brief 测试未映射的 boost 错误码 fallback 到 fault::code::io_error
 */
void TestToCodeFallback()
{
    auto ec = boost::asio::error::make_error_code(boost::asio::error::not_found);
    auto result = psm::fault::to_code(ec);
    runner.Check(result == psm::fault::code::io_error,
                 "unmapped boost error → fault::code::io_error (fallback)");
}

/**
 * @brief 测试入口
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
#ifdef WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_global_pooling();
    psm::trace::init({});

    runner.LogInfo("Starting FaultHandling tests...");

    TestToCodeBoostEof();
    TestToCodeBoostAborted();
    TestToCodeBoostTimeout();
    TestToCodeStdConnectionRefused();
    TestToCodeStdTimeout();
    TestToCodeFallback();

    return runner.Summary();
}
