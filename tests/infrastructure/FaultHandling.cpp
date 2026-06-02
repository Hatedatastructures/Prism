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
#include <gtest/gtest.h>

namespace
{
    TEST(FaultHandling, ToCodeBoostEof)
    {
        auto ec = boost::asio::error::make_error_code(boost::asio::error::eof);
        auto result = psm::fault::to_code(ec);
        EXPECT_TRUE(result == psm::fault::code::eof)
            << "boost::asio::error::eof -> fault::code::eof";
    }

    TEST(FaultHandling, ToCodeBoostAborted)
    {
        auto ec = boost::asio::error::make_error_code(boost::asio::error::operation_aborted);
        auto result = psm::fault::to_code(ec);
        EXPECT_TRUE(result == psm::fault::code::canceled)
            << "boost::asio::error::operation_aborted -> fault::code::canceled";
    }

    TEST(FaultHandling, ToCodeBoostTimeout)
    {
        auto ec = boost::asio::error::make_error_code(boost::asio::error::timed_out);
        auto result = psm::fault::to_code(ec);
        EXPECT_TRUE(result == psm::fault::code::timeout)
            << "boost::asio::error::timed_out -> fault::code::timeout";
    }

    TEST(FaultHandling, ToCodeStdConnectionRefused)
    {
        auto ec = std::make_error_code(std::errc::connection_refused);
        auto result = psm::fault::to_code(ec);
        EXPECT_TRUE(result == psm::fault::code::connection_refused)
            << "std::errc::connection_refused -> fault::code::connection_refused";
    }

    TEST(FaultHandling, ToCodeStdTimeout)
    {
        auto ec = std::make_error_code(std::errc::timed_out);
        auto result = psm::fault::to_code(ec);
        EXPECT_TRUE(result == psm::fault::code::timeout)
            << "std::errc::timed_out -> fault::code::timeout";
    }

    TEST(FaultHandling, ToCodeFallback)
    {
        auto ec = boost::asio::error::make_error_code(boost::asio::error::not_found);
        auto result = psm::fault::to_code(ec);
        EXPECT_TRUE(result == psm::fault::code::io_error)
            << "unmapped boost error -> fault::code::io_error (fallback)";
    }
} // namespace
