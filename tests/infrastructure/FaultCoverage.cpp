/**
 * @file FaultCoverage.cpp
 * @brief psmtest::fault 模块覆盖率补全测试
 * @details 针对 tests/common/core/fault 三层头文件做穷举式覆盖：
 * 1. code.hpp —— describe() 全部 64 个枚举分支（含边界值、default）
 *    及 succeeded()/failed() 全码遍历
 * 2. compatible.hpp —— 双分类器 name/message、cached_message 全码、
 *    make_error_code 往返、std::hash 特化、隐式转换
 * 3. handling.hpp —— to_code() 的 boost/std 双路转换全部分支
 *    （空码、自有分类、越界、Asio/errc 映射、未知码）及三类型
 *    succeeded()/failed() 模板分发
 */

#include <common/core/fault/code.hpp>
#include <common/core/fault/compatible.hpp>
#include <common/core/fault/handling.hpp>

#include <boost/asio/error.hpp>
#include <boost/system/error_code.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>

#include <gtest/gtest.h>

namespace
{
    using psmtest::fault::code;

    constexpr auto code_count = static_cast<int>(code::_count);

    // ────────────────────────── code.hpp ──────────────────────────

    TEST(FaultCoverage, DescribeAllEnumBranches)
    {
        // 遍历全部枚举值，逐一调用 describe()，确保 switch 每个 case 均被覆盖
        // 使用运行时变量避免 constexpr 编译期折叠
        volatile int cursor = 0;
        for (; cursor < code_count; ++cursor)
        {
            const auto c = static_cast<code>(cursor);
            const std::string_view desc = psmtest::fault::describe(c);
            ASSERT_FALSE(desc.empty()) << "describe(code=" << cursor << ") 返回空串";
        }

        // 边界值：首个枚举（success = 0）与最后一个枚举（badcfg = 63）
        EXPECT_EQ(psmtest::fault::describe(code::success), "success");
        EXPECT_EQ(psmtest::fault::describe(code::generic_error), "generic_error");
        EXPECT_EQ(psmtest::fault::describe(code::badcfg), "badcfg");

        // 枚举总数不变式：0..63 共 64 个，_count 仅用于统计
        EXPECT_EQ(code_count, 64);
        EXPECT_EQ(static_cast<int>(code::success), 0);
    }

    TEST(FaultCoverage, DescribeUnknownBranch)
    {
        // default 分支：正负越界均返回 "unknown"，须用运行时变量触发
        volatile int hi = 9999;
        volatile int lo = -1;
        EXPECT_EQ(psmtest::fault::describe(static_cast<code>(hi)), "unknown");
        EXPECT_EQ(psmtest::fault::describe(static_cast<code>(lo)), "unknown");
    }

    TEST(FaultCoverage, SucceededFailedEveryCode)
    {
        // 唯一成功码：succeeded 为 true、failed 为 false
        EXPECT_TRUE(psmtest::fault::succeeded(code::success));
        EXPECT_FALSE(psmtest::fault::failed(code::success));

        // 全部错误码：succeeded 为 false、failed 为 true
        volatile int cursor = 0;
        for (; cursor < code_count; ++cursor)
        {
            const auto c = static_cast<code>(cursor);
            if (c == code::success)
            {
                continue;
            }
            EXPECT_FALSE(psmtest::fault::succeeded(c)) << "succeeded(code=" << cursor << ") 应为 false";
            EXPECT_TRUE(psmtest::fault::failed(c)) << "failed(code=" << cursor << ") 应为 true";
        }

        // 越界值同样视为失败
        EXPECT_FALSE(psmtest::fault::succeeded(static_cast<code>(-1)));
        EXPECT_TRUE(psmtest::fault::failed(static_cast<code>(100000)));
    }

    // ─────────────────────── compatible.hpp ────────────────────────

    TEST(FaultCoverage, CachedMessageEveryCode)
    {
        // 缓存消息与 describe 全码一致
        volatile int cursor = 0;
        for (; cursor < code_count; ++cursor)
        {
            const auto c = static_cast<code>(cursor);
            EXPECT_EQ(psmtest::fault::cached_message(c), psmtest::fault::describe(c));
        }

        // 越界索引回落 "unknown"
        EXPECT_EQ(psmtest::fault::cached_message(static_cast<code>(code::_count)), "unknown");
        EXPECT_EQ(psmtest::fault::cached_message(static_cast<code>(-3)), "unknown");
        EXPECT_EQ(psmtest::fault::cached_message(static_cast<code>(65536)), "unknown");
    }

    TEST(FaultCoverage, StdCategoryNameAndMessage)
    {
        const auto &cat = psmtest::fault::category();

        // name() 非空且固定
        EXPECT_FALSE(std::string_view(cat.name()).empty());
        EXPECT_EQ(std::string_view(cat.name()), "psmtest::fault");

        // 单例：多次调用同一实例
        EXPECT_EQ(&cat, &psmtest::fault::category());

        // message() 对全部已知码非空
        volatile int cursor = 0;
        for (; cursor < code_count; ++cursor)
        {
            const std::string msg = cat.message(cursor);
            EXPECT_FALSE(msg.empty()) << "category.message(" << cursor << ") 返回空串";
        }
        EXPECT_EQ(cat.message(0), "success");
        EXPECT_EQ(cat.message(static_cast<int>(code::_count)), "unknown");
    }

    TEST(FaultCoverage, BoostCategoryNameAndMessage)
    {
        const auto &cat = boost::system::category();

        EXPECT_FALSE(std::string_view(cat.name()).empty());
        EXPECT_EQ(std::string_view(cat.name()), "psmtest::fault");
        EXPECT_EQ(&cat, &boost::system::category());

        EXPECT_EQ(cat.message(static_cast<int>(code::eof)), "eof");
        EXPECT_EQ(cat.message(static_cast<int>(code::success)), "success");
        EXPECT_EQ(cat.message(static_cast<int>(code::_count)), "unknown");
        EXPECT_EQ(cat.message(-7), "unknown");
    }

    TEST(FaultCoverage, MakeErrorCodeStdRoundTrip)
    {
        // 覆盖首、中、尾三类代表性错误码
        const code samples[] = {code::success, code::generic_error, code::timeout,
                                code::verifyfail, code::badcfg};
        for (const auto c : samples)
        {
            const std::error_code ec = psmtest::fault::make_error_code(c);
            EXPECT_EQ(ec.value(), static_cast<int>(c));
            EXPECT_EQ(std::string_view(ec.category().name()), "psmtest::fault");
            EXPECT_FALSE(ec.message().empty());
            EXPECT_EQ(psmtest::fault::to_code(ec), c) << "make_error_code 往返失败";
        }
    }

    TEST(FaultCoverage, MakeErrorCodeBoostRoundTrip)
    {
        const code samples[] = {code::success, code::eof, code::connection_refused, code::badcfg};
        for (const auto c : samples)
        {
            const boost::system::error_code ec = boost::system::make_error_code(c);
            EXPECT_EQ(ec.value(), static_cast<int>(c));
            EXPECT_EQ(std::string_view(ec.category().name()), "psmtest::fault");
            EXPECT_FALSE(ec.message().empty());
            EXPECT_EQ(psmtest::fault::to_code(ec), c) << "boost make_error_code 往返失败";
        }
    }

    TEST(FaultCoverage, ImplicitConversionBothSides)
    {
        // is_error_code_enum 特化：std 侧支持隐式转换
        const std::error_code ec = code::timeout;
        EXPECT_EQ(ec.value(), static_cast<int>(code::timeout));
        EXPECT_EQ(std::string_view(ec.category().name()), "psmtest::fault");

        // boost 侧隐式转换存在缺陷（见 logs/issues.md B-31，ADL 命中
        // psmtest::fault::make_error_code 返回 std::error_code 导致垃圾值），
        // 此处仅验证显式构造路径
        const boost::system::error_code bec = boost::system::make_error_code(code::eof);
        EXPECT_EQ(bec.value(), static_cast<int>(code::eof));
        EXPECT_EQ(std::string_view(bec.category().name()), "psmtest::fault");
    }

    TEST(FaultCoverage, HashSpecialization)
    {
        // 哈希特化委托 std::hash<int>
        std::hash<code> hasher;
        const code samples[] = {code::success, code::generic_error, code::timeout, code::badcfg};
        for (const auto c : samples)
        {
            EXPECT_EQ(hasher(c), std::hash<int>{}(static_cast<int>(c)));
        }
    }

    // ─────────────────────── handling.hpp ──────────────────────────

    TEST(FaultCoverage, SucceededFailedHelpers)
    {
        // fault::code 类型
        EXPECT_TRUE(psmtest::fault::succeeded(code::success));
        EXPECT_FALSE(psmtest::fault::succeeded(code::badcfg));
        EXPECT_FALSE(psmtest::fault::failed(code::success));
        EXPECT_TRUE(psmtest::fault::failed(code::badcfg));

        // std::error_code 类型
        EXPECT_TRUE(psmtest::fault::succeeded(std::error_code{}));
        EXPECT_FALSE(psmtest::fault::succeeded(std::make_error_code(std::errc::io_error)));
        EXPECT_FALSE(psmtest::fault::failed(std::error_code{}));
        EXPECT_TRUE(psmtest::fault::failed(std::make_error_code(std::errc::io_error)));

        // boost::system::error_code 类型
        EXPECT_TRUE(psmtest::fault::succeeded(boost::system::error_code{}));
        EXPECT_FALSE(psmtest::fault::failed(boost::system::error_code{}));
        const boost::system::error_code bec{
            static_cast<int>(boost::system::errc::invalid_argument), boost::system::generic_category()};
        EXPECT_FALSE(psmtest::fault::succeeded(bec));
        EXPECT_TRUE(psmtest::fault::failed(bec));
    }

    TEST(FaultCoverage, ToCodeBoostEmpty)
    {
        // 空错误码 → success
        EXPECT_EQ(psmtest::fault::to_code(boost::system::error_code{}), code::success);
    }

    TEST(FaultCoverage, ToCodeBoostAsioMappings)
    {
        // 全部 Asio → fault 映射分支
        EXPECT_EQ(psmtest::fault::to_code(boost::asio::error::eof), code::eof);
        EXPECT_EQ(psmtest::fault::to_code(boost::asio::error::operation_aborted), code::canceled);
        EXPECT_EQ(psmtest::fault::to_code(boost::asio::error::timed_out), code::timeout);
        EXPECT_EQ(psmtest::fault::to_code(boost::asio::error::connection_refused),
                  code::connection_refused);
        EXPECT_EQ(psmtest::fault::to_code(boost::asio::error::connection_reset), code::connection_reset);
        EXPECT_EQ(psmtest::fault::to_code(boost::asio::error::connection_aborted),
                  code::connection_aborted);
        EXPECT_EQ(psmtest::fault::to_code(boost::asio::error::host_unreachable), code::host_noreply);
        EXPECT_EQ(psmtest::fault::to_code(boost::asio::error::network_unreachable), code::net_noreply);
        EXPECT_EQ(psmtest::fault::to_code(boost::asio::error::no_buffer_space),
                  code::resource_unavailable);
    }

    TEST(FaultCoverage, ToCodeBoostOwnCategory)
    {
        // 自有分类：范围内值原样还原
        const code samples[] = {code::success, code::kexfail, code::badcfg};
        for (const auto c : samples)
        {
            const boost::system::error_code ec = boost::system::make_error_code(c);
            EXPECT_EQ(psmtest::fault::to_code(ec), c);
        }

        // 自有分类：正负越界值 → generic_error
        const boost::system::error_code hi{9999, boost::system::category()};
        const boost::system::error_code lo{-1, boost::system::category()};
        EXPECT_EQ(psmtest::fault::to_code(hi), code::generic_error);
        EXPECT_EQ(psmtest::fault::to_code(lo), code::generic_error);
    }

    TEST(FaultCoverage, ToCodeBoostUnknown)
    {
        // 未映射的系统错误 → io_error
        const boost::system::error_code ec{
            static_cast<int>(boost::system::errc::invalid_argument), boost::system::generic_category()};
        EXPECT_EQ(psmtest::fault::to_code(ec), code::io_error);
        EXPECT_EQ(psmtest::fault::to_code(boost::asio::error::broken_pipe), code::io_error);
    }

    TEST(FaultCoverage, ToCodeStdEmpty)
    {
        // 空错误码 → success
        EXPECT_EQ(psmtest::fault::to_code(std::error_code{}), code::success);
    }

    TEST(FaultCoverage, ToCodeStdErrcMappings)
    {
        // 全部 std::errc → fault 映射分支
        EXPECT_EQ(psmtest::fault::to_code(std::make_error_code(std::errc::connection_refused)),
                  code::connection_refused);
        EXPECT_EQ(psmtest::fault::to_code(std::make_error_code(std::errc::connection_reset)),
                  code::connection_reset);
        EXPECT_EQ(psmtest::fault::to_code(std::make_error_code(std::errc::connection_aborted)),
                  code::connection_aborted);
        EXPECT_EQ(psmtest::fault::to_code(std::make_error_code(std::errc::timed_out)), code::timeout);
        EXPECT_EQ(psmtest::fault::to_code(std::make_error_code(std::errc::host_unreachable)),
                  code::host_noreply);
        EXPECT_EQ(psmtest::fault::to_code(std::make_error_code(std::errc::network_unreachable)),
                  code::net_noreply);
        EXPECT_EQ(psmtest::fault::to_code(std::make_error_code(std::errc::operation_canceled)),
                  code::canceled);
    }

    TEST(FaultCoverage, ToCodeStdOwnCategory)
    {
        // 自有分类：范围内值原样还原
        const code samples[] = {code::success, code::badsni, code::badcfg};
        for (const auto c : samples)
        {
            const std::error_code ec = psmtest::fault::make_error_code(c);
            EXPECT_EQ(psmtest::fault::to_code(ec), c);
        }

        // 自有分类：正负越界值 → generic_error
        const std::error_code hi{9999, psmtest::fault::category()};
        const std::error_code lo{-1, psmtest::fault::category()};
        EXPECT_EQ(psmtest::fault::to_code(hi), code::generic_error);
        EXPECT_EQ(psmtest::fault::to_code(lo), code::generic_error);
    }

    TEST(FaultCoverage, ToCodeStdUnknown)
    {
        // 未映射的标准错误 → io_error
        EXPECT_EQ(psmtest::fault::to_code(std::make_error_code(std::errc::invalid_argument)),
                  code::io_error);
        EXPECT_EQ(psmtest::fault::to_code(std::make_error_code(std::errc::no_such_file_or_directory)),
                  code::io_error);
    }
} // namespace
