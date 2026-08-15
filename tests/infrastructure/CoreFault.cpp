/**
 * @file CoreFault.cpp
 * @brief tests/common/core/fault 模块单元测试
 * @details 覆盖 psmtest::fault 错误码体系的三层头文件：
 * 1. code.hpp —— describe() 全部 64 个枚举分支 + default、succeeded/failed
 * 2. compatible.hpp —— cached_message 正常/越界、std/boost 双分类器、
 *    make_error_code、std::hash 特化、隐式转换
 * 3. handling.hpp —— succeeded/failed 模板三类型分发、
 *    to_code(boost) 全部映射分支、to_code(std) 全部映射分支
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
    // ────────────────────────── code.hpp ──────────────────────────

    TEST(CoreFault, DescribeEveryCode)
    {
        // 遍历全部枚举值，确保每个 case 分支都有非空描述
        constexpr int count = static_cast<int>(psmtest::fault::code::_count);
        for (int i = 0; i < count; ++i)
        {
            const auto c = static_cast<psmtest::fault::code>(i);
            const std::string_view desc = psmtest::fault::describe(c);
            ASSERT_FALSE(desc.empty()) << "describe(code=" << i << ") returned empty string";
        }

        // 抽查关键错误码的精确描述
        EXPECT_EQ(psmtest::fault::describe(psmtest::fault::code::success), "success");
        EXPECT_EQ(psmtest::fault::describe(psmtest::fault::code::eof), "eof");
        EXPECT_EQ(psmtest::fault::describe(psmtest::fault::code::timeout), "timeout");
        EXPECT_EQ(psmtest::fault::describe(psmtest::fault::code::crypto_error), "crypto_error");
        EXPECT_EQ(psmtest::fault::describe(psmtest::fault::code::badcfg), "badcfg");

        // describe 为 constexpr，可在编译期求值
        static_assert(psmtest::fault::describe(psmtest::fault::code::timeout) == "timeout");
        static_assert(psmtest::fault::describe(psmtest::fault::code::success) == "success");
    }

    TEST(CoreFault, DescribeUnknown)
    {
        // default 分支：正数越界与负数越界均返回 "unknown"
        // 注意：describe 为 constexpr，常量参数会被编译期折叠，须用运行时变量触发
        volatile int hi = 9999;
        volatile int lo = -1;
        EXPECT_EQ(psmtest::fault::describe(static_cast<psmtest::fault::code>(hi)), "unknown");
        EXPECT_EQ(psmtest::fault::describe(static_cast<psmtest::fault::code>(lo)), "unknown");
    }

    TEST(CoreFault, SucceededFailed)
    {
        // success 是唯一使 succeeded 返回 true 的码
        EXPECT_TRUE(psmtest::fault::succeeded(psmtest::fault::code::success));
        EXPECT_FALSE(psmtest::fault::failed(psmtest::fault::code::success));

        // 非 success 码：succeeded 为 false、failed 为 true
        EXPECT_FALSE(psmtest::fault::succeeded(psmtest::fault::code::timeout));
        EXPECT_TRUE(psmtest::fault::failed(psmtest::fault::code::timeout));
        EXPECT_FALSE(psmtest::fault::succeeded(psmtest::fault::code::crypto_error));
        EXPECT_TRUE(psmtest::fault::failed(psmtest::fault::code::crypto_error));
        EXPECT_FALSE(psmtest::fault::succeeded(psmtest::fault::code::eof));
        EXPECT_TRUE(psmtest::fault::failed(psmtest::fault::code::eof));
    }

    // ─────────────────────── compatible.hpp ────────────────────────

    TEST(CoreFault, CachedMessageValid)
    {
        // 缓存消息与 describe 完全一致（首次调用触发静态数组构造）
        constexpr int count = static_cast<int>(psmtest::fault::code::_count);
        for (int i = 0; i < count; ++i)
        {
            const auto c = static_cast<psmtest::fault::code>(i);
            EXPECT_EQ(psmtest::fault::cached_message(c), psmtest::fault::describe(c));
        }
    }

    TEST(CoreFault, CachedMessageOutOfRange)
    {
        // 越界索引（>= _count 或负数）返回 "unknown"
        EXPECT_EQ(psmtest::fault::cached_message(static_cast<psmtest::fault::code>(psmtest::fault::code::_count)), "unknown");
        EXPECT_EQ(psmtest::fault::cached_message(static_cast<psmtest::fault::code>(-5)), "unknown");
        EXPECT_EQ(psmtest::fault::cached_message(static_cast<psmtest::fault::code>(100000)), "unknown");
    }

    TEST(CoreFault, StdCategory)
    {
        const auto &cat = psmtest::fault::category();

        // name() 返回分类名
        EXPECT_EQ(std::string_view(cat.name()), "psmtest::fault");

        // 单例：多次调用返回同一实例
        EXPECT_EQ(&cat, &psmtest::fault::category());

        // message(int) 委托 cached_message：有效码返回描述、越界返回 unknown
        EXPECT_EQ(cat.message(static_cast<int>(psmtest::fault::code::eof)), "eof");
        EXPECT_EQ(cat.message(static_cast<int>(psmtest::fault::code::_count)), "unknown");
    }

    TEST(CoreFault, MakeErrorCodeStd)
    {
        const std::error_code ec = psmtest::fault::make_error_code(psmtest::fault::code::eof);
        EXPECT_EQ(ec.value(), static_cast<int>(psmtest::fault::code::eof));
        EXPECT_EQ(std::string_view(ec.category().name()), "psmtest::fault");
        EXPECT_TRUE(ec) << "非零错误码应判为失败";
    }

    TEST(CoreFault, ImplicitConversionStd)
    {
        // is_error_code_enum 特化支持隐式转换
        const std::error_code ec = psmtest::fault::code::timeout;
        EXPECT_EQ(ec.value(), static_cast<int>(psmtest::fault::code::timeout));
        EXPECT_EQ(std::string_view(ec.category().name()), "psmtest::fault");
    }

    TEST(CoreFault, HashSpecialization)
    {
        // hash 特化委托 std::hash<int>
        std::hash<psmtest::fault::code> hasher;
        const auto c = psmtest::fault::code::eof;
        EXPECT_EQ(hasher(c), std::hash<int>{}(static_cast<int>(c)));
        EXPECT_EQ(hasher(psmtest::fault::code::success), std::hash<int>{}(0));
    }

    TEST(CoreFault, BoostCategory)
    {
        const auto &cat = boost::system::category();

        EXPECT_EQ(std::string_view(cat.name()), "psmtest::fault");

        // 单例
        EXPECT_EQ(&cat, &boost::system::category());

        // message(int) 委托 cached_message
        EXPECT_EQ(cat.message(static_cast<int>(psmtest::fault::code::eof)), "eof");
        EXPECT_EQ(cat.message(static_cast<int>(psmtest::fault::code::_count)), "unknown");
    }

    TEST(CoreFault, MakeErrorCodeBoost)
    {
        const boost::system::error_code ec = boost::system::make_error_code(psmtest::fault::code::eof);
        EXPECT_EQ(ec.value(), static_cast<int>(psmtest::fault::code::eof));
        EXPECT_EQ(std::string_view(ec.category().name()), "psmtest::fault");
        EXPECT_TRUE(ec);
    }

    TEST(CoreFault, ErrorCodeEnumTraits)
    {
        // 特化生效：std 与 boost 双路 is_error_code_enum 均为 true
        static_assert(std::is_error_code_enum<psmtest::fault::code>::value);
        static_assert(boost::system::is_error_code_enum<psmtest::fault::code>::value);

        // std 侧隐式转换正常
        const std::error_code ec = psmtest::fault::code::timeout;
        EXPECT_EQ(ec.value(), static_cast<int>(psmtest::fault::code::timeout));
        EXPECT_EQ(std::string_view(ec.category().name()), "psmtest::fault");

        // boost 侧经 boost::system::make_error_code 显式转换
        const boost::system::error_code bec = boost::system::make_error_code(psmtest::fault::code::timeout);
        EXPECT_EQ(bec.value(), static_cast<int>(psmtest::fault::code::timeout));
        EXPECT_EQ(std::string_view(bec.category().name()), "psmtest::fault");
    }

    // ─────────────────────── handling.hpp ──────────────────────────

    TEST(CoreFault, SucceededFailedTemplate)
    {
        // fault::code 类型分发
        EXPECT_TRUE(psmtest::fault::succeeded(psmtest::fault::code::success));
        EXPECT_FALSE(psmtest::fault::succeeded(psmtest::fault::code::eof));
        EXPECT_FALSE(psmtest::fault::failed(psmtest::fault::code::success));
        EXPECT_TRUE(psmtest::fault::failed(psmtest::fault::code::eof));

        // std::error_code 类型分发
        EXPECT_TRUE(psmtest::fault::succeeded(std::error_code{}));
        EXPECT_FALSE(psmtest::fault::succeeded(std::make_error_code(std::errc::io_error)));
        EXPECT_FALSE(psmtest::fault::failed(std::error_code{}));
        EXPECT_TRUE(psmtest::fault::failed(std::make_error_code(std::errc::io_error)));

        // boost::system::error_code 类型分发
        EXPECT_TRUE(psmtest::fault::succeeded(boost::system::error_code{}));
        EXPECT_FALSE(
            psmtest::fault::succeeded(boost::system::error_code{static_cast<int>(boost::system::errc::invalid_argument), boost::system::generic_category()}));
        EXPECT_FALSE(psmtest::fault::failed(boost::system::error_code{}));
        EXPECT_TRUE(psmtest::fault::failed(boost::system::error_code{static_cast<int>(boost::system::errc::invalid_argument), boost::system::generic_category()}));
    }

    TEST(CoreFault, ToCodeBoostSuccess)
    {
        // 空错误码 → success
        EXPECT_EQ(psmtest::fault::to_code(boost::system::error_code{}), psmtest::fault::code::success);
    }

    TEST(CoreFault, ToCodeBoostPsmCategory)
    {
        // psmtest::fault 分类：范围内值还原为原码
        const boost::system::error_code ec = boost::system::make_error_code(psmtest::fault::code::kexfail);
        EXPECT_EQ(psmtest::fault::to_code(ec), psmtest::fault::code::kexfail);

        // psmtest::fault 分类：越界值 → generic_error
        const boost::system::error_code out{9999, boost::system::category()};
        EXPECT_EQ(psmtest::fault::to_code(out), psmtest::fault::code::generic_error);
    }

    TEST(CoreFault, ToCodeBoostMappings)
    {
        // 逐个验证 Asio 错误 → fault 错误映射
        EXPECT_EQ(psmtest::fault::to_code(boost::asio::error::eof), psmtest::fault::code::eof);
        EXPECT_EQ(psmtest::fault::to_code(boost::asio::error::operation_aborted), psmtest::fault::code::canceled);
        EXPECT_EQ(psmtest::fault::to_code(boost::asio::error::timed_out), psmtest::fault::code::timeout);
        EXPECT_EQ(psmtest::fault::to_code(boost::asio::error::connection_refused), psmtest::fault::code::connection_refused);
        EXPECT_EQ(psmtest::fault::to_code(boost::asio::error::connection_reset), psmtest::fault::code::connection_reset);
        EXPECT_EQ(psmtest::fault::to_code(boost::asio::error::connection_aborted), psmtest::fault::code::connection_aborted);
        EXPECT_EQ(psmtest::fault::to_code(boost::asio::error::host_unreachable), psmtest::fault::code::host_noreply);
        EXPECT_EQ(psmtest::fault::to_code(boost::asio::error::network_unreachable), psmtest::fault::code::net_noreply);
        EXPECT_EQ(psmtest::fault::to_code(boost::asio::error::no_buffer_space), psmtest::fault::code::resource_unavailable);
    }

    TEST(CoreFault, ToCodeBoostUnknown)
    {
        // 未映射的错误 → io_error
        const boost::system::error_code ec{static_cast<int>(boost::system::errc::invalid_argument),
                                           boost::system::generic_category()};
        EXPECT_EQ(psmtest::fault::to_code(ec), psmtest::fault::code::io_error);
        EXPECT_EQ(psmtest::fault::to_code(boost::asio::error::broken_pipe), psmtest::fault::code::io_error);
    }

    TEST(CoreFault, ToCodeStdSuccess)
    {
        // 空错误码 → success
        EXPECT_EQ(psmtest::fault::to_code(std::error_code{}), psmtest::fault::code::success);
    }

    TEST(CoreFault, ToCodeStdPsmCategory)
    {
        // psmtest::fault 分类：范围内值还原为原码
        const std::error_code ec = psmtest::fault::make_error_code(psmtest::fault::code::badsni);
        EXPECT_EQ(psmtest::fault::to_code(ec), psmtest::fault::code::badsni);

        // psmtest::fault 分类：越界值 → generic_error
        const std::error_code out{9999, psmtest::fault::category()};
        EXPECT_EQ(psmtest::fault::to_code(out), psmtest::fault::code::generic_error);
    }

    TEST(CoreFault, ToCodeStdMappings)
    {
        // 逐个验证 std::errc 错误 → fault 错误映射
        EXPECT_EQ(psmtest::fault::to_code(std::make_error_code(std::errc::connection_refused)),
                  psmtest::fault::code::connection_refused);
        EXPECT_EQ(psmtest::fault::to_code(std::make_error_code(std::errc::connection_reset)),
                  psmtest::fault::code::connection_reset);
        EXPECT_EQ(psmtest::fault::to_code(std::make_error_code(std::errc::connection_aborted)),
                  psmtest::fault::code::connection_aborted);
        EXPECT_EQ(psmtest::fault::to_code(std::make_error_code(std::errc::timed_out)), psmtest::fault::code::timeout);
        EXPECT_EQ(psmtest::fault::to_code(std::make_error_code(std::errc::host_unreachable)),
                  psmtest::fault::code::host_noreply);
        EXPECT_EQ(psmtest::fault::to_code(std::make_error_code(std::errc::network_unreachable)),
                  psmtest::fault::code::net_noreply);
        EXPECT_EQ(psmtest::fault::to_code(std::make_error_code(std::errc::operation_canceled)),
                  psmtest::fault::code::canceled);
    }

    TEST(CoreFault, ToCodeStdUnknown)
    {
        // 未映射的错误 → io_error
        EXPECT_EQ(psmtest::fault::to_code(std::make_error_code(std::errc::invalid_argument)),
                  psmtest::fault::code::io_error);
        EXPECT_EQ(psmtest::fault::to_code(std::make_error_code(std::errc::no_such_file_or_directory)),
                  psmtest::fault::code::io_error);
    }
} // namespace
