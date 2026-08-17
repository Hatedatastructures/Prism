/**
 * @file CoreFault.cpp
 * @brief tests/common/core/fault 模块单元测试
 * @details 覆盖 preview::fault 错误码体系的三层头文件：
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
        constexpr int count = static_cast<int>(preview::fault::code::_count);
        for (int i = 0; i < count; ++i)
        {
            const auto c = static_cast<preview::fault::code>(i);
            const std::string_view desc = preview::fault::describe(c);
            ASSERT_FALSE(desc.empty()) << "describe(code=" << i << ") returned empty string";
        }

        // 抽查关键错误码的精确描述
        EXPECT_EQ(preview::fault::describe(preview::fault::code::success), "success");
        EXPECT_EQ(preview::fault::describe(preview::fault::code::eof), "eof");
        EXPECT_EQ(preview::fault::describe(preview::fault::code::timeout), "timeout");
        EXPECT_EQ(preview::fault::describe(preview::fault::code::crypto_error), "crypto_error");
        EXPECT_EQ(preview::fault::describe(preview::fault::code::badcfg), "badcfg");

        // describe 为 constexpr，可在编译期求值
        static_assert(preview::fault::describe(preview::fault::code::timeout) == "timeout");
        static_assert(preview::fault::describe(preview::fault::code::success) == "success");
    }

    TEST(CoreFault, DescribeUnknown)
    {
        // default 分支：正数越界与负数越界均返回 "unknown"
        // 注意：describe 为 constexpr，常量参数会被编译期折叠，须用运行时变量触发
        volatile int hi = 9999;
        volatile int lo = -1;
        EXPECT_EQ(preview::fault::describe(static_cast<preview::fault::code>(hi)), "unknown");
        EXPECT_EQ(preview::fault::describe(static_cast<preview::fault::code>(lo)), "unknown");
    }

    TEST(CoreFault, SucceededFailed)
    {
        // success 是唯一使 succeeded 返回 true 的码
        EXPECT_TRUE(preview::fault::succeeded(preview::fault::code::success));
        EXPECT_FALSE(preview::fault::failed(preview::fault::code::success));

        // 非 success 码：succeeded 为 false、failed 为 true
        EXPECT_FALSE(preview::fault::succeeded(preview::fault::code::timeout));
        EXPECT_TRUE(preview::fault::failed(preview::fault::code::timeout));
        EXPECT_FALSE(preview::fault::succeeded(preview::fault::code::crypto_error));
        EXPECT_TRUE(preview::fault::failed(preview::fault::code::crypto_error));
        EXPECT_FALSE(preview::fault::succeeded(preview::fault::code::eof));
        EXPECT_TRUE(preview::fault::failed(preview::fault::code::eof));
    }

    // ─────────────────────── compatible.hpp ────────────────────────

    TEST(CoreFault, CachedMessageValid)
    {
        // 缓存消息与 describe 完全一致（首次调用触发静态数组构造）
        constexpr int count = static_cast<int>(preview::fault::code::_count);
        for (int i = 0; i < count; ++i)
        {
            const auto c = static_cast<preview::fault::code>(i);
            EXPECT_EQ(preview::fault::cached_message(c), preview::fault::describe(c));
        }
    }

    TEST(CoreFault, CachedMessageOutOfRange)
    {
        // 越界索引（>= _count 或负数）返回 "unknown"
        EXPECT_EQ(preview::fault::cached_message(static_cast<preview::fault::code>(preview::fault::code::_count)), "unknown");
        EXPECT_EQ(preview::fault::cached_message(static_cast<preview::fault::code>(-5)), "unknown");
        EXPECT_EQ(preview::fault::cached_message(static_cast<preview::fault::code>(100000)), "unknown");
    }

    TEST(CoreFault, StdCategory)
    {
        const auto &cat = preview::fault::category();

        // name() 返回分类名
        EXPECT_EQ(std::string_view(cat.name()), "preview::fault");

        // 单例：多次调用返回同一实例
        EXPECT_EQ(&cat, &preview::fault::category());

        // message(int) 委托 cached_message：有效码返回描述、越界返回 unknown
        EXPECT_EQ(cat.message(static_cast<int>(preview::fault::code::eof)), "eof");
        EXPECT_EQ(cat.message(static_cast<int>(preview::fault::code::_count)), "unknown");
    }

    TEST(CoreFault, MakeErrorCodeStd)
    {
        const std::error_code ec = preview::fault::make_error_code(preview::fault::code::eof);
        EXPECT_EQ(ec.value(), static_cast<int>(preview::fault::code::eof));
        EXPECT_EQ(std::string_view(ec.category().name()), "preview::fault");
        EXPECT_TRUE(ec) << "非零错误码应判为失败";
    }

    TEST(CoreFault, ImplicitConversionStd)
    {
        // is_error_code_enum 特化支持隐式转换
        const std::error_code ec = preview::fault::code::timeout;
        EXPECT_EQ(ec.value(), static_cast<int>(preview::fault::code::timeout));
        EXPECT_EQ(std::string_view(ec.category().name()), "preview::fault");
    }

    TEST(CoreFault, HashSpecialization)
    {
        // hash 特化委托 std::hash<int>
        std::hash<preview::fault::code> hasher;
        const auto c = preview::fault::code::eof;
        EXPECT_EQ(hasher(c), std::hash<int>{}(static_cast<int>(c)));
        EXPECT_EQ(hasher(preview::fault::code::success), std::hash<int>{}(0));
    }

    TEST(CoreFault, BoostCategory)
    {
        const auto &cat = boost::system::category();

        EXPECT_EQ(std::string_view(cat.name()), "preview::fault");

        // 单例
        EXPECT_EQ(&cat, &boost::system::category());

        // message(int) 委托 cached_message
        EXPECT_EQ(cat.message(static_cast<int>(preview::fault::code::eof)), "eof");
        EXPECT_EQ(cat.message(static_cast<int>(preview::fault::code::_count)), "unknown");
    }

    TEST(CoreFault, MakeErrorCodeBoost)
    {
        const boost::system::error_code ec = boost::system::make_error_code(preview::fault::code::eof);
        EXPECT_EQ(ec.value(), static_cast<int>(preview::fault::code::eof));
        EXPECT_EQ(std::string_view(ec.category().name()), "preview::fault");
        EXPECT_TRUE(ec);
    }

    TEST(CoreFault, ErrorCodeEnumTraits)
    {
        // 特化生效：std 与 boost 双路 is_error_code_enum 均为 true
        static_assert(std::is_error_code_enum<preview::fault::code>::value);
        static_assert(boost::system::is_error_code_enum<preview::fault::code>::value);

        // std 侧隐式转换正常
        const std::error_code ec = preview::fault::code::timeout;
        EXPECT_EQ(ec.value(), static_cast<int>(preview::fault::code::timeout));
        EXPECT_EQ(std::string_view(ec.category().name()), "preview::fault");

        // boost 侧经 boost::system::make_error_code 显式转换
        const boost::system::error_code bec = boost::system::make_error_code(preview::fault::code::timeout);
        EXPECT_EQ(bec.value(), static_cast<int>(preview::fault::code::timeout));
        EXPECT_EQ(std::string_view(bec.category().name()), "preview::fault");
    }

    // ─────────────────────── handling.hpp ──────────────────────────

    TEST(CoreFault, SucceededFailedTemplate)
    {
        // fault::code 类型分发
        EXPECT_TRUE(preview::fault::succeeded(preview::fault::code::success));
        EXPECT_FALSE(preview::fault::succeeded(preview::fault::code::eof));
        EXPECT_FALSE(preview::fault::failed(preview::fault::code::success));
        EXPECT_TRUE(preview::fault::failed(preview::fault::code::eof));

        // std::error_code 类型分发
        EXPECT_TRUE(preview::fault::succeeded(std::error_code{}));
        EXPECT_FALSE(preview::fault::succeeded(std::make_error_code(std::errc::io_error)));
        EXPECT_FALSE(preview::fault::failed(std::error_code{}));
        EXPECT_TRUE(preview::fault::failed(std::make_error_code(std::errc::io_error)));

        // boost::system::error_code 类型分发
        EXPECT_TRUE(preview::fault::succeeded(boost::system::error_code{}));
        EXPECT_FALSE(
            preview::fault::succeeded(boost::system::error_code{static_cast<int>(boost::system::errc::invalid_argument), boost::system::generic_category()}));
        EXPECT_FALSE(preview::fault::failed(boost::system::error_code{}));
        EXPECT_TRUE(preview::fault::failed(boost::system::error_code{static_cast<int>(boost::system::errc::invalid_argument), boost::system::generic_category()}));
    }

    TEST(CoreFault, ToCodeBoostSuccess)
    {
        // 空错误码 → success
        EXPECT_EQ(preview::fault::to_code(boost::system::error_code{}), preview::fault::code::success);
    }

    TEST(CoreFault, ToCodeBoostPsmCategory)
    {
        // preview::fault 分类：范围内值还原为原码
        const boost::system::error_code ec = boost::system::make_error_code(preview::fault::code::kexfail);
        EXPECT_EQ(preview::fault::to_code(ec), preview::fault::code::kexfail);

        // preview::fault 分类：越界值 → generic_error
        const boost::system::error_code out{9999, boost::system::category()};
        EXPECT_EQ(preview::fault::to_code(out), preview::fault::code::generic_error);
    }

    TEST(CoreFault, ToCodeBoostMappings)
    {
        // 逐个验证 Asio 错误 → fault 错误映射
        EXPECT_EQ(preview::fault::to_code(boost::asio::error::eof), preview::fault::code::eof);
        EXPECT_EQ(preview::fault::to_code(boost::asio::error::operation_aborted), preview::fault::code::canceled);
        EXPECT_EQ(preview::fault::to_code(boost::asio::error::timed_out), preview::fault::code::timeout);
        EXPECT_EQ(preview::fault::to_code(boost::asio::error::connection_refused), preview::fault::code::connection_refused);
        EXPECT_EQ(preview::fault::to_code(boost::asio::error::connection_reset), preview::fault::code::connection_reset);
        EXPECT_EQ(preview::fault::to_code(boost::asio::error::connection_aborted), preview::fault::code::connection_aborted);
        EXPECT_EQ(preview::fault::to_code(boost::asio::error::host_unreachable), preview::fault::code::host_noreply);
        EXPECT_EQ(preview::fault::to_code(boost::asio::error::network_unreachable), preview::fault::code::net_noreply);
        EXPECT_EQ(preview::fault::to_code(boost::asio::error::no_buffer_space), preview::fault::code::resource_unavailable);
    }

    TEST(CoreFault, ToCodeBoostUnknown)
    {
        // 未映射的错误 → io_error
        const boost::system::error_code ec{static_cast<int>(boost::system::errc::invalid_argument),
                                           boost::system::generic_category()};
        EXPECT_EQ(preview::fault::to_code(ec), preview::fault::code::io_error);
        EXPECT_EQ(preview::fault::to_code(boost::asio::error::broken_pipe), preview::fault::code::io_error);
    }

    TEST(CoreFault, ToCodeStdSuccess)
    {
        // 空错误码 → success
        EXPECT_EQ(preview::fault::to_code(std::error_code{}), preview::fault::code::success);
    }

    TEST(CoreFault, ToCodeStdPsmCategory)
    {
        // preview::fault 分类：范围内值还原为原码
        const std::error_code ec = preview::fault::make_error_code(preview::fault::code::badsni);
        EXPECT_EQ(preview::fault::to_code(ec), preview::fault::code::badsni);

        // preview::fault 分类：越界值 → generic_error
        const std::error_code out{9999, preview::fault::category()};
        EXPECT_EQ(preview::fault::to_code(out), preview::fault::code::generic_error);
    }

    TEST(CoreFault, ToCodeStdMappings)
    {
        // 逐个验证 std::errc 错误 → fault 错误映射
        EXPECT_EQ(preview::fault::to_code(std::make_error_code(std::errc::connection_refused)),
                  preview::fault::code::connection_refused);
        EXPECT_EQ(preview::fault::to_code(std::make_error_code(std::errc::connection_reset)),
                  preview::fault::code::connection_reset);
        EXPECT_EQ(preview::fault::to_code(std::make_error_code(std::errc::connection_aborted)),
                  preview::fault::code::connection_aborted);
        EXPECT_EQ(preview::fault::to_code(std::make_error_code(std::errc::timed_out)), preview::fault::code::timeout);
        EXPECT_EQ(preview::fault::to_code(std::make_error_code(std::errc::host_unreachable)),
                  preview::fault::code::host_noreply);
        EXPECT_EQ(preview::fault::to_code(std::make_error_code(std::errc::network_unreachable)),
                  preview::fault::code::net_noreply);
        EXPECT_EQ(preview::fault::to_code(std::make_error_code(std::errc::operation_canceled)),
                  preview::fault::code::canceled);
    }

    TEST(CoreFault, ToCodeStdUnknown)
    {
        // 未映射的错误 → io_error
        EXPECT_EQ(preview::fault::to_code(std::make_error_code(std::errc::invalid_argument)),
                  preview::fault::code::io_error);
        EXPECT_EQ(preview::fault::to_code(std::make_error_code(std::errc::no_such_file_or_directory)),
                  preview::fault::code::io_error);
    }
} // namespace
