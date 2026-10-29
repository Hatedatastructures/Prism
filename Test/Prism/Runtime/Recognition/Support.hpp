/**
 * @file Support.hpp
 * @brief 当前 Recognition 生产接口测试的共享辅助。
 */
#pragma once

#include <Prism/Foundation/Memory/Container.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Runtime/Recognition/Probe.hpp>
#include <Prism/Runtime/Recognition/Protocol.hpp>
#include <Prism/Runtime/Recognition/Tls.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <TestSupport/Fixtures/RecognitionWire.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <concepts>
#include <cstdint>
#include <exception>
#include <initializer_list>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace rec = Prism::Recognition;
    using Prism::Error;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;

    /** @brief 把协议首包字节初始化列表转换为拥有型字节数组。 */
    auto BytesOf(std::initializer_list<std::uint8_t> List) -> std::vector<std::uint8_t>
    {
        return {List};
    }

    /** @brief 在 io_context 上完整驱动单个测试协程并传播异常。 */
    template <typename Awaitable>
    auto RunCoro(Net::io_context &Ioc, Awaitable Coro) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(Ioc, std::move(Coro), [&Exception, &Ioc](std::exception_ptr ErrorValue)
                      { Exception = ErrorValue; Ioc.stop(); });
        Ioc.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }
} // namespace

template <typename T>
concept HasRecognitionStatusString = requires(T Value)
{
    { rec::ToStringView(Value) } -> std::same_as<std::string_view>;
};

template <typename T>
auto ExpectRecognitionStatusStrings() -> void
{
    EXPECT_TRUE(HasRecognitionStatusString<T>);
    if constexpr (HasRecognitionStatusString<T>)
    {
        EXPECT_EQ(rec::ToStringView(static_cast<T>(rec::RecognitionStatus::Accepted)), "accepted");
        EXPECT_EQ(rec::ToStringView(static_cast<T>(rec::RecognitionStatus::NoMatch)), "no_match");
        EXPECT_EQ(rec::ToStringView(static_cast<T>(rec::RecognitionStatus::Ambiguous)), "ambiguous");
        EXPECT_EQ(rec::ToStringView(static_cast<T>(rec::RecognitionStatus::BudgetExceeded)), "budget_exceeded");
        EXPECT_EQ(rec::ToStringView(static_cast<T>(rec::RecognitionStatus::TimedOut)), "timed_out");
        EXPECT_EQ(rec::ToStringView(static_cast<T>(rec::RecognitionStatus::EndOfStream)), "end_of_stream");
        EXPECT_EQ(rec::ToStringView(static_cast<T>(rec::RecognitionStatus::IoError)), "io_error");
        EXPECT_EQ(rec::ToStringView(static_cast<T>(rec::RecognitionStatus::Polluted)), "polluted");
    }
}
