/**
 * @file RecognitionTestSupport.hpp
 * @brief RecognitionTest.cpp 拆分后的模块共享测试夹具与构造辅助。
 */
#pragma once

/**
 * @file RecognitionTest.cpp
 * @brief 协议识别流水线测试（T2-4）
 * @details 覆盖：
 *          - 协议首字节检测矩阵（socks5/tls/vless/trojan/vmess/http/unknown）
 *          - Probe 预读 + 回注
 *          - SNI 路由表（精确/通配/未命中）
 *          - Pipeline 完整识别（含预读回注可重读）
 */

#include <Preview/Foundation/Memory/Container.hpp>
#include <tests/Experiments/Preview/ProbeRecognition.hpp>
#include <Preview/Runtime/Recognition/Probe.hpp>
#include <Preview/Runtime/Recognition/Protocol.hpp>
#include <Experiments/Preview/Route.hpp>
#include <Experiments/Preview/SchemeExecutor.hpp>
#include <Preview/Runtime/Recognition/Tls.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <TestSupport/Fixtures/RecognitionWire.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <concepts>
#include <memory>
#include <string_view>
#include <stdexcept>
#include <thread>

#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace rec = Preview::Recognition;
    namespace experiment = Preview::Recognition::Experiment;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using Preview::SharedTransmission;

    /// 构造首包字节
    auto BytesOf(std::initializer_list<std::uint8_t> List) -> std::vector<std::uint8_t>
    {
        return {List};
    }

    template <typename A>
    auto RunCoro(Net::io_context &Ioc, A Coro) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(Ioc, std::move(Coro), [&](std::exception_ptr ErrorValue)
                      { Exception = ErrorValue; Ioc.stop(); });
        Ioc.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    auto WaitForRecognitionEvent(Net::any_io_executor Executor, std::chrono::milliseconds Delay,
                                 rec::RecognitionControlEvent Event)
        -> Net::awaitable<rec::RecognitionControlEvent>
    {
        Net::steady_timer Timer(Executor);
        Timer.expires_after(Delay);
        co_await Timer.async_wait(Net::use_awaitable);
        co_return Event;
    }
} // namespace

// ── 协议检测矩阵 ──



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







// ── Probe ──





// ── SNI 路由表 ──



















// ── Pipeline ──









