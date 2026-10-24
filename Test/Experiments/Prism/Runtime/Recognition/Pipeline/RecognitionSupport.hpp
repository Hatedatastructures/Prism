/**
 * @file RecognitionSupport.hpp
 * @brief Recognition Experiment 用例的共享异步测试辅助。
 */
#pragma once

#include <Test/Experiments/Prism/Runtime/Recognition/Probe/ProbeRecognition.hpp>
#include <Experiments/Prism/Runtime/Recognition/Route/Route.hpp>
#include <Experiments/Prism/Runtime/Recognition/Scheme/SchemeExecutor.hpp>
#include <Prism/Runtime/Recognition/Probe.hpp>
#include <Prism/Runtime/Recognition/Protocol.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <TestSupport/Fixtures/RecognitionWire.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <chrono>
#include <exception>
#include <memory>
#include <string_view>
#include <utility>

#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace rec = Prism::Recognition;
    namespace experiment = Prism::Recognition::Experiment;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;
    using Prism::SharedTransmission;

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

    /** @brief 用定时等待模拟 recognition 控制事件。 */
    auto WaitForRecognitionEvent(Net::any_io_executor Executor, std::chrono::milliseconds Delay,
                                 rec::RecognitionControlEvent Event)
        -> Net::awaitable<rec::RecognitionControlEvent>
    {
        Net::steady_timer Timer(Executor);
        Timer.expires_after(Delay);
        co_await Timer.async_wait(Net::use_awaitable);
        co_return Event;
    }

    static_assert(requires(rec::Experiment::SniRouteTable &Routes)
                  { Routes.Add(std::string_view{}, std::string_view{}, Prism::Contract::ProtocolType::Tls); });
} // namespace
