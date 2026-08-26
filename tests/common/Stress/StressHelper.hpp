/**
 * @file StressHelper.hpp
 * @brief 协议会话层压力测试公共设施
 * @details 提供三类基础件：
 * 1. Gate：并发汇合点（channel 容量 = 参与者总数，try_send 不丢失完成信号）
 * 2. LeakTracker：连接泄漏探测器（weak_ptr 弱引用追踪，不延长对象生命周期）
 * 3. RunCoro / ReadFull / WriteFull：协程驱动与精确读写工具
 * @note 仅 Header-only；供 tests/Protocol 各协议目录下的 XxxStressTest.cpp 使用。
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <cstddef>
#include <memory>
#include <span>
#include <vector>

namespace Preview::Stress
{
    namespace net = boost::asio;

    /// 并发汇合点（等所有参与者到达后继续）
    class Gate
    {
    public:
        /**
         * @brief 构造
         * @param ex 执行器
         * @param Total 参与者总数（Arrive 次数 = Wait 消耗次数）
         */
        Gate(net::any_io_executor ex, std::size_t Total) : Ch_(std::move(ex), Total), Total_(Total)
        {
        }

        /// 到达（线程安全，满则静默丢弃——容量与总数相等保证不丢）
        auto Arrive() -> void
        {
            (void)Ch_.try_send(boost::system::error_code{});
        }

        /// 等待全部参与者到达
        auto Wait() -> net::awaitable<void>
        {
            for (std::size_t I = 0; I < Total_; ++I)
            {
                co_await Ch_.async_receive(net::use_awaitable);
            }
        }

    private:
        net::experimental::channel<void(boost::system::error_code)> Ch_;
        std::size_t Total_;
    };

    /// 连接泄漏探测器（弱引用追踪）
    class LeakTracker
    {
    public:
        /// 追踪一个连接对象（仅弱引用，不延长生命周期）
        auto Track(const std::shared_ptr<void> &p) -> void
        {
            if (p)
            {
                Weak_.emplace_back(p);
            }
        }

        /// 追踪总数
        [[nodiscard]] auto Total() const -> std::size_t
        {
            return Weak_.size();
        }

        /// 当前仍存活（未释放）的连接数
        [[nodiscard]] auto Live() const -> std::size_t
        {
            return static_cast<std::size_t>(
                std::count_if(Weak_.begin(), Weak_.end(),
                              [](const auto &w) { return !w.expired(); }));
        }

        /// 是否全部释放（无泄漏）
        [[nodiscard]] auto AllReleased() const -> bool
        {
            return Live() == 0;
        }

    private:
        std::vector<std::weak_ptr<void>> Weak_;
    };

    /// 运行协程直至完成（异常重抛）
    template <typename A>
    auto RunCoro(net::io_context &ioc, A coro) -> void
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          ioc.stop();
                      });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    /// 精确读取指定字节数
    /// @return true = 失败（EOF / 底层错误）；false = 成功
    template <typename Stream>
    auto ReadFull(Stream &s, std::span<std::byte> dst) -> net::awaitable<bool>
    {
        std::size_t Done = 0;
        while (Done < dst.size())
        {
            std::error_code ec;
            const auto N = co_await s.async_read_some(dst.subspan(Done), ec);
            if (ec || N == 0)
            {
                co_return true;
            }
            Done += N;
        }
        co_return false;
    }

    /// 精确写入指定字节数
    /// @return true = 失败（底层错误）；false = 成功
    template <typename Stream>
    auto WriteFull(Stream &s, std::span<const std::byte> src) -> net::awaitable<bool>
    {
        std::size_t Done = 0;
        while (Done < src.size())
        {
            std::error_code ec;
            const auto N = co_await s.async_write_some(src.subspan(Done), ec);
            if (ec || N == 0)
            {
                co_return true;
            }
            Done += N;
        }
        co_return false;
    }

} // namespace Preview::Stress
