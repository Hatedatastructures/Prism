/**
 * @file stress_helper.hpp
 * @brief 协议会话层压力测试公共设施
 * @details 提供三类基础件：
 * 1. gate：并发汇合点（channel 容量 = 参与者总数，try_send 不丢失完成信号）
 * 2. leak_tracker：连接泄漏探测器（weak_ptr 弱引用追踪，不延长对象生命周期）
 * 3. run_coro / read_full / write_full：协程驱动与精确读写工具
 * @note 仅 header-only；供 tests/protocol 各协议目录下的 XxxStressTest.cpp 使用。
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

namespace psmtest::stress
{
    namespace net = boost::asio;

    /// 并发汇合点（等所有参与者到达后继续）
    class gate
    {
    public:
        /**
         * @brief 构造
         * @param ex 执行器
         * @param total 参与者总数（arrive 次数 = wait 消耗次数）
         */
        gate(net::any_io_executor ex, std::size_t total) : ch_(std::move(ex), total), total_(total)
        {
        }

        /// 到达（线程安全，满则静默丢弃——容量与总数相等保证不丢）
        auto arrive() -> void
        {
            (void)ch_.try_send(boost::system::error_code{});
        }

        /// 等待全部参与者到达
        auto wait() -> net::awaitable<void>
        {
            for (std::size_t i = 0; i < total_; ++i)
            {
                co_await ch_.async_receive(net::use_awaitable);
            }
        }

    private:
        net::experimental::channel<void(boost::system::error_code)> ch_;
        std::size_t total_;
    };

    /// 连接泄漏探测器（弱引用追踪）
    class leak_tracker
    {
    public:
        /// 追踪一个连接对象（仅弱引用，不延长生命周期）
        auto track(const std::shared_ptr<void> &p) -> void
        {
            if (p)
            {
                weak_.emplace_back(p);
            }
        }

        /// 追踪总数
        [[nodiscard]] auto total() const -> std::size_t
        {
            return weak_.size();
        }

        /// 当前仍存活（未释放）的连接数
        [[nodiscard]] auto live() const -> std::size_t
        {
            return static_cast<std::size_t>(
                std::count_if(weak_.begin(), weak_.end(),
                              [](const auto &w) { return !w.expired(); }));
        }

        /// 是否全部释放（无泄漏）
        [[nodiscard]] auto all_released() const -> bool
        {
            return live() == 0;
        }

    private:
        std::vector<std::weak_ptr<void>> weak_;
    };

    /// 运行协程直至完成（异常重抛）
    template <typename A>
    auto run_coro(net::io_context &ioc, A coro) -> void
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
    auto read_full(Stream &s, std::span<std::byte> dst) -> net::awaitable<bool>
    {
        std::size_t done = 0;
        while (done < dst.size())
        {
            std::error_code ec;
            const auto n = co_await s.async_read_some(dst.subspan(done), ec);
            if (ec || n == 0)
            {
                co_return true;
            }
            done += n;
        }
        co_return false;
    }

    /// 精确写入指定字节数
    /// @return true = 失败（底层错误）；false = 成功
    template <typename Stream>
    auto write_full(Stream &s, std::span<const std::byte> src) -> net::awaitable<bool>
    {
        std::size_t done = 0;
        while (done < src.size())
        {
            std::error_code ec;
            const auto n = co_await s.async_write_some(src.subspan(done), ec);
            if (ec || n == 0)
            {
                co_return true;
            }
            done += n;
        }
        co_return false;
    }

} // namespace psmtest::stress
