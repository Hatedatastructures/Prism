/**
 * @file Maintenance.hpp
 * @brief DNS Resolver 后台维护协程
 * @details 周期执行缓存过期驱逐、single-flight 清理和上游连接池清扫。
 *          通过状态模板接收资源对象，detached 协程不依赖 Resolver 裸指针。
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <chrono>
#include <memory>

namespace Preview::Network::Dns::Detail
{

    /**
     * @brief 执行 Resolver 后台维护循环
     * @tparam State Resolver 共享状态类型
     * @param state 由共享指针持有的维护状态
     * @return 后台协程
     */
    template <typename State>
    [[nodiscard]] inline auto MaintenanceLoop(std::shared_ptr<State> StateObject)
        -> boost::asio::awaitable<void>
    {
        while (StateObject->Alive_->load(std::memory_order_acquire))
        {
            StateObject->MaintenanceTimer_.expires_after(std::chrono::seconds(30));
            boost::system::error_code ErrorCode;
            co_await StateObject->MaintenanceTimer_.async_wait(
                boost::asio::redirect_error(boost::asio::use_awaitable, ErrorCode));
            if (ErrorCode == boost::asio::error::operation_aborted ||
                !StateObject->Alive_->load(std::memory_order_acquire))
            {
                co_return;
            }
            StateObject->Cache_.EvictExpired();
            StateObject->Coalescer_.FlushCleanup();
            StateObject->Upstream_->ClearIdleConns();
        }
    }

} // namespace Preview::Network::Dns::Detail
