/**
 * @file DatagramSession.hpp
 * @brief 协议拥有的数据报会话生命周期。
 */
#pragma once

#include <boost/asio/awaitable.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <expected>
#include <Preview/Contract/Io/CarrierActivity.hpp>
#include <memory>

namespace Preview::Contract
{
    /**
     * @brief 协议会话拥有控制流与私有数据报 socket，并负责最终关闭。
     * @details 所有操作在创建会话的 executor 执行；Run 只允许一次，完成表示
     *          所有子操作已退栈。Cancel 取消解析和 I/O；Close 幂等关闭资源。
     *          数据报无半关闭。调用方持有 owner 直到 Run 完成。
     */
    class DatagramSession
    {
    public:
        virtual ~DatagramSession() = default;
        /** @brief 共享真实Run、pump、deadline与completion退栈owner；必须固定其原executor，不提供空能力。 */
        [[nodiscard]] virtual auto Activity() const
            -> std::shared_ptr<Preview::Contract::CarrierActivity> = 0;
        /**
         * @brief 运行该协议唯一的数据报泵并等待自身 I/O 真实退栈。
         * @return 空 expected 表示协议正常边界和子操作成功。取消返回 Canceled，
         *         可用 operation_aborted/native identity 随首因保留。
         */
        [[nodiscard]] virtual auto Run()
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>> = 0;
        virtual auto Cancel() noexcept -> void = 0;
        virtual auto Close() noexcept -> void = 0;
    };
}
