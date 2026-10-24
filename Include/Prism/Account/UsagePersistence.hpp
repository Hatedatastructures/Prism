/** @file UsagePersistence.hpp
 * @brief Account 持久账本的唯一异步端口，不包含 SQL、路径或数据库线程。
 */
#pragma once
#include <Prism/Account/UsageModels.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <boost/asio/awaitable.hpp>
#include <expected>

namespace Prism::Account
{
    /**
     * @brief 领域请求按值拥有输入，完成回到调用协程 executor；实现拥有独立存储执行域。
     * @details 已提交事务不因调用取消回滚；结果丢失由 RequestKey 查询恢复，不能盲目重发。
     *          不关闭任何网络连接；最终连接关闭归数据面 owner，存储关闭由 Application 等待。
     */
    class UsagePersistence
    {
    public:
        virtual ~UsagePersistence() = default;
        [[nodiscard]] virtual auto ResolveCycle(UsageCycleRequest Request)
            -> boost::asio::awaitable<std::expected<UsageCycle, Fault::Failure>> = 0;
        [[nodiscard]] virtual auto Read(UsageReadRequest Request)
            -> boost::asio::awaitable<std::expected<UsageSnapshot, Fault::Failure>> = 0;
        [[nodiscard]] virtual auto Reserve(UsageReservationRequest Request)
            -> boost::asio::awaitable<std::expected<UsageReservation, Fault::Failure>> = 0;
        [[nodiscard]] virtual auto Settle(UsageSettlementRequest Request)
            -> boost::asio::awaitable<std::expected<UsageSnapshot, Fault::Failure>> = 0;
        [[nodiscard]] virtual auto Adjust(UsageAdjustmentRequest Request)
            -> boost::asio::awaitable<std::expected<UsageSnapshot, Fault::Failure>> = 0;
    };
}
