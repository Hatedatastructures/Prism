/** @file SessionRegistryStreamCatalog.hpp @brief 注册会话上的 stream catalog 查询和重置 owner。 */
#pragma once

#include <Prism/Contract/Ingress/StreamCatalog.hpp>
#include <Prism/Runtime/SessionRegistryStorage.hpp>

#include <boost/asio/awaitable.hpp>

#include <expected>
#include <memory>
#include <utility>

namespace Prism::Runtime::Detail
{
    /**
     * @brief 通过已注册 SessionControl 查询和重置单一 Mux stream。
     * @details 本 owner 固定注册表状态快照，校验 worker、generation、root task 后，
     *          把唯一 stream 的协议 reset 与真实 child retirement 交给该 SessionControl。
     */
    class SessionRegistryStreamCatalog final
    {
        using State = SessionRegistryState;
        using Storage = SessionRegistryStorage;

    public:
        explicit SessionRegistryStreamCatalog(std::shared_ptr<State> StateValue)
            : State_(std::move(StateValue))
        {
        }

        /** @brief 按完整父身份复制真实 protocol stream 描述；不查询 task 表冒充流状态。 */
        [[nodiscard]] auto Find(
            const Prism::Contract::Ingress::StreamIdentity &Identity) const noexcept
            -> Prism::Contract::Ingress::StreamCatalogLookup;

        /** @brief 按完整父身份枚举该会话的 live stream；缺少真实 catalog 返回 unavailable。 */
        [[nodiscard]] auto List(
            const Prism::Contract::Ingress::StreamListRequest &Request) const
            -> Prism::Contract::Ingress::StreamCatalogPage;

        /** @brief 校验完整 parent scope 后取消单一 stream 并等待真实 child retirement。 */
        [[nodiscard]] auto ResetAndDrain(
            Prism::Contract::Ingress::StreamResetRequest Request)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            return RunReset(State_, std::move(Request));
        }

    private:
        [[nodiscard]] static auto RunReset(
            std::shared_ptr<State> StateValue,
            Prism::Contract::Ingress::StreamResetRequest Request)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;

        std::shared_ptr<State> State_;
    };
}
