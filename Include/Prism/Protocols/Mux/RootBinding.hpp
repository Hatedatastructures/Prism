/** @file RootBinding.hpp @brief Mux root 的正式注册 binding 与 nested-child factory。 */
#pragma once
#include <Prism/Contract/Ingress/MuxRootCreateRequest.hpp>
#include <Prism/Contract/Ingress/MuxSession.hpp>
#include <Prism/Protocols/Mux/RootOptions.hpp>
#include <Prism/Protocols/Mux/Root/Registry.hpp>
#include <boost/asio/awaitable.hpp>
#include <atomic>
#include <expected>
#include <memory>
#include <utility>

namespace Prism::Mux
{
    namespace Net = boost::asio;

    /** @brief Binding 接受后交给调用方的正式 root session 与入站 data plane。 */
    struct RootCreateResult final
    {
        std::shared_ptr<Prism::Contract::MuxSession> Session;
        Prism::Contract::ProtocolDataPlane Plane;
    };

    /**
     * @brief 创建由唯一 AnyTLS 父 stream ticket 拥有的嵌套 root。
     * @details 不建立全局 registry；成功后父 stream 的 admission ticket 持有 session，
     *          ParentStreamLease、GenerationUseLease 与 Plane 沿同一请求完成 transfer。
     *          实际 session 创建只调用 Detail::RootSession::Create，与 RootBinding 共用实现。
     */
    class NestedRootFactory final
    {
    public:
        explicit NestedRootFactory(RootOptions Options) : Options_(std::move(Options)) {}

        [[nodiscard]] auto Create(Prism::Contract::MuxRootCreateRequest &Request)
            -> std::expected<std::shared_ptr<Prism::Contract::MuxSession>,
                             Prism::Fault::Failure>;

    private:
        RootOptions Options_;
    };

    /**
     * @brief 冷路径 typed mux factory 与全局 RootSession 生命周期目录。
     * @details Create 只消费握手前已预约的 owner ticket。Registry 的 intrusive node
     *          强持有未退休 root，直到 children、loops、engine 与 carrier 真实退休。
     */
    class RootBinding final
    {
    public:
        explicit RootBinding(RootOptions Options)
            : Options_(std::make_shared<const RootOptions>(std::move(Options)))
        {
        }

        /**
         * @brief 消费唯一已预约 root 请求并发布正式 root session。
         * @param Request 已持完整 Plane/account lease 与同代 GenerationUseLease 的 move-only 请求。
         * @return 成功时返回正式 session facade 与保留 account lease 的 data plane。
         */
        [[nodiscard]] auto Create(Prism::Contract::MuxRootCreateRequest Request)
            -> std::expected<RootCreateResult, Prism::Fault::Failure>;

        /** @brief 关闭 registry；活动 root 保留取消结果，不清除 owner 或 options。 */
        auto Close() noexcept -> void { Roots_.Close(); }

        /** @brief 正常关闭并封止注册；供 catalog shutdown 在 Drain 前请求。 */
        auto CloseForDrain() noexcept -> void { Roots_.CloseForDrain(); }

        /** @brief 等待 roots 的真实关闭与退休；完成后释放 options snapshot。 */
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        [[nodiscard]] auto GenerationUseState() const noexcept
            -> std::shared_ptr<Prism::Foundation::GenerationUseState>
        {
            const auto Options = Options_.load(std::memory_order_acquire);
            return Options ? Options->GenerationUseState : nullptr;
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool
        {
            return Roots_.IsRetired() && !Options_.load(std::memory_order_acquire);
        }

        /** @brief 返回 registry 内 root 已记录的持久终态首因，不包含可重试 attempt cancellation。 */
        [[nodiscard]] auto DrainFailure() const noexcept -> Prism::Fault::Failure
        {
            return Roots_.DrainFailure();
        }

    private:
        std::atomic<std::shared_ptr<const RootOptions>> Options_;
        Detail::RootRegistry Roots_;
    };
}
