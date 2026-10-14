/** @file RootBinding.hpp @brief Mux root 的正式注册 binding 与 nested-child factory。 */
#pragma once
#include <Preview/Contract/Ingress/MuxRootCreateRequest.hpp>
#include <Preview/Contract/Ingress/MuxSession.hpp>
#include <Preview/Protocols/Mux/RootOptions.hpp>
#include <Preview/Protocols/Mux/Detail/Root/RootRegistry.hpp>
#include <boost/asio/awaitable.hpp>
#include <atomic>
#include <expected>
#include <memory>
#include <utility>

namespace Preview::Mux
{
    namespace Net = boost::asio;

    /** @brief Binding 接受后交给调用方的正式 root session 与入站 data plane。 */
    struct RootCreateResult final
    {
        std::shared_ptr<Preview::Contract::MuxSession> Session;
        Preview::Contract::ProtocolDataPlane Plane;
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

        [[nodiscard]] auto Create(Preview::Contract::MuxRootCreateRequest &Request)
            -> std::expected<std::shared_ptr<Preview::Contract::MuxSession>,
                             Preview::Fault::Failure>
        {
            if (!Options_.Services.Egress || !Options_.GenerationUseState ||
                Request.GenerationUseState() != Options_.GenerationUseState)
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            auto Created = Detail::RootSession::Create(Request, Options_);
            if (!Created) return std::unexpected(Created.error());
            return std::static_pointer_cast<Preview::Contract::MuxSession>(
                std::move(*Created));
        }

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
        [[nodiscard]] auto Create(Preview::Contract::MuxRootCreateRequest Request)
            -> std::expected<RootCreateResult, Preview::Fault::Failure>
        {
            const auto Options = Options_.load(std::memory_order_acquire);
            if (Roots_.IsClosed() || !Options || !Options->Services.Egress ||
                !Options->GenerationUseState)
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            }
            if (Request.GenerationUseState() != Options->GenerationUseState)
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }

            auto Created = Detail::RootSession::Create(Request, *Options);
            if (!Created) return std::unexpected(Created.error());
            auto Registration = Roots_.Register(*Created);
            if (!Registration || Roots_.IsClosed())
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            }

            auto Plane = Request.TakePlane();
            Request.Transfer();
            return RootCreateResult{
                std::static_pointer_cast<Preview::Contract::MuxSession>(
                    std::move(*Created)),
                std::move(Plane)};
        }

        /** @brief 请求 registry 中已发布 roots 取消，不清除 owner 或 options。 */
        auto Close() noexcept -> void { Roots_.Close(); }

        /** @brief 等待 roots 的真实关闭与退休；完成后释放 options snapshot。 */
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            const auto Result = co_await Roots_.Drain();
            if (Roots_.IsRetired()) Options_.store({}, std::memory_order_release);
            if (!Result) co_return std::unexpected(Result.error());
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        [[nodiscard]] auto GenerationUseState() const noexcept
            -> std::shared_ptr<Preview::Foundation::GenerationUseState>
        {
            const auto Options = Options_.load(std::memory_order_acquire);
            return Options ? Options->GenerationUseState : nullptr;
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool
        {
            return Roots_.IsRetired() && !Options_.load(std::memory_order_acquire);
        }

    private:
        std::atomic<std::shared_ptr<const RootOptions>> Options_;
        Detail::RootRegistry Roots_;
    };
}
