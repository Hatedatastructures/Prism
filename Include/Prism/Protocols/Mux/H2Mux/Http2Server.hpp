/** @file Http2Server.hpp @brief H2Mux HTTP/2 根 owner、并发准入和流实际退休。 */
#pragma once
#include <Prism/Protocols/Mux/H2Mux/Http2Dispatch.hpp>

#include <cstddef>
#include <expected>
#include <memory>
namespace Prism::Mux::H2Mux
{
    class Http2Server final : public std::enable_shared_from_this<Http2Server>
    {
    public:
        Http2Server(Prism::SharedTransmission Inbound, std::size_t MaxStreams,
            bool DeferAccept = false);

        /** @brief 外部 frame scope await root；退出前关闭连接并等待所有实际 retirement。 */
        [[nodiscard]] auto Run()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        /** @brief 重试同一连接的物理 drain；失败首因与 Run 共用 FailureState。 */
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        /** @brief 只读物理退休事实；历史 Failure 不阻止已排空 owner 退休。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool
        {
            return State_ && State_->Retired.load(std::memory_order_acquire);
        }

        auto BindIdentity(Prism::Lifecycle::TaskIdentity Identity) -> void
        {
            State_->Identity = Identity;
        }

    private:
        /** @brief 在固定 strand 中读取 HTTP/2 frame 并保留首个传输或协议失败。 */
        [[nodiscard]] auto RunLoop()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

    public:
        /** @brief 交付下一个 admitted stream；超限请求只收到 REFUSED_STREAM。 */
        [[nodiscard]] auto AcceptStream() -> Net::awaitable<std::shared_ptr<Http2Stream>>;

        auto Close() -> void;

        auto Cancel() -> void { Close(); }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor;

    private:
        std::shared_ptr<Http2State> State_;
    };
}
