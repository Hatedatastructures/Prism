/** @file Resources.hpp @brief 管理 provider ticket 拥有的 carriers 与协议 root。 */
#pragma once

#include <Prism/Protocols/Common/ProviderMuxRootState.hpp>
#include <Prism/Protocols/Common/Provider/Drain/Attempt.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <expected>
#include <memory>

namespace Prism::Protocols
{
    namespace Asio = boost::asio;

    /**
     * @brief 一个 provider ticket 的固定容量 transport 与 root resource owner。
     * @details ticket 负责 admission 和重试；本 owner 负责 carrier close、activity drain、
     *          物理退休核验与释放，避免 ticket 同时维护两套资源生命周期。
     */
    class ProviderSessionResources final
    {
        using Root = std::shared_ptr<ProviderMuxRootState::RootOwner>;
        using DrainResult = Detail::ProviderSessionDrainResult;

    public:
        explicit ProviderSessionResources(Prism::SharedTransmission Inbound) noexcept;

        [[nodiscard]] auto Track(const Prism::SharedTransmission& Transport)
            -> std::expected<void, Prism::Fault::Failure>;

        auto CloseRootOnly(const Root& RootValue) noexcept -> void
        {
            CloseRoot(RootValue);
        }

        /** @brief 同时请求 root 和已登记 transports 关闭，返回命令交付的首个真实错误。 */
        auto Close(const Root& RootValue) noexcept -> Prism::Fault::Failure;

        /** @brief 关闭晚于 owner close 登记的 carrier，必要时取消既有操作。 */
        auto CloseTransport(
            const Prism::SharedTransmission& Transport, bool CancelInFlight) noexcept
            -> Prism::Fault::Failure;

        /** @brief 在原 executor 上排空 root、Connection/replay 和入站 carrier。 */
        [[nodiscard]] auto Drain(
            const Root& RootValue, const Asio::any_io_executor& Executor)
            -> Asio::awaitable<DrainResult>;

        /** @brief 核验 root 与所有真实 transmission Activity 的物理退休回执。 */
        [[nodiscard]] auto IsRetired(const Root& RootValue) const noexcept -> bool;

        auto Release() noexcept -> void;

    private:
        static auto PreserveFailure(
            Prism::Fault::Failure& Primary,
            const Prism::Fault::Failure& Next) noexcept -> void;

        [[nodiscard]] static auto RootRetired(const Root& RootValue) noexcept -> bool;

        static auto CloseRoot(const Root& RootValue) noexcept -> void;

        [[nodiscard]] static auto DrainActivity(
            const std::shared_ptr<Prism::Contract::CarrierActivity>& Activity)
            -> Asio::awaitable<DrainResult>;

        [[nodiscard]] static auto DrainRoot(const Root& RootValue)
            -> Asio::awaitable<DrainResult>;

        [[nodiscard]] static auto DrainTransport(
            const Prism::SharedTransmission& Transport) -> Asio::awaitable<DrainResult>;

        std::array<std::atomic<Prism::SharedTransmission>, 4> Tracked_{};
        std::atomic<std::size_t> TrackedCount_{0U};
    };
}
