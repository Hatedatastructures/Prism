/**
 * @file QuicConnectionLifecycle.hpp
 * @brief 单条 QUIC connection 的关闭门与资源所有权声明。
 */
#pragma once

#include <Prism/Contract/Ingress/QuicConnection.hpp>
#include <Prism/Contract/Services/Quic.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Foundation/Utility/TrafficSink.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>
#include <Prism/Protocols/Common/QuicBindingState.hpp>
#include <Prism/Protocols/Quic/Native.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ssl/context.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <exception>
#include <functional>
#include <memory>
#include <span>
#include <string>

namespace Prism::Protocols
{

    /** @brief 创建一条 Native QUIC connection 所需的 owning 输入。 */
    struct QuicConnectionPreparation final
    {
        Prism::Contract::QuicListenerResources Listener;
        Prism::Contract::QuicAcceptRequest Request;
        std::shared_ptr<QuicBindingState> Lifetime;
        Prism::Foundation::GenerationPin Generation;
        std::shared_ptr<Prism::Foundation::TrafficSink> Traffic{};
    };

    /**
     * @brief QUIC connection 的唯一关闭 owner。
     * @details owner 固定 listener executor，协调 native 和协议 child drain；最终 UDP socket 关闭权仍归 Boundary。
     */
    class QuicConnectionLifecycle : public Prism::Contract::QuicConnectionOwner,
        public std::enable_shared_from_this<QuicConnectionLifecycle>
    {
        enum class CloseRequestState : std::uint8_t
        {
            Open,
            Submitting,
            Queued,
            Finalizing,
            Completed,
            Failed,
        };

    public:
        explicit QuicConnectionLifecycle(QuicConnectionPreparation Input);
        ~QuicConnectionLifecycle() override;

        auto Start() -> void override;
        [[nodiscard]] auto ReceivePacket(
            std::span<const std::byte> Payload,
            const boost::asio::ip::udp::endpoint& Peer) -> bool override;
        [[nodiscard]] auto State() const noexcept
            -> Prism::Contract::QuicConnectionState override;
        [[nodiscard]] auto RequestClose() noexcept
            -> std::expected<void, Prism::Fault::Failure> override;
        [[nodiscard]] auto Drain()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> override;

    protected:
        /** @brief 协议内部共享同一 native server，不向 Boundary 暴露具体实现。 */
        [[nodiscard]] auto NativeServer() const -> std::shared_ptr<Prism::Quic::Server>;
        [[nodiscard]] auto Options() -> Prism::Quic::ServerOptions;
        auto Install(Prism::Quic::ServerOptions Value) -> void;
        [[nodiscard]] auto Executor() const -> boost::asio::any_io_executor;
        [[nodiscard]] auto SourceIp() const -> std::string;
        [[nodiscard]] auto Metadata() const noexcept
            -> const Prism::Contract::RequestMetadata&;
        /** @brief 派生协议把已发生的协议关闭失败交给本 connection 的唯一首因。 */
        auto RecordProtocolFailure(Prism::Fault::Failure Reason) noexcept -> void;
        virtual auto CloseProtocol() -> void = 0;
        [[nodiscard]] virtual auto DrainProtocol()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> = 0;

    private:
        [[nodiscard]] static auto DrainOwned(
            std::shared_ptr<QuicConnectionLifecycle> Owner)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;
        [[nodiscard]] auto DrainOnExecutor()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;
        [[nodiscard]] auto CanDispatch() const noexcept -> bool;
        auto RequestCloseFromNativeNotification() noexcept -> void;
        auto RecordFailure(Prism::Fault::Failure Reason) noexcept -> void;
        auto PublishFatal(std::exception_ptr Error) noexcept -> void;
        auto StartFinalizer() -> void;
        [[nodiscard]] auto Finalize()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;
        auto Complete(std::expected<void, Prism::Fault::Failure> Result) noexcept -> void;

        Prism::Contract::QuicListenerResources Listener_;
        /// 释放 listener 时仍由 Native owner 保留 TLS 原始材料。
        std::shared_ptr<boost::asio::ssl::context> NativeTls_;
        boost::asio::ip::udp::endpoint Peer_;
        std::function<void()> Observer_;
        Prism::Contract::RequestMetadata Metadata_;
        std::shared_ptr<Prism::Foundation::TrafficSink> Traffic_;
        std::weak_ptr<QuicBindingState> Lifetime_;
        Prism::Foundation::GenerationPin Generation_;
        Prism::Contract::QuicConnectionGenerationLease GenerationUse_;
        std::shared_ptr<Prism::Executor::ContextOwner> Context_;
        std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer_;
        Prism::Lifecycle::DrainBarrier Barrier_;
        std::shared_ptr<Prism::Quic::Server> Server_;
        std::atomic<CloseRequestState> CloseRequest_{CloseRequestState::Open};
        Prism::Fault::FailureState Failure_;
    };

} // namespace Prism::Protocols
