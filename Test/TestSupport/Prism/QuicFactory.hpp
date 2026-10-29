/** @file QuicFactory.hpp @brief QUIC registry 测试的 Native owner 与 UDP 发送端口。 */
#pragma once
#include <Prism/Contract/Ingress/QuicConnection.hpp>
#include <Prism/Contract/Ingress/Datagram/Selection.hpp>
#include <Prism/Contract/Services/Quic.hpp>
#include <Prism/Foundation/Identifier/SessionIdAllocator.hpp>
#include <Prism/Protocols/Quic/Native.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <cstddef>
#include <expected>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <stdexcept>
namespace Prism::Testing::Quic
{
    namespace Net = boost::asio;
    using Udp = Net::ip::udp;

    /** @brief 只由测试 Boundary 持有的 socket 发送实现。 */
    class SocketDatagramSender final : public Prism::Contract::QuicDatagramSender
    {
    public:
        explicit SocketDatagramSender(std::shared_ptr<Udp::socket> Socket)
            : Socket_(std::move(Socket))
        {
        }

        [[nodiscard]] auto SendTo(
            const std::span<const std::byte> Payload,
            const Udp::endpoint& Peer)
            -> Net::awaitable<boost::system::error_code> override
        {
            if (!Socket_ || !Socket_->is_open())
            {
                co_return boost::system::errc::make_error_code(
                    boost::system::errc::operation_canceled);
            }
            boost::system::error_code Error;
            const auto Length = co_await Socket_->async_send_to(
                Net::buffer(Payload.data(), Payload.size()), Peer,
                Net::redirect_error(Net::use_awaitable, Error));
            if (!Error && Length != Payload.size())
            {
                co_return boost::system::errc::make_error_code(
                    boost::system::errc::message_size);
            }
            co_return Error;
        }

    private:
        std::shared_ptr<Udp::socket> Socket_;
    };

    [[nodiscard]] inline auto MakeSender(std::shared_ptr<Udp::socket> Socket)
        -> std::shared_ptr<Prism::Contract::QuicDatagramSender>
    {
        return std::make_shared<SocketDatagramSender>(std::move(Socket));
    }

    class NativeOwner final : public Prism::Contract::QuicConnectionOwner
    {
    public:
        explicit NativeOwner(std::shared_ptr<Prism::Quic::Server> Server,
            Prism::Contract::QuicConnectionGenerationLease GenerationUse = {})
            : Server_(std::move(Server)), GenerationUse_(std::move(GenerationUse))
        {
        }

        auto Start() -> void override { Server_->Start(); }

        [[nodiscard]] auto ReceivePacket(
            const std::span<const std::byte> Payload,
            const Udp::endpoint& Peer) -> bool override
        {
            return Server_->ReceivePacket(Payload, Peer);
        }

        [[nodiscard]] auto State() const noexcept
            -> Prism::Contract::QuicConnectionState override
        {
            const auto Health = Server_->Health();
            return {Health.HandshakeReady, Health.Closed};
        }

        [[nodiscard]] auto RequestClose() noexcept
            -> std::expected<void, Prism::Fault::Failure> override
        {
            if (!Server_)
            {
                return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            Server_->Close();
            return {};
        }

        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            const auto Result = co_await Server_->Drain();
            if (Result)
            {
                GenerationUse_ = {};
            }
            co_return Result;
        }

    private:
        std::shared_ptr<Prism::Quic::Server> Server_;
        Prism::Contract::QuicConnectionGenerationLease GenerationUse_;
    };

    class Generation final : public Prism::Foundation::GenerationLifetime
    {
    public:
        explicit Generation(Prism::GenerationId Value) : Value_(Value) {}
        [[nodiscard]] auto Id() const noexcept -> Prism::GenerationId override { return Value_; }

    private:
        Prism::GenerationId Value_;
    };

    [[nodiscard]] inline auto MakeIngress(
        std::shared_ptr<Prism::Contract::QuicConnectionFactory> Factory = {},
        Prism::GenerationId GenerationIdValue = Prism::GenerationId{17},
        std::string BindingId = "quic-fixture")
        -> std::shared_ptr<const Prism::Contract::QuicIngressBindingSnapshot>
    {
        const auto GenerationOwner = std::make_shared<Generation>(GenerationIdValue);
        const auto UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
        Prism::Contract::RequestMetadata Metadata;
        Metadata.TaskIdentity.Generation = GenerationOwner->Id();
        std::optional<Prism::Contract::QuicIngressBindingSnapshot::Binding> Listener;
        if (Factory)
        {
            Listener.emplace(Prism::Contract::QuicIngressBindingSnapshot::Binding{
                std::move(BindingId), std::move(Factory)});
        }
        return std::make_shared<const Prism::Contract::QuicIngressBindingSnapshot>(
            Prism::Contract::QuicIngressBindingSnapshot::Options{
                GenerationOwner, UseState, std::move(Metadata), std::move(Listener)});
    }

    [[nodiscard]] inline auto MakeSelection(
        std::shared_ptr<const Prism::Contract::QuicIngressBindingSnapshot> Quic)
        -> std::shared_ptr<const Prism::Contract::DatagramIngressSelection>
    {
        const auto GenerationOwner = Quic->GenerationOwner();
        const auto UseState = Quic->UseState();
        auto Raw = std::make_shared<const Prism::Contract::RawDatagramIngressSnapshot>(
            Prism::Contract::RawDatagramIngressSnapshot::Options{
                GenerationOwner->Id(), UseState, {}, {}});
        return std::make_shared<const Prism::Contract::DatagramIngressSelection>(
            Prism::Contract::DatagramIngressSelection::Options{
                GenerationOwner, UseState, std::move(Raw), std::move(Quic)});
    }

    struct QuicFactoryRequest final
    {
        std::shared_ptr<Prism::Contract::QuicConnectionFactory> Factory;
        Prism::GenerationId Generation;
        std::string BindingId;
        std::vector<std::byte> ConnectionId;
        Udp::endpoint Peer;
        std::function<void()> OnClosed;
        std::shared_ptr<Prism::Foundation::GenerationUseState>* UseState{nullptr};
    };

    [[nodiscard]] inline auto MakeRequest(QuicFactoryRequest Value)
        -> Prism::Contract::QuicAcceptRequest
    {
        const auto Ingress = MakeIngress(
            std::move(Value.Factory), Value.Generation, Value.BindingId);
        auto GenerationUse = Ingress->AcquireUse();
        if (!GenerationUse)
        {
            throw std::runtime_error("QUIC fixture could not acquire generation use");
        }
        if (Value.UseState)
        {
            *Value.UseState = Ingress->UseState();
        }
        auto Metadata = Ingress->Metadata();
        Metadata.TaskIdentity.SessionId = Prism::Foundation::Identifier::ReserveSessionId();
        return {std::move(Value.ConnectionId), std::move(Value.Peer), std::move(Value.OnClosed),
            std::move(Metadata), std::move(*GenerationUse)};
    }

    inline auto MakeLease(std::shared_ptr<Prism::Quic::Server> Server)
        -> std::shared_ptr<Prism::Contract::QuicConnectionLease>
    {
        static std::unordered_map<Prism::Quic::Server*,
            std::weak_ptr<Prism::Contract::QuicConnectionLease>> Leases;
        if (auto Lease = Leases[Server.get()].lock()) return Lease;
        auto Lease = std::make_shared<Prism::Contract::QuicConnectionLease>(
            std::make_shared<NativeOwner>(Server));
        Leases[Server.get()] = Lease;
        return Lease;
    }

    class RecordingFactory final : public Prism::Contract::QuicConnectionFactory
    {
    public:
        using CreateFn = std::function<std::shared_ptr<Prism::Quic::Server>(
            Prism::Contract::QuicAcceptRequest)>;

        explicit RecordingFactory(CreateFn Create) : Create_(std::move(Create))
        {
        }

        auto Create(Prism::Contract::QuicAcceptRequest Request)
            -> std::expected<Prism::Contract::QuicConnectionLease,
                Prism::Contract::ProviderFailure> override
        {
            auto GenerationUse = std::move(Request.GenerationUse);
            auto Server = Create_(std::move(Request));
            if (!Server)
            {
                return std::unexpected(Prism::Contract::ProviderFailure{
                    Prism::Contract::ProviderError::InvalidConfiguration,
                    {}, "Test.Native"});
            }
            return Prism::Contract::QuicConnectionLease(
                std::make_shared<NativeOwner>(std::move(Server), std::move(GenerationUse)));
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override { return false; }

    private:
        CreateFn Create_;
    };

    inline auto MakeFactory(RecordingFactory::CreateFn Create)
        -> std::shared_ptr<Prism::Contract::QuicConnectionFactory>
    {
        return std::make_shared<RecordingFactory>(std::move(Create));
    }
}
