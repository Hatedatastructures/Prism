/** @file QuicFactory.hpp @brief QUIC registry 测试的 Native owner 与 UDP 发送端口。 */
#pragma once
#include <Preview/Contract/Ingress/QuicConnection.hpp>
#include <Preview/Contract/Ingress/DatagramIngressSelection.hpp>
#include <Preview/Contract/Services/Quic.hpp>
#include <Preview/Foundation/Identifier/SessionIdAllocator.hpp>
#include <Preview/Protocols/Quic/Native.hpp>
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
namespace Preview::Testing::Quic
{
    namespace Net = boost::asio;
    using Udp = Net::ip::udp;

    /** @brief 只由测试 Boundary 持有的 socket 发送实现。 */
    class SocketDatagramSender final : public Preview::Contract::QuicDatagramSender
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
        -> std::shared_ptr<Preview::Contract::QuicDatagramSender>
    {
        return std::make_shared<SocketDatagramSender>(std::move(Socket));
    }

    class NativeOwner final : public Preview::Contract::QuicConnectionOwner
    {
    public:
        explicit NativeOwner(std::shared_ptr<Preview::Quic::Server> Server,
            Preview::Contract::QuicConnectionGenerationLease GenerationUse = {})
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
            -> Preview::Contract::QuicConnectionState override
        {
            const auto Health = Server_->Health();
            return {Health.HandshakeReady, Health.Closed};
        }

        [[nodiscard]] auto RequestClose() noexcept
            -> std::expected<void, Preview::Fault::Failure> override
        {
            if (!Server_)
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            Server_->Close();
            return {};
        }

        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            const auto Result = co_await Server_->Drain();
            if (Result)
            {
                GenerationUse_ = {};
            }
            co_return Result;
        }

    private:
        std::shared_ptr<Preview::Quic::Server> Server_;
        Preview::Contract::QuicConnectionGenerationLease GenerationUse_;
    };

    class Generation final : public Preview::Foundation::GenerationLifetime
    {
    public:
        explicit Generation(Preview::GenerationId Value) : Value_(Value) {}
        [[nodiscard]] auto Id() const noexcept -> Preview::GenerationId override { return Value_; }

    private:
        Preview::GenerationId Value_;
    };

    [[nodiscard]] inline auto MakeIngress(
        std::shared_ptr<Preview::Contract::QuicConnectionFactory> Factory = {},
        Preview::GenerationId GenerationIdValue = Preview::GenerationId{17},
        std::string BindingId = "quic-fixture")
        -> std::shared_ptr<const Preview::Contract::QuicIngressBindingSnapshot>
    {
        const auto GenerationOwner = std::make_shared<Generation>(GenerationIdValue);
        const auto UseState = std::make_shared<Preview::Foundation::GenerationUseState>();
        Preview::Contract::RequestMetadata Metadata;
        Metadata.TaskIdentity.Generation = GenerationOwner->Id();
        std::optional<Preview::Contract::QuicIngressBindingSnapshot::Binding> Listener;
        if (Factory)
        {
            Listener.emplace(Preview::Contract::QuicIngressBindingSnapshot::Binding{
                std::move(BindingId), std::move(Factory)});
        }
        return std::make_shared<const Preview::Contract::QuicIngressBindingSnapshot>(
            Preview::Contract::QuicIngressBindingSnapshot::Options{
                GenerationOwner, UseState, std::move(Metadata), std::move(Listener)});
    }

    [[nodiscard]] inline auto MakeSelection(
        std::shared_ptr<const Preview::Contract::QuicIngressBindingSnapshot> Quic)
        -> std::shared_ptr<const Preview::Contract::DatagramIngressSelection>
    {
        const auto GenerationOwner = Quic->GenerationOwner();
        const auto UseState = Quic->UseState();
        auto Raw = std::make_shared<const Preview::Contract::RawDatagramIngressSnapshot>(
            Preview::Contract::RawDatagramIngressSnapshot::Options{
                GenerationOwner->Id(), UseState, {}, {}});
        return std::make_shared<const Preview::Contract::DatagramIngressSelection>(
            Preview::Contract::DatagramIngressSelection::Options{
                GenerationOwner, UseState, std::move(Raw), std::move(Quic)});
    }

    struct QuicFactoryRequest final
    {
        std::shared_ptr<Preview::Contract::QuicConnectionFactory> Factory;
        Preview::GenerationId Generation;
        std::string BindingId;
        std::vector<std::byte> ConnectionId;
        Udp::endpoint Peer;
        std::function<void()> OnClosed;
        std::shared_ptr<Preview::Foundation::GenerationUseState>* UseState{nullptr};
    };

    [[nodiscard]] inline auto MakeRequest(QuicFactoryRequest Value)
        -> Preview::Contract::QuicAcceptRequest
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
        Metadata.TaskIdentity.SessionId = Preview::Foundation::Identifier::ReserveSessionId();
        return {std::move(Value.ConnectionId), std::move(Value.Peer), std::move(Value.OnClosed),
            std::move(Metadata), std::move(*GenerationUse)};
    }

    inline auto MakeLease(std::shared_ptr<Preview::Quic::Server> Server)
        -> std::shared_ptr<Preview::Contract::QuicConnectionLease>
    {
        static std::unordered_map<Preview::Quic::Server*,
            std::weak_ptr<Preview::Contract::QuicConnectionLease>> Leases;
        if (auto Lease = Leases[Server.get()].lock()) return Lease;
        auto Lease = std::make_shared<Preview::Contract::QuicConnectionLease>(
            std::make_shared<NativeOwner>(Server));
        Leases[Server.get()] = Lease;
        return Lease;
    }

    class RecordingFactory final : public Preview::Contract::QuicConnectionFactory
    {
    public:
        using CreateFn = std::function<std::shared_ptr<Preview::Quic::Server>(
            Preview::Contract::QuicAcceptRequest)>;

        explicit RecordingFactory(CreateFn Create) : Create_(std::move(Create))
        {
        }

        auto Create(Preview::Contract::QuicAcceptRequest Request)
            -> std::expected<Preview::Contract::QuicConnectionLease,
                Preview::Contract::ProviderFailure> override
        {
            auto GenerationUse = std::move(Request.GenerationUse);
            auto Server = Create_(std::move(Request));
            if (!Server)
            {
                return std::unexpected(Preview::Contract::ProviderFailure{
                    Preview::Contract::ProviderError::InvalidConfiguration,
                    {}, "Test.Native"});
            }
            return Preview::Contract::QuicConnectionLease(
                std::make_shared<NativeOwner>(std::move(Server), std::move(GenerationUse)));
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override { return false; }

    private:
        CreateFn Create_;
    };

    inline auto MakeFactory(RecordingFactory::CreateFn Create)
        -> std::shared_ptr<Preview::Contract::QuicConnectionFactory>
    {
        return std::make_shared<RecordingFactory>(std::move(Create));
    }
}
