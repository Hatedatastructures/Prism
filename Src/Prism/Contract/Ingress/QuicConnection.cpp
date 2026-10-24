/** @file QuicConnection.cpp @brief QUIC owner lease 与代次预约实现。 */
#include <Prism/Contract/Ingress/QuicConnection.hpp>

#include <expected>
#include <memory>
#include <utility>

namespace Prism::Contract
{
    QuicConnectionLease::QuicConnectionLease(std::shared_ptr<QuicConnectionOwner> Owner)
        : Owner_(std::move(Owner))
    {
    }

    QuicConnectionLease::QuicConnectionLease(QuicConnectionLease &&Other) noexcept
        : Owner_(std::move(Other.Owner_))
    {
    }

    auto QuicConnectionLease::operator=(QuicConnectionLease &&Other) noexcept
        -> QuicConnectionLease &
    {
        if (this != &Other)
        {
            (void)RequestClose();
            Owner_ = std::move(Other.Owner_);
        }
        return *this;
    }

    QuicConnectionLease::~QuicConnectionLease()
    {
        (void)RequestClose();
    }

    auto QuicConnectionLease::Start() -> void
    {
        if (Owner_)
        {
            Owner_->Start();
        }
    }

    auto QuicConnectionLease::ReceivePacket(
        std::span<const std::byte> Payload,
        const boost::asio::ip::udp::endpoint &Peer) const -> bool
    {
        return Owner_ && Owner_->ReceivePacket(Payload, Peer);
    }

    auto QuicConnectionLease::State() const noexcept -> QuicConnectionState
    {
        if (!Owner_)
        {
            return {false, true};
        }
        return Owner_->State();
    }

    auto QuicConnectionLease::RequestClose() noexcept
        -> std::expected<void, Prism::Fault::Failure>
    {
        return Owner_ ? Owner_->RequestClose()
                      : std::expected<void, Prism::Fault::Failure>{};
    }

    auto QuicConnectionLease::Drain()
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        return DrainOwned(Owner_);
    }

    auto QuicConnectionLease::DrainOwned(
        std::shared_ptr<QuicConnectionOwner> Owner)
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        if (!Owner)
        {
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        co_return co_await Owner->Drain();
    }

    auto QuicIngressBindingSnapshot::AcquireUse() const
        -> std::expected<QuicConnectionGenerationLease, Prism::Fault::Failure>
    {
        if (!IsValid() || !HasListener())
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
        }
        auto Use = UseState_->Acquire();
        if (!Use)
        {
            return std::unexpected(Use.error());
        }
        return QuicConnectionGenerationLease{
            Generation(), Listener_->Id, std::move(*Use)};
    }
}
