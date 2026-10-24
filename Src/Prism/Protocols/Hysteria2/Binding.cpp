/**
 * @file Binding.cpp
 * @brief Hysteria2 配置准备与 QUIC provider 生命周期。
 */
#include <Prism/Protocols/Hysteria2/Binding.hpp>

#include <Prism/Protocols/Hysteria2/NativeSession.hpp>

#include <string>
#include <utility>

namespace Prism::Hysteria2
{

    [[nodiscard]] auto Prepare(
        Prism::Protocols::QuicPreparation Input,
        BindingServices Services)
        -> std::expected<Prepared, Prism::Contract::ProviderFailure>
    {
        auto Valid = Prism::Protocols::ValidateQuic(Input, Services.Network);
        if (!Valid)
        {
            return std::unexpected(Valid.error());
        }
        if (!Services.Http3)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::MissingHttp3,
                Input.Instance,
                "Quic.Http3"});
        }
        auto Record = Prism::Protocols::ValidateQuicAuthentication(
            Input, Services.Authentication);
        if (!Record)
        {
            return std::unexpected(Record.error());
        }
        return Prepared(std::move(Input), std::move(Services), std::move(*Record));
    }

    Binding::Binding(Prepared Value)
        : Prepared_(std::make_shared<const Prepared>(std::move(Value))),
          Lifetime_(std::make_shared<Prism::Protocols::QuicBindingState>(
              Prepared_.load()->Services.Network.Listener.Executor))
    {
    }

    Binding::~Binding()
    {
        Close();
        Lifetime_->HoldPending();
    }

    [[nodiscard]] auto Binding::Create(Prism::Contract::QuicAcceptRequest Request)
        -> std::expected<Prism::Contract::QuicConnectionLease,
            Prism::Contract::ProviderFailure>
    {
        auto Value = Prepared_.load();
        if (!Value || Lifetime_->Closed() || !Lifetime_->CanAdmit())
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::DispatchUnavailable,
                Value ? Value->Input.Instance : std::string{},
                "Quic.Accept"});
        }
        if (!Request.GenerationUse || !Value->Input.Generation ||
            Request.GenerationUse.Generation() != Value->Input.Generation->Id() ||
            Request.GenerationUse.BindingId() != Value->Input.Instance ||
            Request.Metadata.TaskIdentity.Generation != Value->Input.Generation->Id())
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::GenerationMismatch,
                Value->Input.Instance,
                "Quic.Generation"});
        }
        auto Owner = std::make_shared<NativeSession>(
            Value,
            Prism::Protocols::QuicConnectionPreparation{
                Value->Services.Network.Listener,
                std::move(Request),
                Lifetime_,
                Value->Input.Generation,
                Value->Services.Network.Traffic});
        Owner->Build();
        if (!Lifetime_->Track(Owner))
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::Cancelled,
                Value->Input.Instance,
                "Quic.Accept"});
        }
        return Prism::Contract::QuicConnectionLease(std::move(Owner));
    }

    auto Binding::Close() noexcept -> void
    {
        Lifetime_->Close();
    }

    [[nodiscard]] auto Binding::IsRetired() const noexcept -> bool
    {
        return Lifetime_->IsRetired() && !Prepared_.load(std::memory_order_acquire);
    }

    [[nodiscard]] auto Binding::Drain()
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        Close();
        const auto Drained = co_await Lifetime_->Drain();
        if (Lifetime_->IsRetired())
        {
            Prepared_.store({}, std::memory_order_release);
        }
        if (!Drained)
        {
            co_return std::unexpected(Drained.error());
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    [[nodiscard]] auto Bind(Prepared Value, std::stop_token Stop)
        -> std::expected<std::shared_ptr<Binding>, Prism::Contract::ProviderFailure>
    {
        if (Stop.stop_requested())
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::Cancelled, Value.Input.Instance, "Bind"});
        }
        auto Verified = Prepare(std::move(Value.Input), std::move(Value.Services));
        if (!Verified)
        {
            return std::unexpected(Verified.error());
        }
        auto Result = std::make_shared<Binding>(std::move(*Verified));
        if (Stop.stop_requested())
        {
            Result->Close();
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::Cancelled, {}, "Bind"});
        }
        return Result;
    }

} // namespace Prism::Hysteria2
