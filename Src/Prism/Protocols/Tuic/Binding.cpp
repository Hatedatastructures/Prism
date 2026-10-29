/**
 * @file Binding.cpp
 * @brief TUIC 配置准备与 QUIC provider 生命周期。
 */
#include <Prism/Protocols/Tuic/Binding.hpp>

#include <Prism/Protocols/Tuic/Detail/Session.hpp>

#include <openssl/ssl.h>

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace Prism::Tuic
{
    namespace
    {
        [[nodiscard]] auto ParseBindingUuid(std::string_view Text)
            -> std::optional<std::array<std::uint8_t, UuidLen>>
        {
            if (Text.size() != 36)
            {
                return std::nullopt;
            }
            std::array<std::uint8_t, UuidLen> Value{};
            std::size_t Offset = 0;
            const auto Digit = [](const char Character) -> int
            {
                if (Character >= '0' && Character <= '9') return Character - '0';
                if (Character >= 'a' && Character <= 'f') return Character - 'a' + 10;
                if (Character >= 'A' && Character <= 'F') return Character - 'A' + 10;
                return -1;
            };
            for (std::size_t Index = 0; Index < Text.size();)
            {
                if (Index == 8 || Index == 13 || Index == 18 || Index == 23)
                {
                    if (Text[Index++] != '-')
                    {
                        return std::nullopt;
                    }
                    continue;
                }
                const auto High = Digit(Text[Index++]);
                const auto Low = Digit(Text[Index++]);
                if (High < 0 || Low < 0 || Offset >= Value.size())
                {
                    return std::nullopt;
                }
                Value[Offset++] = static_cast<std::uint8_t>((High << 4) | Low);
            }
            return Value;
        }
    }

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
        const auto MaximumVersion = SSL_CTX_get_max_proto_version(
            Services.Network.Listener.Tls->native_handle());
        if (MaximumVersion != 0 && MaximumVersion < TLS1_3_VERSION)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::MissingExporter,
                Input.Instance,
                "Quic.Tls.Exporter"});
        }
        auto Uuid = ParseBindingUuid(Input.Config.Uuid);
        if (!Uuid)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::InvalidConfiguration,
                Input.Instance,
                "Quic.Uuid"});
        }
        auto Record = Prism::Protocols::ValidateQuicAuthentication(
            Input, Services.Authentication);
        if (!Record)
        {
            return std::unexpected(Record.error());
        }
        Prepared Result(std::move(Input), std::move(Services), std::move(*Record));
        Result.Uuid = *Uuid;
        return Result;
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

} // namespace Prism::Tuic
