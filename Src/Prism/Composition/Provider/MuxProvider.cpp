/** @file MuxProvider.cpp @brief typed mux binding Prepare/Bind 与 owner lifecycle 实现。 */

#include <Prism/Composition/Provider/MuxProvider.hpp>

#include <algorithm>
#include <unordered_set>
#include <utility>

namespace Prism::Composition::Provider
{

    auto BoundMux::Close() const noexcept -> void
    {
        if (Owner)
        {
            Owner->CloseForDrain();
        }
    }

    auto BoundMux::PhysicalRetirement() const noexcept
        -> Prism::Composition::Provider::PhysicalRetirementState
    {
        if (!Owner)
        {
            if (!Generation)
            {
                return Prism::Composition::Provider::PhysicalRetirementState::Retired;
            }
            return Prism::Composition::Provider::PhysicalRetirementState::Unknown;
        }
        if constexpr (requires { Owner->IsRetired(); })
        {
            if (Owner->IsRetired() && !Generation)
            {
                return Prism::Composition::Provider::PhysicalRetirementState::Retired;
            }
            return Prism::Composition::Provider::PhysicalRetirementState::Active;
        }
        return Prism::Composition::Provider::PhysicalRetirementState::Unknown;
    }

    auto BoundMux::DrainFailure() const noexcept
        -> std::optional<Prism::Fault::Failure>
    {
        if (DrainFailure_.Failed()) return DrainFailure_;
        if (Owner)
        {
            const auto Failure = Owner->DrainFailure();
            if (Failure.Failed()) return Failure;
        }
        return {};
    }

    auto BoundMux::Drain()
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        if (!Owner)
        {
            if (DrainFailure_.Failed()) co_return std::unexpected(DrainFailure_);
            Generation.reset();
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        const auto Result = co_await Owner->Drain();
        const bool Retired = Owner->IsRetired();
        const auto Durable = Owner->DrainFailure();
        if (Durable.Failed() && (!DrainFailure_.Failed() ||
            (DrainFailure_.Code == Prism::Fault::Code::Canceled &&
             Durable.Code != Prism::Fault::Code::Canceled)))
        {
            DrainFailure_ = Durable;
        }
        else if (!Result && Result.error().Code != Prism::Fault::Code::Canceled &&
            (!DrainFailure_.Failed() ||
             (DrainFailure_.Code == Prism::Fault::Code::Canceled &&
              Result.error().Code != Prism::Fault::Code::Canceled)))
        {
            DrainFailure_ = Result.error();
        }
        if constexpr (requires { Owner->IsRetired(); })
        {
            if (Retired)
            {
                Owner.reset();
                Generation.reset();
            }
        }
        if (DrainFailure_.Failed())
        {
            co_return std::unexpected(DrainFailure_);
        }
        if (!Result)
        {
            if (Result.error().Code == Prism::Fault::Code::Canceled && Retired)
            {
                co_return std::expected<void, Prism::Fault::Failure>{};
            }
            co_return std::unexpected(Result.error());
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto ConfiguredMuxMode(const Prism::Contract::ProtocolConfiguration& Protocol,
        const Prism::Contract::ProtocolBindingConfiguration& Binding)
        -> std::optional<Prism::Mux::Mode>
    {
        const auto Descriptor = Prism::Composition::Protocol::ProtocolCatalog::Find(Protocol.Builtin);
        if (Descriptor && Descriptor->Id == Prism::Contract::ProtocolType::AnyTls)
        {
            return std::nullopt;
        }
        for (const auto& Name : Binding.MuxModes)
        {
            const auto Mode = Prism::Mux::ParseMode(Name);
            if (Mode && (*Mode == Prism::Mux::Mode::H2Mux || *Mode == Prism::Mux::Mode::Yamux))
            {
                return Mode;
            }
        }
        for (const auto& Name : Binding.MuxModes)
        {
            const auto Mode = Prism::Mux::ParseMode(Name);
            if (Mode && *Mode == Prism::Mux::Mode::Smux)
            {
                return Mode;
            }
        }
        return std::nullopt;
    }

    auto PrepareMux(MuxPreparationInput Input)
        -> std::expected<std::optional<PreparedMux>, Prism::Contract::ProviderFailure>
    {
        const auto Mode = ConfiguredMuxMode(Input.Protocol, Input.Binding);
        if (!Mode)
        {
            if (!Input.Binding.MuxModes.empty())
            {
                return std::unexpected(Prism::Contract::ProviderFailure{
                    Prism::Contract::ProviderError::UnsupportedInstance,
                    Input.Protocol.Id, "Bindings.Mux.Modes"});
            }
            return std::optional<PreparedMux>{};
        }
        if (!Input.Services.Egress)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::MissingEgress, Input.Protocol.Id, "Bindings.Mux.Egress"});
        }
        if (!Input.Services.Bytes)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::InvalidConfiguration, Input.Protocol.Id,
                "Bindings.Mux.BytePool"});
        }
        if (!Input.Generation || !Input.UseState)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::GenerationMismatch,
                Input.Protocol.Id, "Generation"});
        }
        return std::optional<PreparedMux>{PreparedMux{
            MuxProviderKey, Input.Binding.Id, Input.Protocol.Id, *Mode,
            std::move(Input.Services), std::move(Input.Generation), std::move(Input.UseState)}};
    }

    auto PrepareMuxes(MuxCatalogPreparation Input)
        -> std::expected<std::vector<PreparedMux>, Prism::Contract::ProviderFailure>
    {
        std::vector<PreparedMux> Result;
        std::unordered_set<std::string> Seen;
        for (const auto& Binding : Input.Bindings)
        {
            if (!Seen.emplace(Binding.Id).second)
            {
                return std::unexpected(Prism::Contract::ProviderFailure{
                    Prism::Contract::ProviderError::DuplicateInstance, Binding.Id, "Bindings.Id"});
            }
            const auto Protocol = std::find_if(Input.Protocols.begin(), Input.Protocols.end(),
                [&Binding](const ConfiguredInstance& Value)
                {
                    return Value.Protocol.Id == Binding.ProtocolId;
                });
            if (Protocol == Input.Protocols.end())
            {
                return std::unexpected(Prism::Contract::ProviderFailure{
                    Prism::Contract::ProviderError::UnsupportedInstance,
                    Binding.ProtocolId, "Bindings.ProtocolId"});
            }
            const auto Descriptor = Prism::Composition::Protocol::ProtocolCatalog::Find(
                Protocol->Protocol.Builtin);
            if (!Descriptor || Descriptor->Kind != Prism::Composition::Protocol::DescriptorKind::Protocol)
            {
                return std::unexpected(Prism::Contract::ProviderFailure{
                    Prism::Contract::ProviderError::UnsupportedInstance,
                    Binding.ProtocolId, "Bindings.Protocol"});
            }
            auto Prepared = PrepareMux(MuxPreparationInput{
                Protocol->Protocol, Binding, Input.Services, Input.Generation, Input.UseState});
            if (!Prepared)
            {
                return std::unexpected(Prepared.error());
            }
            if (!Prepared->has_value())
            {
                continue;
            }
            if (!Descriptor->SupportsTcp)
            {
                return std::unexpected(Prism::Contract::ProviderFailure{
                    Prism::Contract::ProviderError::UnsupportedInstance,
                    Binding.ProtocolId, "Bindings.Mux.Protocol"});
            }
            Result.push_back(std::move(**Prepared));
        }
        return Result;
    }

    auto BindMux(PreparedMux Value, const bool Cancelled)
        -> std::expected<BoundMux, Prism::Contract::ProviderFailure>
    {
        if (Cancelled)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::Cancelled, Value.Id, "Bind"});
        }
        if (Value.Key != MuxProviderKey)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::UnsupportedInstance, Value.Id, "Bindings.Mux.Slot"});
        }
        Prism::Mux::RootOptions Options;
        Options.Wire = Value.Wire;
        Options.Services = std::move(Value.Services);
        Options.GenerationUseState = std::move(Value.UseState);
        auto Root = std::make_shared<Prism::Mux::RootBinding>(std::move(Options));
        return BoundMux{Value.Key, std::move(Value.Id), std::move(Value.ProtocolId), Value.Wire,
            std::move(Root), std::move(Value.Generation)};
    }

    auto MuxesForProtocol(const std::string_view ProtocolId,
        const std::vector<BoundMux>& Values) -> std::vector<BoundMux>
    {
        std::vector<BoundMux> Result;
        for (const auto& Value : Values)
        {
            if (Value.Key == MuxProviderKey && Value.ProtocolId == ProtocolId && Value.Owner)
            {
                Result.push_back(Value);
            }
        }
        return Result;
    }

} // namespace Prism::Composition::Provider
