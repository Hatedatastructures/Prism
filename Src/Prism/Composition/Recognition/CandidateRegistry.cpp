/** @file CandidateRegistry.cpp @brief configured candidate 与 carrier registry 实现。 */

#include <Prism/Composition/Recognition/CandidateRegistry.hpp>

#include <Prism/Composition/Recognition/CandidateFactory.hpp>
#include <Prism/Composition/Recognition/LayeredCandidateFactory.hpp>
#include <Prism/Composition/Recognition/TlsCandidateFactory.hpp>

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <variant>

namespace Prism::Composition::Recognition
{
    namespace detail
    {

        auto CanonicalCarrierScheme(const std::string_view Scheme) -> std::string
        {
            const auto Descriptor = Prism::Composition::Protocol::ProtocolCatalog::Find(Scheme);
            if (Descriptor && (Descriptor->Kind == Prism::Composition::Protocol::DescriptorKind::Carrier ||
                Descriptor->Id == Prism::Contract::ProtocolType::TrustTunnel))
            {
                return std::string(Descriptor->Name);
            }
            return std::string(Scheme);
        }

        auto CarrierForScheme(const std::string_view Scheme) -> std::optional<TlsCarrier>
        {
            const auto Descriptor = Prism::Composition::Protocol::ProtocolCatalog::Find(Scheme);
            if (!Descriptor) return std::nullopt;
            if (Descriptor->Kind == Prism::Composition::Protocol::DescriptorKind::Carrier)
            {
                return Descriptor->Carrier;
            }
            if (Descriptor->Id == Prism::Contract::ProtocolType::TrustTunnel)
            {
                return TlsCarrier::TrustTunnel;
            }
            return std::nullopt;
        }

        auto OptionsFrom(const CandidateDefinition& Candidate) -> CandidateOptions
        {
            CandidateOptions Options;
            Options.Id = Candidate.Id;
            Options.Name = Candidate.Name;
            Options.Priority = Candidate.Priority;
            Options.Tier = Candidate.Tier;
            Options.Fallback = Candidate.Fallback;
            Options.BindingId = Candidate.BindingId;
            Options.UdpEnabled = Candidate.UdpEnabled;
            return Options;
        }

    } // namespace detail

    auto CandidateRegistry::Register(const std::string_view Protocol, CandidateBuilder Builder) -> bool
    {
        const auto Name = Canonicalize(Protocol);
        if (Name.empty() || !Builder)
        {
            return false;
        }
        return State_.Builders.emplace(Name, std::move(Builder)).second;
    }

    auto CandidateRegistry::RegisterTlsCarrier(
        Prism::Composition::Protocol::ProviderKey Key,
        std::string Id,
        CarrierRegistration Registration) -> bool
    {
        using Category = Prism::Composition::Protocol::ProviderCategory;
        const auto* Kind = std::get_if<Prism::Composition::Protocol::CarrierKind>(&Key.Identity);
        if (Key.Category != Category::TlsCarrier || Kind == nullptr ||
            *Kind == Prism::Composition::Protocol::CarrierKind::None ||
            (static_cast<bool>(Registration.Accept) == static_cast<bool>(Registration.AcceptPrepared)))
        {
            return false;
        }
        const auto Descriptor = Prism::Composition::Protocol::ProtocolCatalog::Find(Key);
        if (!Descriptor || Descriptor->Kind != Prism::Composition::Protocol::DescriptorKind::Carrier)
        {
            return false;
        }
        const auto Scheme = Descriptor->Name;
        Registration.Key = Key;
        if (Id.empty())
        {
            return State_.Carriers.emplace(std::string(Scheme), std::move(Registration)).second;
        }
        const auto CarrierId = Normalize(Id);
        if (CarrierId.empty())
        {
            return false;
        }
        return State_.CarriersById.emplace(CarrierId, std::move(Registration)).second;
    }

    auto CandidateRegistry::RegisterConfigured(std::string Id, CandidateBuilder Builder) -> bool
    {
        if (Id.empty() || !Builder)
        {
            return false;
        }
        return State_.Builders.emplace("instance/" + std::move(Id), std::move(Builder)).second;
    }

    auto CandidateRegistry::RegisterConfiguredProvider(
        std::string Id, ProviderCandidateInputs Inputs) -> bool
    {
        return RegisterConfigured(std::move(Id),
            [Inputs = std::move(Inputs)](const auto& Candidate) -> std::optional<CandidateBinding>
            {
                return CandidateFactory::MakeConfiguredProvider(
                    detail::OptionsFrom(Candidate), Inputs);
            });
    }

    auto CandidateRegistry::Build(const CandidateDefinition& Candidate) const
        -> std::optional<CandidateBinding>
    {
        return BuildFrom(Candidate, State_);
    }

    auto CandidateRegistry::MakeFactory() const -> CandidateBuilder
    {
        const auto Snapshot = std::make_shared<const BuilderState>(State_);
        return [Snapshot = std::move(Snapshot)](const CandidateDefinition& Candidate)
            -> std::optional<CandidateBinding>
        {
            return BuildFrom(Candidate, *Snapshot);
        };
    }

    auto CandidateRegistry::BuildFrom(const CandidateDefinition& Candidate,
        const BuilderState& State) -> std::optional<CandidateBinding>
    {
        auto Protocol = std::string{};
        if (Candidate.ProtocolId.empty())
        {
            Protocol = Canonicalize(Candidate.Protocol);
        }
        else
        {
            Protocol = "instance/" + Candidate.ProtocolId;
        }
        const auto BuilderIt = State.Builders.find(Protocol);
        if (BuilderIt == State.Builders.end())
        {
            return std::nullopt;
        }
        auto Inner = BuilderIt->second(Candidate);
        if (!Inner)
        {
            return std::nullopt;
        }
        if (Candidate.Scheme.empty())
        {
            if (Inner->Spec.Kind == Core::CandidateKind::TlsCarrier &&
                Normalize(Inner->Spec.Scheme).empty())
            {
                return std::nullopt;
            }
            return Inner;
        }

        const auto Scheme = Normalize(Candidate.Scheme);
        if (Scheme.empty())
        {
            return std::nullopt;
        }
        const auto CanonicalScheme = detail::CanonicalCarrierScheme(Scheme);
        const auto Carrier = detail::CarrierForScheme(CanonicalScheme);
        if (!Carrier)
        {
            return std::nullopt;
        }
        if (Inner->Spec.Kind == Core::CandidateKind::TlsCarrier)
        {
            if (Normalize(Inner->Spec.Scheme) == Scheme)
            {
                return Inner;
            }
            return std::nullopt;
        }
        const auto Descriptor =
            Prism::Composition::Protocol::ProtocolCatalog::Find(CanonicalScheme);
        if (!Descriptor ||
            Descriptor->Kind != Prism::Composition::Protocol::DescriptorKind::Carrier)
        {
            return std::nullopt;
        }
        const CarrierRegistration* Registration = nullptr;
        if (!Candidate.CarrierId.empty())
        {
            const auto CarrierIt = State.CarriersById.find(Normalize(Candidate.CarrierId));
            if (CarrierIt == State.CarriersById.end())
            {
                return std::nullopt;
            }
            Registration = &CarrierIt->second;
        }
        else
        {
            const auto CarrierIt = State.Carriers.find(CanonicalScheme);
            if (CarrierIt == State.Carriers.end())
            {
                return std::nullopt;
            }
            Registration = &CarrierIt->second;
        }
        if (!Registration || (!Registration->Accept && !Registration->AcceptPrepared))
        {
            return std::nullopt;
        }
        if (Registration->Key != Descriptor->Slot())
        {
            return std::nullopt;
        }

        TlsCandidateOptions Options;
        Options.Id = Candidate.Id;
        Options.Name = Candidate.Name;
        Options.Scheme = Scheme;
        Options.ServerNames = Candidate.ServerNames;
        Options.Alpn = Candidate.Alpn;
        Options.Fallback = Candidate.Fallback;
        Options.Carrier = *Carrier;
        Options.HasNativeTlsContext = Registration->HasNativeTlsContext;
        if (Registration->AcceptPrepared)
        {
            return LayeredCandidateFactory::MakePrepared(
                std::move(Options), Registration->AcceptPrepared, std::move(*Inner));
        }
        return LayeredCandidateFactory::Make(
            std::move(Options), Registration->Accept, std::move(*Inner));
    }

    auto CandidateRegistry::Normalize(const std::string_view Protocol) -> std::string
    {
        std::string Result;
        Result.reserve(Protocol.size());
        for (const auto Character : Protocol)
        {
            const auto Byte = static_cast<unsigned char>(Character);
            const bool Letter = (Byte >= 'A' && Byte <= 'Z') || (Byte >= 'a' && Byte <= 'z');
            const bool Digit = Byte >= '0' && Byte <= '9';
            if (!Letter && !Digit && Byte != '-' && Byte != '_')
            {
                return {};
            }
            unsigned char Lower = Byte;
            if (Byte >= 'A' && Byte <= 'Z')
            {
                Lower = static_cast<unsigned char>(Byte + ('a' - 'A'));
            }
            Result.push_back(static_cast<char>(Lower));
        }
        return Result;
    }

    auto CandidateRegistry::Canonicalize(const std::string_view Protocol) -> std::string
    {
        return Normalize(Protocol);
    }

    auto CandidateRegistry::Has(const std::string_view Protocol) const -> bool
    {
        return Find(Protocol) != nullptr;
    }

    auto CandidateRegistry::Find(const std::string_view Protocol) const
        -> const CandidateBuilder*
    {
        const auto Name = Canonicalize(Protocol);
        const auto It = State_.Builders.find(Name);
        if (It == State_.Builders.end())
        {
            return nullptr;
        }
        return &It->second;
    }

} // namespace Prism::Composition::Recognition
