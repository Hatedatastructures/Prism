/** @file ProfileBuilder.cpp @brief Recognition profile 与 winner resolver 装配实现。 */

#include <Prism/Composition/Recognition/ProfileBuilder.hpp>
#include <Prism/Composition/Recognition/CandidateFactory.hpp>
#include <Prism/Composition/Recognition/LayeredCandidateFactory.hpp>

#include <algorithm>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Prism::Composition::Recognition
{
    namespace detail
    {

        auto NormalizeProtocol(const std::string_view Value) -> std::string
        {
            if (Value.empty())
            {
                return {};
            }
            std::string Result;
            Result.reserve(Value.size());
            for (const auto Character : Value)
            {
                const auto Byte = static_cast<unsigned char>(Character);
                const bool Letter = (Byte >= 'A' && Byte <= 'Z') || (Byte >= 'a' && Byte <= 'z');
                const bool Digit = Byte >= '0' && Byte <= '9';
                if (!Letter && !Digit && Byte != '-' && Byte != '_')
                {
                    return {};
                }
                const auto Lower = Byte >= 'A' && Byte <= 'Z'
                    ? static_cast<unsigned char>(Byte + ('a' - 'A')) : Byte;
                Result.push_back(static_cast<char>(Lower));
            }
            return Result;
        }

        auto NormalizeScheme(const std::string_view Value) -> std::string
        {
            if (Value.empty())
            {
                return {};
            }
            std::string Result;
            Result.reserve(Value.size());
            for (const auto Character : Value)
            {
                const auto Byte = static_cast<unsigned char>(Character);
                const bool Letter = (Byte >= 'A' && Byte <= 'Z') || (Byte >= 'a' && Byte <= 'z');
                const bool Digit = Byte >= '0' && Byte <= '9';
                if (!Letter && !Digit && Byte != '-' && Byte != '_')
                {
                    return {};
                }
                const auto Lower = Byte >= 'A' && Byte <= 'Z'
                    ? static_cast<unsigned char>(Byte + ('a' - 'A')) : Byte;
                Result.push_back(static_cast<char>(Lower));
            }
            return Result;
        }

        auto ParseProtocol(const std::string_view Value)
            -> std::optional<Prism::Contract::ProtocolType>
        {
            const auto Name = NormalizeProtocol(Value);
            if (Name == "http") return Prism::Contract::ProtocolType::Http;
            if (Name == "socks5") return Prism::Contract::ProtocolType::Socks5;
            if (Name == "trojan") return Prism::Contract::ProtocolType::Trojan;
            if (Name == "vless") return Prism::Contract::ProtocolType::Vless;
            if (Name == "vmess") return Prism::Contract::ProtocolType::Vmess;
            if (Name == "ss2022") return Prism::Contract::ProtocolType::Shadowsocks;
            if (Name == "anytls") return Prism::Contract::ProtocolType::AnyTls;
            if (Name == "trusttunnel") return Prism::Contract::ProtocolType::TrustTunnel;
            if (Name == "hysteria2") return Prism::Contract::ProtocolType::Hysteria2;
            if (Name == "tuic") return Prism::Contract::ProtocolType::Tuic;
            return std::nullopt;
        }

        auto IsQuicProtocol(const Prism::Contract::ProtocolType Protocol) noexcept -> bool
        {
            return Protocol == Prism::Contract::ProtocolType::Hysteria2 ||
                Protocol == Prism::Contract::ProtocolType::Tuic;
        }

        auto WithRouteServerNames(const RecognitionDefinition& Config,
            CandidateDefinition Candidate) -> CandidateDefinition
        {
            if (Candidate.Scheme.empty())
            {
                return Candidate;
            }
            for (const auto& Route : Config.Routes)
            {
                if (Route.Candidate != Candidate.Id)
                {
                    continue;
                }
                const auto Pattern = std::string_view(Route.Pattern);
                if (!Pattern.empty() && std::find(Candidate.ServerNames.begin(),
                        Candidate.ServerNames.end(), Pattern) == Candidate.ServerNames.end())
                {
                    Candidate.ServerNames.push_back(std::string(Pattern));
                }
            }
            return Candidate;
        }

        auto SameOuter(const CandidateDefinition& Left, const CandidateDefinition& Right) -> bool
        {
            return !Left.CarrierId.empty() && Left.CarrierId == Right.CarrierId &&
                Left.Scheme == Right.Scheme && Left.ServerNames == Right.ServerNames &&
                Left.Alpn == Right.Alpn && Left.Priority == Right.Priority &&
                Left.Tier == Right.Tier && Left.Fallback == Right.Fallback &&
                Left.UdpEnabled == Right.UdpEnabled;
        }

        auto ApplyCandidateMetadata(const CandidateDefinition& Candidate,
            CandidateBinding& Binding) -> void
        {
            Binding.Spec.Id = Candidate.Id;
            if (!Candidate.Name.empty())
            {
                Binding.Spec.Name = Candidate.Name;
            }
            if (const auto Protocol = ParseProtocol(Candidate.Protocol))
            {
                Binding.Spec.Protocol = *Protocol;
            }
            const auto Scheme = NormalizeScheme(Candidate.Scheme);
            if (!Scheme.empty())
            {
                Binding.Spec.Scheme = Scheme;
            }
            Binding.Spec.Priority = Candidate.Priority;
            Binding.Spec.Tier = Candidate.Tier;
            Binding.Spec.Fallback = Candidate.Fallback;
        }

    } // namespace detail

    auto ProfileBuildResult::Resolve(Core::CandidateId Id) const
        -> std::shared_ptr<Prism::Contract::StreamFactory>
    {
        if (Resolver)
        {
            return Resolver(Id);
        }
        return std::shared_ptr<Prism::Contract::StreamFactory>{};
    }

    auto ProfileBuilder::Build(std::vector<CandidateBinding> Bindings,
        ProfileBuilderOptions Options)
        -> std::expected<ProfileBuildResult, Core::ProfileError>
    {
        Core::ProfileSpec Spec;
        Spec.Mode = Options.Mode;
        Spec.ConfiguredCandidate = Options.ConfiguredCandidate;
        Spec.DefaultCandidate = Options.DefaultCandidate;
        Spec.Budget = Options.Budget;
        Spec.Routes = std::move(Options.Routes);

        std::unordered_map<Core::CandidateId,
            std::shared_ptr<Prism::Contract::StreamFactory>> Acceptors;
        Acceptors.reserve(Bindings.size());
        Spec.Candidates.reserve(Bindings.size());
        for (auto& Binding : Bindings)
        {
            if (!Binding.Accept)
            {
                return std::unexpected(Core::ProfileError::MissingResolver);
            }
            if (Options.Mode == Core::RecognitionMode::Configured &&
                Spec.ConfiguredCandidate == Core::InvalidCandidate && Bindings.size() == 1)
            {
                Spec.ConfiguredCandidate = Binding.Spec.Id;
            }
            Spec.Candidates.push_back(std::move(Binding.Spec));
            Acceptors.emplace(Binding.Spec.Id, std::move(Binding.Accept));
        }

        auto Compiled = Core::Profile::Compile(std::move(Spec));
        if (!Compiled)
        {
            return std::unexpected(Compiled.error());
        }

        ProfileBuildResult Result;
        Result.Profile = std::move(*Compiled);
        auto ResolveFunction = [Acceptors = std::move(Acceptors)](const Core::CandidateId Id)
            -> std::shared_ptr<Prism::Contract::StreamFactory>
        {
            const auto It = Acceptors.find(Id);
            if (It == Acceptors.end())
            {
                return std::shared_ptr<Prism::Contract::StreamFactory>{};
            }
            return It->second;
        };
        Result.Resolver = std::move(ResolveFunction);
        return Result;
    }

    auto ProfileBuilder::Build(CandidateBinding Binding, ProfileBuilderOptions Options)
        -> std::expected<ProfileBuildResult, Core::ProfileError>
    {
        std::vector<CandidateBinding> Bindings;
        Bindings.push_back(std::move(Binding));
        return Build(std::move(Bindings), std::move(Options));
    }

    auto ProfileBuilder::Build(const RecognitionDefinition& Definition,
        CandidateBuilder Factory) -> std::expected<ProfileBuildResult, Core::ProfileError>
    {
        if (!Factory)
        {
            return std::unexpected(Core::ProfileError::MissingResolver);
        }
        struct BuiltCandidate final
        {
            CandidateDefinition Source;
            CandidateBinding Binding;
        };

        std::vector<BuiltCandidate> BuiltCandidates;
        BuiltCandidates.reserve(Definition.Candidates.size());
        for (const auto& Source : Definition.Candidates)
        {
            auto Candidate = detail::WithRouteServerNames(Definition, Source);
            const auto Protocol = detail::ParseProtocol(Candidate.Protocol);
            if (!Protocol)
            {
                return std::unexpected(Core::ProfileError::MissingResolver);
            }
            if (detail::IsQuicProtocol(*Protocol))
            {
                return std::unexpected(Core::ProfileError::QuicCandidateRequiresGateway);
            }
            auto Binding = Factory(Candidate);
            if (!Binding)
            {
                return std::unexpected(Core::ProfileError::MissingResolver);
            }
            const auto Scheme = detail::NormalizeScheme(Candidate.Scheme);
            if (!Candidate.Scheme.empty() &&
                (Scheme.empty() || Binding->Spec.Kind != Core::CandidateKind::TlsCarrier ||
                 detail::NormalizeScheme(Binding->Spec.Scheme) != Scheme))
            {
                return std::unexpected(Core::ProfileError::MissingResolver);
            }
            detail::ApplyCandidateMetadata(Candidate, *Binding);
            BuiltCandidates.push_back(BuiltCandidate{std::move(Candidate), std::move(*Binding)});
        }
        const auto HasExplicitRoute = [&Definition](const Core::CandidateId Id) noexcept
        {
            return std::any_of(Definition.Routes.begin(), Definition.Routes.end(),
                [Id](const auto& Route)
                {
                    return Route.Candidate == Id;
                });
        };
        std::vector<CandidateBinding> Bindings;
        Bindings.reserve(BuiltCandidates.size());
        std::vector<bool> Consumed(BuiltCandidates.size(), false);
        for (std::size_t Index = 0; Index < BuiltCandidates.size(); ++Index)
        {
            if (Consumed[Index])
            {
                continue;
            }
            Consumed[Index] = true;
            auto& First = BuiltCandidates[Index];
            std::vector<std::shared_ptr<const CandidateInnerBinding>> Inner;
            if (First.Binding.Inner && !HasExplicitRoute(First.Source.Id))
            {
                Inner.push_back(First.Binding.Inner);
                for (std::size_t Other = Index + 1U; Other < BuiltCandidates.size(); ++Other)
                {
                    if (Consumed[Other] || HasExplicitRoute(BuiltCandidates[Other].Source.Id) ||
                        !BuiltCandidates[Other].Binding.Inner ||
                        !detail::SameOuter(First.Source, BuiltCandidates[Other].Source))
                    {
                        continue;
                    }
                    Consumed[Other] = true;
                    Inner.push_back(BuiltCandidates[Other].Binding.Inner);
                }
            }
            if (Inner.size() > 1U)
            {
                First.Binding.Accept = MakeInnerProtocolDispatch(std::move(Inner));
                First.Binding.Inner.reset();
            }
            Bindings.push_back(std::move(First.Binding));
        }
        ProfileBuilderOptions Options;
        Options.Mode = Definition.Mode;
        Options.ConfiguredCandidate = Definition.ConfiguredCandidate;
        Options.DefaultCandidate = Definition.DefaultCandidate;
        Options.Budget = Definition.Budget;
        Options.Routes = Definition.Routes;
        return Build(std::move(Bindings), std::move(Options));
    }

    auto BuildProfile(std::vector<CandidateBinding> Bindings,
        ProfileBuilderOptions Options) -> std::expected<ProfileBuildResult, Core::ProfileError>
    {
        return ProfileBuilder::Build(std::move(Bindings), std::move(Options));
    }

} // namespace Prism::Composition::Recognition
