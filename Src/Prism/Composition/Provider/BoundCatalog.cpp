/** @file BoundCatalog.cpp @brief 已发布 provider binding catalog 的关闭与排空实现。 */
#include <Prism/Composition/Provider/BoundCatalog.hpp>
#include <Prism/Composition/Detail/BoundCatalogOwnerClosure.hpp>

#include <algorithm>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace Prism::Composition::Provider
{
    namespace
    {
        struct DrainOwnerFailureReceipt final
        {
            std::optional<Prism::Fault::Failure> DurableFailure;
            PhysicalRetirementState Retirement{PhysicalRetirementState::Unknown};
            bool HasDurableFailureSource{false};
        };

        auto IsRetryableDrainAttempt(const std::expected<void, Prism::Fault::Failure>& Result,
            const DrainOwnerFailureReceipt& Owner) noexcept -> bool
        {
            if (Result || Owner.DurableFailure)
            {
                return false;
            }
            const auto Code = Result.error().Code;
            if (Code == Prism::Fault::Code::Canceled)
            {
                return Owner.Retirement != PhysicalRetirementState::Retired ||
                    Owner.HasDurableFailureSource;
            }
            return Code == Prism::Fault::Code::Blocked && Owner.HasDurableFailureSource;
        }

        template<typename T>
        auto OwnerPhysicalRetirement(const std::shared_ptr<T>& Value) noexcept
            -> PhysicalRetirementState
        {
            if (!Value)
            {
                return PhysicalRetirementState::Retired;
            }
            if constexpr (requires { Value->IsRetired(); })
            {
                if (Value->IsRetired())
                {
                    return PhysicalRetirementState::Retired;
                }
                return PhysicalRetirementState::Active;
            }
            return PhysicalRetirementState::Unknown;
        }

        template<typename T>
        auto MuxStreamOf(const std::shared_ptr<T>& Owner,
            const std::shared_ptr<Prism::Mux::RootBinding>& Mux)
            -> std::shared_ptr<Prism::Contract::StreamFactory>
        {
            if (!Owner)
            {
                return {};
            }
            if constexpr (std::is_same_v<T, Prism::Socks5::Binding>)
            {
                return Owner->WithAdmission(Prism::Socks5::Binding::AdmissionPolicy{
                    .Mux = Mux, .UdpEnabled = std::nullopt});
            }
            else if constexpr (std::is_same_v<T, Prism::Shadowsocks2022::Binding>)
            {
                return Owner->WithMux(Mux);
            }
            return {};
        }

        template<typename T>
        auto DrainOwner(const T& Owner)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            if (!Owner)
            {
                co_return std::expected<void, Prism::Fault::Failure>{};
            }
            if constexpr (requires { Owner->Drain(); })
            {
                co_return co_await Owner->Drain();
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        auto ReleaseOwner(ActiveBinding& Owner) noexcept -> void
        {
            std::visit([](auto& Value) { Value.reset(); }, Owner);
        }
    }

    auto PhysicalRetirementReceipt::Complete() const noexcept -> bool
    {
        for (const auto& Owner : Owners)
        {
            if (Owner.State != PhysicalRetirementState::Retired)
            {
                return false;
            }
        }
        return true;
    }

    auto BoundInstance::PhysicalRetirement() const noexcept -> PhysicalRetirementState
    {
        return std::visit([](const auto& Value) { return OwnerPhysicalRetirement(Value); }, Owner);
    }

    auto BoundInstance::DrainFailure() const noexcept
        -> std::optional<Prism::Fault::Failure>
    {
        return std::visit([](const auto& Value) -> std::optional<Prism::Fault::Failure>
        {
            if constexpr (requires { Value->DrainFailure(); })
            {
                if (!Value) return {};
                const auto Failure = Value->DrainFailure();
                if (Failure.Failed()) return Failure;
            }
            return {};
        }, Owner);
    }

    auto BoundInstance::HasDrainFailureSource() const noexcept -> bool
    {
        return std::visit([](const auto& Value)
        {
            return requires { Value->DrainFailure(); };
        }, Owner);
    }

    auto BoundInstance::Stream() const -> std::shared_ptr<Prism::Contract::StreamFactory>
    {
        return std::visit([](const auto& Value) -> std::shared_ptr<Prism::Contract::StreamFactory>
        {
            using T = typename std::decay_t<decltype(Value)>::element_type;
            if constexpr (std::is_base_of_v<Prism::Contract::StreamFactory, std::remove_const_t<T>>)
            {
                return Value;
            }
            return {};
        }, Owner);
    }

    auto BoundInstance::MuxStream(std::shared_ptr<Prism::Mux::RootBinding> Mux) const
        -> std::shared_ptr<Prism::Contract::StreamFactory>
    {
        return std::visit([&Mux](const auto& Value) { return MuxStreamOf(Value, Mux); }, Owner);
    }

    auto BoundInstance::Quic() const -> std::shared_ptr<Prism::Contract::QuicConnectionFactory>
    {
        return std::visit([](const auto& Value) -> std::shared_ptr<Prism::Contract::QuicConnectionFactory>
        {
            using T = typename std::decay_t<decltype(Value)>::element_type;
            if constexpr (std::is_base_of_v<Prism::Contract::QuicConnectionFactory,
                std::remove_const_t<T>>)
            {
                return Value;
            }
            return {};
        }, Owner);
    }

    auto BoundInstance::Raw() const -> std::shared_ptr<Prism::Contract::RawDatagramIngress>
    {
        if (const auto* Value = std::get_if<std::shared_ptr<Prism::Shadowsocks2022::Binding>>(&Owner))
        {
            if (*Value)
            {
                return (*Value)->RawIngress();
            }
        }
        return {};
    }

    BoundCatalog::BoundCatalog(BoundCatalog&& Other) noexcept
        : Entries_(std::move(Other.Entries_)), Muxes_(std::move(Other.Muxes_)),
          CarrierOwners_(std::move(Other.CarrierOwners_)), UseState_(std::move(Other.UseState_)),
          FirstFailure_(std::move(Other.FirstFailure_))
    {
        Other.FirstFailure_.reset();
    }

    auto BoundCatalog::operator=(BoundCatalog&& Other) noexcept -> BoundCatalog&
    {
        if (this != &Other)
        {
            Close();
            Entries_ = std::move(Other.Entries_);
            Muxes_ = std::move(Other.Muxes_);
            CarrierOwners_ = std::move(Other.CarrierOwners_);
            UseState_ = std::move(Other.UseState_);
            if (!FirstFailure_) FirstFailure_ = std::move(Other.FirstFailure_);
            Other.FirstFailure_.reset();
        }
        return *this;
    }

    BoundCatalog::~BoundCatalog()
    {
        Close();
    }

    BoundCatalog::BoundCatalog(std::vector<BoundInstance> Values, std::vector<BoundMux> Muxes,
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState)
        : Entries_(std::move(Values)), Muxes_(std::move(Muxes)),
          UseState_(std::move(UseState))
    {
    }

    auto BoundCatalog::QuicIngressBinding() const
        -> std::expected<std::optional<Prism::Contract::QuicIngressBindingSnapshot::Binding>,
            Prism::Contract::ProviderFailure>
    {
        auto Result = std::optional<Prism::Contract::QuicIngressBindingSnapshot::Binding>{};
        for (const auto& Entry : Entries_)
        {
            auto Factory = Entry.Quic();
            if (!Factory) continue;
            if (Result)
            {
                return std::unexpected(Prism::Contract::ProviderFailure{
                    Prism::Contract::ProviderError::AmbiguousListener,
                    Entry.Id, "Quic.Listener"});
            }
            Result.emplace(Prism::Contract::QuicIngressBindingSnapshot::Binding{
                Entry.Id, std::move(Factory)});
        }
        return Result;
    }

    auto BoundCatalog::Find(const std::string_view Id) const -> const BoundInstance*
    {
        for (const auto& Value : Entries_)
        {
            if (Value.Id == Id)
            {
                return &Value;
            }
        }
        return nullptr;
    }

    auto BoundCatalog::AdoptCarrierOwner(std::string Name,
        std::shared_ptr<Prism::Contract::CarrierCatalogOwner> Owner)
        -> std::expected<void, Prism::Contract::ProviderFailure>
    {
        if (Name.empty() || !Owner)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::InvalidConfiguration,
                std::move(Name), "Carriers.Owner"});
        }
        const auto Duplicate = std::find_if(CarrierOwners_.begin(), CarrierOwners_.end(),
            [&Name](const auto& Entry) { return Entry.first == Name; });
        if (Duplicate != CarrierOwners_.end())
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::AlreadyBound,
                std::move(Name), "Carriers.Owner"});
        }
        CarrierOwners_.emplace_back(std::move(Name), std::move(Owner));
        return {};
    }

    auto BoundCatalog::MuxesForProtocol(const std::string_view ProtocolId) const
        -> std::vector<BoundMux>
    {
        return Prism::Composition::Provider::MuxesForProtocol(ProtocolId, Muxes_);
    }

    auto BoundCatalog::PhysicalRetirement() const -> PhysicalRetirementReceipt
    {
        PhysicalRetirementReceipt Receipt;
        Receipt.Owners.reserve(Entries_.size() + Muxes_.size() + CarrierOwners_.size());
        for (const auto& Entry : Entries_)
        {
            Receipt.Owners.push_back({Entry.Id, Entry.PhysicalRetirement()});
        }
        for (const auto& Mux : Muxes_)
        {
            Receipt.Owners.push_back({"Mux." + Mux.Id, Mux.PhysicalRetirement()});
        }
        for (const auto& [Name, Owner] : CarrierOwners_)
        {
            const auto State = !Owner ? PhysicalRetirementState::Retired :
                Owner->IsRetired() ? PhysicalRetirementState::Retired :
                PhysicalRetirementState::Active;
            Receipt.Owners.push_back({"TlsCarrier." + Name, State});
        }
        return Receipt;
    }

    auto BoundCatalog::Close() noexcept -> void
    {
        for (auto& Entry : Entries_)
        {
            std::visit([](const auto& Owner) { CloseOwner(Owner); }, Entry.Owner);
        }
        for (const auto& Mux : Muxes_)
        {
            Mux.Close();
        }
        for (const auto& [Name, Owner] : CarrierOwners_)
        {
            (void)Name;
            if (Owner) Owner->Close();
        }
    }

    auto BoundCatalog::Drain()
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        Close();
        auto AttemptCancellation = std::optional<Prism::Fault::Failure>{};
        for (auto& Entry : Entries_)
        {
            const auto Result = co_await std::visit(
                [](const auto& Owner) { return DrainOwner(Owner); }, Entry.Owner);
            const auto Durable = Entry.DrainFailure();
            const auto FailureReceipt = DrainOwnerFailureReceipt{
                Durable, Entry.PhysicalRetirement(), Entry.HasDrainFailureSource()};
            if (Durable && !FirstFailure_) FirstFailure_ = *Durable;
            if (IsRetryableDrainAttempt(Result, FailureReceipt))
            {
                if (!AttemptCancellation) AttemptCancellation = Result.error();
            }
            else if (!Result && !FirstFailure_)
            {
                FirstFailure_ = Result.error();
            }
        }
        for (auto& Mux : Muxes_)
        {
            const auto Result = co_await Mux.Drain();
            const auto Durable = Mux.DrainFailure();
            const auto FailureReceipt = DrainOwnerFailureReceipt{
                Durable, Mux.PhysicalRetirement(), true};
            if (Durable && !FirstFailure_) FirstFailure_ = *Durable;
            if (IsRetryableDrainAttempt(Result, FailureReceipt))
            {
                if (!AttemptCancellation) AttemptCancellation = Result.error();
            }
            else if (!Result && !FirstFailure_)
            {
                FirstFailure_ = Result.error();
            }
        }
        for (auto& [Name, Owner] : CarrierOwners_)
        {
            if (!Owner) continue;
            const auto Result = co_await Owner->Drain();
            const bool Retired = Owner->IsRetired();
            if (Retired) Owner.reset();
            if (!Result && Result.error().Code == Prism::Fault::Code::Canceled && !Retired)
            {
                if (!AttemptCancellation) AttemptCancellation = Result.error();
            }
            else if (!Result && !FirstFailure_)
            {
                FirstFailure_ = Result.error();
            }
            (void)Name;
        }
        const bool PhysicallyRetired = PhysicalRetirement().Complete();
        for (const auto& Entry : Entries_)
        {
            const auto Durable = Entry.DrainFailure();
            if (Durable && !FirstFailure_) FirstFailure_ = *Durable;
        }
        for (const auto& Mux : Muxes_)
        {
            const auto Durable = Mux.DrainFailure();
            if (Durable && !FirstFailure_) FirstFailure_ = *Durable;
        }
        for (auto& Entry : Entries_)
        {
            if (Entry.PhysicalRetirement() == PhysicalRetirementState::Retired)
            {
                ReleaseOwner(Entry.Owner);
            }
        }
        if (FirstFailure_) co_return std::unexpected(*FirstFailure_);
        if (AttemptCancellation && !PhysicallyRetired)
        {
            co_return std::unexpected(*AttemptCancellation);
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }
}
