/** @file TlsCarrierCatalogOwner.cpp @brief generation-owned carrier callback 生命周期实现。 */

#include <Prism/Composition/Provider/TlsCarrierCatalogOwner.hpp>
#include <Prism/Composition/Detail/TlsCarrierCatalogInvocation.hpp>

#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <expected>
#include <memory>
#include <system_error>
#include <utility>

namespace Prism::Composition::Provider
{

    BoundTlsCarrierCatalog::DrainGuard::~DrainGuard()
    {
        Flag.clear(std::memory_order_release);
    }

    BoundTlsCarrierCatalog::~BoundTlsCarrierCatalog()
    {
        Close();
    }

    auto BoundTlsCarrierCatalog::Register(Recognition::CandidateRegistry& Registry)
        -> std::expected<void, Prism::Contract::ProviderFailure>
    {
        if (Registered_)
        {
            return std::unexpected(ProviderFailure(
                Prism::Contract::ProviderError::AlreadyBound, {}, "Carriers.Bind"));
        }
        Registered_ = true;
        for (std::size_t Index = 0; Index < Entries_.size(); ++Index)
        {
            const auto Accepted = Registry.RegisterTlsCarrier(
                Entries_[Index].Key, Entries_[Index].Id, MakeRegistration(Index));
            if (!Accepted)
            {
                return std::unexpected(ProviderFailure(
                    Prism::Contract::ProviderError::DuplicateInstance,
                    Entries_[Index].Id, "Carriers.Id"));
            }
        }
        return {};
    }

    auto BoundTlsCarrierCatalog::Close() noexcept -> void
    {
        const auto Previous = Gate_.fetch_or(ClosedBit, std::memory_order_acq_rel);
        if ((Previous & CountMask) == 0U)
        {
            NotifyDrain();
        }
    }

    auto BoundTlsCarrierCatalog::Drain()
        -> Net::awaitable<std::expected<void, CarrierFailure>>
    {
        Close();
        if (IsRetired())
        {
            co_return std::expected<void, CarrierFailure>{};
        }
        if (Draining_.test_and_set(std::memory_order_acq_rel))
        {
            co_return std::unexpected(CarrierFailure{Prism::Fault::Code::Blocked});
        }
        DrainGuard Guard{Draining_};
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        auto Signal = std::make_shared<CallbackSignal>(
            co_await Net::this_coro::executor, 1);
        std::shared_ptr<CallbackSignal> Empty;
        if (!Waiter_.compare_exchange_strong(
                Empty, Signal, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            co_return std::unexpected(CarrierFailure{Prism::Fault::Code::Blocked});
        }

        while (ActiveCount() != 0U)
        {
            boost::system::error_code Error;
            co_await Signal->async_receive(Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                ClearWaiter(Signal);
                co_return std::unexpected(Prism::Fault::FromNative(
                    static_cast<std::error_code>(Error)));
            }
        }
        ClearWaiter(Signal);
        Entries_.clear();
        Retired_.store(true, std::memory_order_release);
        co_return std::expected<void, CarrierFailure>{};
    }

    auto BoundTlsCarrierCatalog::IsRetired() const noexcept -> bool
    {
        return Retired_.load(std::memory_order_acquire);
    }

    BoundTlsCarrierCatalog::Invocation::~Invocation()
    {
        Lease = {};
        Owner->Leave();
    }

    BoundTlsCarrierCatalog::BoundTlsCarrierCatalog(
        std::vector<Entry> Values,
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState)
        : Entries_(std::move(Values)), UseState_(std::move(UseState))
    {
    }

    auto BoundTlsCarrierCatalog::MakeRegistration(const std::size_t Index)
        -> CarrierRegistration
    {
        CarrierRegistration Result;
        Result.Key = Entries_[Index].Key;
        Result.HasNativeTlsContext = Entries_[Index].Registration.HasNativeTlsContext;
        const auto Weak = weak_from_this();
        if (Entries_[Index].Registration.Accept)
        {
            Result.Accept = [Weak, Index](Core::CarrierAcceptInput Input)
            {
                return InvokeOrRetire(Weak, Index, std::move(Input));
            };
        }
        if (Entries_[Index].Registration.AcceptPrepared)
        {
            Result.AcceptPrepared = [Weak, Index](Core::CarrierAcceptPreparedInput Input)
            {
                return InvokeOrRetire(Weak, Index, std::move(Input));
            };
        }
        return Result;
    }

    auto BoundTlsCarrierCatalog::Enter() noexcept -> bool
    {
        auto State = Gate_.load(std::memory_order_acquire);
        while ((State & ClosedBit) == 0U && (State & CountMask) != CountMask)
        {
            if (Gate_.compare_exchange_weak(
                    State, State + 1U, std::memory_order_acq_rel, std::memory_order_acquire))
            {
                return true;
            }
        }
        return false;
    }

    auto BoundTlsCarrierCatalog::Leave() noexcept -> void
    {
        const auto Previous = Gate_.fetch_sub(1U, std::memory_order_acq_rel);
        if ((Previous & ClosedBit) != 0U && (Previous & CountMask) == 1U)
        {
            NotifyDrain();
        }
    }

    auto BoundTlsCarrierCatalog::ActiveCount() const noexcept -> std::uint64_t
    {
        return Gate_.load(std::memory_order_acquire) & CountMask;
    }

    auto BoundTlsCarrierCatalog::NotifyDrain() noexcept -> void
    {
        if (const auto Signal = Waiter_.load(std::memory_order_acquire))
        {
            (void)Signal->try_send(boost::system::error_code{});
        }
    }

    auto BoundTlsCarrierCatalog::ClearWaiter(
        const std::shared_ptr<CallbackSignal>& Signal) noexcept -> void
    {
        auto Expected = Signal;
        (void)Waiter_.compare_exchange_strong(
            Expected, std::shared_ptr<CallbackSignal>{},
            std::memory_order_acq_rel, std::memory_order_acquire);
    }

    auto BoundTlsCarrierCatalog::ProviderFailure(
        const Prism::Contract::ProviderError Code,
        const std::string_view Id,
        const std::string_view Path) -> Prism::Contract::ProviderFailure
    {
        return {Code, std::string(Id), std::string(Path)};
    }

} // namespace Prism::Composition::Provider
