/** @file TlsCarrierCatalogOwner.hpp @brief TCP TLS callbacks 的 generation owner 与真实退休回执。 */
#pragma once

#include <Prism/Composition/Recognition/CandidateRegistry.hpp>
#include <Prism/Contract/Ingress/CarrierCatalogOwner.hpp>
#include <Prism/Contract/Ingress/ProviderFailure.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>

#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

namespace Prism::Composition::Provider
{
    namespace Net = boost::asio;
    namespace Recognition = Prism::Composition::Recognition;
    namespace Core = Prism::Recognition;
    using CarrierRegistration = Recognition::CandidateRegistry::CarrierRegistration;
    using CarrierResult = Core::CarrierAcceptResult;
    using CarrierFailure = Prism::Fault::Failure;
    using CallbackSignal = Net::experimental::concurrent_channel<void(boost::system::error_code)>;

    /** @brief 一代 callback 注册表唯一拥有者；wrapper 只弱引用本 owner。 */
    class BoundTlsCarrierCatalog final
        : public Prism::Contract::CarrierCatalogOwner,
          public std::enable_shared_from_this<BoundTlsCarrierCatalog>
    {
    public:
        struct Entry final
        {
            Prism::Composition::Protocol::ProviderKey Key;
            std::string Id;
            CarrierRegistration Registration;
        };

        BoundTlsCarrierCatalog(const BoundTlsCarrierCatalog &) = delete;
        auto operator=(const BoundTlsCarrierCatalog &) -> BoundTlsCarrierCatalog & = delete;
        ~BoundTlsCarrierCatalog() override { Close(); }

        /** @brief 把弱包装 callback 登记到尚未发布的 registry。 */
        [[nodiscard]] auto Register(Recognition::CandidateRegistry &Registry)
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

        /** @brief 封止本 catalog 的新 callback；已有协程继续持有活动计数。 */
        auto Close() noexcept -> void override
        {
            const auto Previous = Gate_.fetch_or(ClosedBit, std::memory_order_acq_rel);
            if ((Previous & CountMask) == 0U)
            {
                NotifyDrain();
            }
        }

        /** @brief 等待 callback frame 与 generation lease 退出，再清理闭包并发布退休回执。 */
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, CarrierFailure>> override
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
                co_await Signal->async_receive(
                    Net::redirect_error(Net::use_awaitable, Error));
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

        /** @brief 只有 owner 已封 admission、无活动回调并清空 registrations 后为 true。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Retired_.load(std::memory_order_acquire);
        }

    private:
        friend class FrozenTlsCarrierCatalog;

        struct Invocation final
        {
            std::shared_ptr<BoundTlsCarrierCatalog> Owner;
            Prism::Foundation::GenerationUseLease Lease;
            ~Invocation()
            {
                Lease = {};
                Owner->Leave();
            }
        };

        struct DrainGuard final
        {
            std::atomic_flag &Flag;
            ~DrainGuard() { Flag.clear(std::memory_order_release); }
        };

        explicit BoundTlsCarrierCatalog(
            std::vector<Entry> Values,
            std::shared_ptr<Prism::Foundation::GenerationUseState> UseState)
            : Entries_(std::move(Values)), UseState_(std::move(UseState))
        {
        }

        [[nodiscard]] auto MakeRegistration(const std::size_t Index)
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

        template<typename Input>
        [[nodiscard]] static auto InvokeOrRetire(
            std::weak_ptr<BoundTlsCarrierCatalog> Weak,
            const std::size_t Index,
            Input Request) -> Net::awaitable<CarrierResult>
        {
            if (auto Owner = Weak.lock())
            {
                co_return co_await Owner->Invoke(Index, std::move(Request));
            }
            co_return co_await RejectInput(
                std::move(Request), CarrierFailure{Prism::Fault::Code::ResourceUnavailable});
        }

        template<typename Input>
        [[nodiscard]] auto Invoke(const std::size_t Index, Input Request)
            -> Net::awaitable<CarrierResult>
        {
            if (!Enter())
            {
                co_return co_await RejectInput(
                    std::move(Request), CarrierFailure{Prism::Fault::Code::ResourceUnavailable});
            }
            auto Lease = UseState_ ? UseState_->Acquire()
                : std::expected<Prism::Foundation::GenerationUseLease, CarrierFailure>{
                    std::unexpected(CarrierFailure{Prism::Fault::Code::ResourceUnavailable})};
            if (!Lease)
            {
                Leave();
                co_return co_await RejectInput(std::move(Request), Lease.error());
            }
            Invocation Active{shared_from_this(), std::move(*Lease)};
            if (Index >= Entries_.size())
            {
                co_return co_await RejectInput(
                    std::move(Request), CarrierFailure{Prism::Fault::Code::InvalidArgument});
            }
            if constexpr (std::is_same_v<Input, Core::CarrierAcceptInput>)
            {
                co_return co_await Entries_[Index].Registration.Accept(std::move(Request));
            }
            else
            {
                co_return co_await Entries_[Index].Registration.AcceptPrepared(std::move(Request));
            }
        }

        template<typename Input>
        [[nodiscard]] static auto RejectInput(Input Request, CarrierFailure Cause)
            -> Net::awaitable<CarrierResult>
        {
            CarrierResult Result;
            const auto Failure = co_await Recognition::Detail::RetireCarrierInput(
                std::move(Request.Inbound), Cause);
            Recognition::Detail::SetCarrierFailure(Result, Failure);
            co_return Result;
        }

        [[nodiscard]] auto Enter() noexcept -> bool
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

        auto Leave() noexcept -> void
        {
            const auto Previous = Gate_.fetch_sub(1U, std::memory_order_acq_rel);
            if ((Previous & ClosedBit) != 0U && (Previous & CountMask) == 1U)
            {
                NotifyDrain();
            }
        }

        [[nodiscard]] auto ActiveCount() const noexcept -> std::uint64_t
        {
            return Gate_.load(std::memory_order_acquire) & CountMask;
        }

        auto NotifyDrain() noexcept -> void
        {
            if (const auto Signal = Waiter_.load(std::memory_order_acquire))
            {
                (void)Signal->try_send(boost::system::error_code{});
            }
        }

        auto ClearWaiter(const std::shared_ptr<CallbackSignal> &Signal) noexcept -> void
        {
            auto Expected = Signal;
            (void)Waiter_.compare_exchange_strong(
                Expected, std::shared_ptr<CallbackSignal>{},
                std::memory_order_acq_rel, std::memory_order_acquire);
        }

        [[nodiscard]] static auto ProviderFailure(
            const Prism::Contract::ProviderError Code,
            const std::string_view Id,
            const std::string_view Path) -> Prism::Contract::ProviderFailure
        {
            return {Code, std::string(Id), std::string(Path)};
        }

        static constexpr std::uint64_t ClosedBit{std::uint64_t{1} << 63U};
        static constexpr std::uint64_t CountMask{ClosedBit - 1U};
        std::vector<Entry> Entries_;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState_;
        std::atomic<std::uint64_t> Gate_{0U};
        std::atomic<bool> Retired_{false};
        std::atomic_flag Draining_ = ATOMIC_FLAG_INIT;
        std::atomic<std::shared_ptr<CallbackSignal>> Waiter_{};
        bool Registered_{false};
    };
}
