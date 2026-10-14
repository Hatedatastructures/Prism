/** @file RootRegistry.hpp @brief 以预创建节点强持有未退休 mux root。 */
#pragma once
#include <Preview/Protocols/Mux/Detail/Root/RootSession.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Fault/FailureState.hpp>
#include <boost/system/system_error.hpp>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <system_error>
#include <utility>

namespace Preview::Mux::Detail
{
    class RootRegistry final
    {
        static constexpr std::uint64_t ClosedMask = std::uint64_t{1} << 63U;
        static constexpr std::uint64_t RegistrationMask = ~ClosedMask;

    public:
        /** @brief 保持冷创建登记未完成，直到 RootBinding 已转交完整 Plane。 */
        class Registration final
        {
        public:
            explicit Registration(std::atomic_uint64_t &Value) noexcept : Gate(Value)
            {
                auto Current = Gate.load(std::memory_order_acquire);
                while (!(Current & ClosedMask))
                {
                    if ((Current & RegistrationMask) == RegistrationMask) return;
                    if (Gate.compare_exchange_weak(Current, Current + 1U,
                            std::memory_order_acq_rel, std::memory_order_acquire))
                    {
                        Active = true;
                        return;
                    }
                }
            }
            Registration(const Registration &) = delete;
            auto operator=(const Registration &) -> Registration & = delete;
            Registration(Registration &&Other) noexcept
                : Gate(Other.Gate), Active(std::exchange(Other.Active, false)) {}
            auto operator=(Registration &&) -> Registration & = delete;
            ~Registration()
            {
                if (Active) Gate.fetch_sub(1U, std::memory_order_release);
            }
            explicit operator bool() const noexcept { return Active; }

        private:
            std::atomic_uint64_t &Gate;
            bool Active{false};
        };

    private:
        struct State final : RootRetirementOwner
        {
            auto Retire(Preview::Fault::Failure Failure) noexcept -> void override
            {
                (void)HistoricalFailure.TrySet(Failure);
                CollectRetired();
            }

            auto CollectRetired() noexcept -> void
            {
                for (;;)
                {
                    std::shared_ptr<RootRegistryNode> Previous;
                    auto Current = Head.load(std::memory_order_acquire);
                    bool Retry = false;
                    while (Current)
                    {
                        const auto Next = Current->Next.load(std::memory_order_acquire);
                        if (Current->Owner && Current->Owner->IsRetired())
                        {
                            auto Expected = Current;
                            bool Removed = false;
                            if (Previous)
                                Removed = Previous->Next.compare_exchange_weak(
                                    Expected, Next, std::memory_order_acq_rel,
                                    std::memory_order_acquire);
                            else
                                Removed = Head.compare_exchange_weak(
                                    Expected, Next, std::memory_order_acq_rel,
                                    std::memory_order_acquire);
                            if (!Removed)
                            {
                                Retry = true;
                                break;
                            }
                            Current = Next;
                            continue;
                        }
                        Previous = Current;
                        Current = Next;
                    }
                    if (!Retry) return;
                }
            }

            std::atomic_uint64_t RegistrationGate{0};
            std::atomic<std::shared_ptr<RootRegistryNode>> Head;
            Preview::Fault::FailureState HistoricalFailure;
        };

        struct PendingRootOwner final
        {
            explicit PendingRootOwner(std::shared_ptr<RootRegistryNode> Value) noexcept
                : Node(std::move(Value)) {}
            ~PendingRootOwner()
            {
                if (!Published) Node->Owner.reset();
            }
            std::shared_ptr<RootRegistryNode> Node;
            bool Published{false};
        };

        [[nodiscard]] static auto FailureFromException(std::exception_ptr Failure) noexcept
            -> Preview::Fault::Failure
        {
            try
            {
                if (Failure) std::rethrow_exception(Failure);
            }
            catch (const boost::system::system_error &Error)
            {
                return Preview::Fault::FromNative(static_cast<std::error_code>(Error.code()));
            }
            catch (const std::system_error &Error)
            {
                return Preview::Fault::FromNative(Error.code());
            }
            catch (...) { return {Preview::Fault::Code::IoError}; }
            return {Preview::Fault::Code::IoError};
        }

    public:
        RootRegistry() : State_(std::make_shared<State>()) {}

        /** @brief 把冷创建时预留的 owner 节点转交给 registry；登记过程不分配。 */
        [[nodiscard]] auto Register(const std::shared_ptr<RootSession> &Root)
            -> std::optional<Registration>
        {
            if (!Root) return {};
            Registration InFlight(State_->RegistrationGate);
            if (!InFlight) return {};
            const auto Node = Root->RegistrationNode_;
            if (!Node) return {};
            bool Unregistered = false;
            if (!Node->Registered.compare_exchange_strong(
                    Unregistered, true, std::memory_order_acq_rel,
                    std::memory_order_acquire)) return {};

            PendingRootOwner OwnerGuard(Node);
            Root->SetRetirementOwner(State_);
            Node->Owner = Root;
            auto Current = State_->Head.load(std::memory_order_acquire);
            do
            {
                Node->Next.store(Current, std::memory_order_release);
            }
            while (!State_->Head.compare_exchange_weak(
                Current, Node, std::memory_order_acq_rel, std::memory_order_acquire));
            OwnerGuard.Published = true;
            Root->RegistrationNode_.reset();

            const auto Closed = IsClosed();
            if (Closed) Root->Close();
            return std::optional<Registration>{std::move(InFlight)};
        }

        /** @brief 封止新注册并向当前目录中的每个 root 发出取消。 */
        auto Close() noexcept -> void
        {
            State_->RegistrationGate.fetch_or(ClosedMask, std::memory_order_acq_rel);
            for (auto Node = State_->Head.load(std::memory_order_acquire); Node;
                 Node = Node->Next.load(std::memory_order_acquire))
                if (Node->Owner) Node->Owner->Close();
        }

        [[nodiscard]] auto IsClosed() const noexcept -> bool
        {
            return (State_->RegistrationGate.load(std::memory_order_acquire) & ClosedMask) != 0U;
        }

        /** @brief 只在封止、无登记中请求且目录确实为空时报告物理退休。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool
        {
            const auto Gate = State_->RegistrationGate.load(std::memory_order_acquire);
            return (Gate & ClosedMask) != 0U && (Gate & RegistrationMask) == 0U &&
                !State_->Head.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            Close();
            const auto Gate = State_->RegistrationGate.load(std::memory_order_acquire);
            if ((Gate & RegistrationMask) != 0U)
            {
                const auto Failure = State_->HistoricalFailure.Load();
                if (Failure.Failed()) co_return std::unexpected(Failure);
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            const auto Snapshot = State_->Head.load(std::memory_order_acquire);
            for (auto Node = Snapshot; Node;)
            {
                const auto Next = Node->Next.load(std::memory_order_acquire);
                if (Node->Owner)
                {
                    try
                    {
                        const auto Result = co_await Node->Owner->Drain();
                        if (!Result) (void)State_->HistoricalFailure.TrySet(Result.error());
                    }
                    catch (...)
                    {
                        (void)State_->HistoricalFailure.TrySet(
                            FailureFromException(std::current_exception()));
                    }
                }
                Node = Next;
            }
            State_->CollectRetired();
            const auto Failure = State_->HistoricalFailure.Load();
            if (Failure.Failed()) co_return std::unexpected(Failure);
            if (!IsRetired())
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

    private:
        std::shared_ptr<State> State_;
    };
}
