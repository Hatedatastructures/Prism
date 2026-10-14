/**
 * @file DnsPerfCoalescerOwner.cpp
 * @brief DNS coalescer 所有者、fake resolver 批次与 round 生命周期实现。
 */

#include "DnsPerfCoalescer.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <exception>
#include <future>
#include <functional>
#include <string>
#include <system_error>
#include <thread>
#include <utility>

namespace DnsPerf
{
    struct CoalescerBatch final
    {
        CoalescerBatch(const Net::any_io_executor Executor)
            : Started(std::make_shared<GateChannel>(Executor, CoalescerWaiters)),
              Done(std::make_shared<GateChannel>(Executor, CoalescerWaiters))
        {
            for (auto &Signal : Cancellations)
            {
                Signal = std::make_shared<Net::cancellation_signal>();
            }
        }

        std::shared_ptr<GateChannel> Started;
        std::shared_ptr<GateChannel> Done;
        std::array<std::shared_ptr<Net::cancellation_signal>, CoalescerWaiters> Cancellations;
        std::array<std::atomic<bool>, CoalescerWaiters> StartedSent{};
        std::array<std::atomic<bool>, CoalescerWaiters> DoneSent{};
        std::array<bool, CoalescerWaiters> Success{};
        std::array<ErrorInfo, CoalescerWaiters> Errors{};
    };

    namespace
    {
        auto PublishBatchStarted(
            const std::shared_ptr<CoalescerBatch> &Batch, const std::size_t Index) -> void
        {
            bool Expected = false;
            if (Batch->StartedSent[Index].compare_exchange_strong(
                    Expected, true, std::memory_order_acq_rel))
            {
                (void)Batch->Started->try_send(boost::system::error_code{});
            }
        }

        auto PublishBatchDone(
            const std::shared_ptr<CoalescerBatch> &Batch, const std::size_t Index) -> void
        {
            bool Expected = false;
            if (Batch->DoneSent[Index].compare_exchange_strong(
                    Expected, true, std::memory_order_acq_rel))
            {
                (void)Batch->Done->try_send(boost::system::error_code{});
            }
        }

        struct CoalescerResolveRequest final
        {
            Net::io_context *IoContext{nullptr};
            Preview::Network::Dns::Resolver *Resolver{nullptr};
            std::shared_ptr<CoalescerBatch> Batch;
            std::shared_ptr<CoalescerRoundSignals> Signals;
            std::string Domain;
            std::string ValidationMessage;
            std::size_t Index{0};
        };

        struct CoalescerResolveCompletion final
        {
            std::shared_ptr<CoalescerBatch> Batch;
            std::size_t Index{0};

            auto operator()(std::exception_ptr Failure) const -> void
            {
                if (Failure && Batch->Errors[Index].Category == "none")
                {
                    Batch->Errors[Index] = MakeExceptionInfo(Failure);
                }
                PublishBatchStarted(Batch, Index);
                PublishBatchDone(Batch, Index);
            }
        };

        auto RunCoalescerResolve(CoalescerResolveRequest Request) -> Net::awaitable<void>
        {
            PublishBatchStarted(Request.Batch, Request.Index);
            if (Request.Signals->StopRequested.load(std::memory_order_acquire))
            {
                Request.Batch->Errors[Request.Index] = {"canceled", 1, "round_stopped"};
                co_return;
            }
            try
            {
                if (Request.Resolver == nullptr)
                {
                    Request.Batch->Errors[Request.Index] = {"owner", 1, "resolver_missing"};
                    co_return;
                }
                const auto Addresses = co_await Request.Resolver->AsyncResolve(
                    Request.Domain);
                const auto Failure = Addresses ? Preview::Fault::Failure{} : Addresses.error();
                Request.Batch->Errors[Request.Index] = MakeErrorInfo(Failure);
                Request.Batch->Success[Request.Index] =
                    !Request.Signals->StopRequested.load(std::memory_order_acquire) &&
                    Addresses && Addresses->Size() == 1U;
                if (!Request.Batch->Success[Request.Index] && Failure.Succeeded() &&
                    !Request.Signals->StopRequested.load(std::memory_order_acquire))
                {
                    Request.Batch->Errors[Request.Index] = {
                        "validation", 1, Request.ValidationMessage};
                }
            }
            catch (...)
            {
                Request.Batch->Errors[Request.Index] = MakeExceptionInfo(std::current_exception());
            }
        }

        auto StartCoalescerResolve(CoalescerResolveRequest Request) -> void
        {
            try
            {
                Net::co_spawn(
                    *Request.IoContext,
                    RunCoalescerResolve(Request),
                    Net::bind_cancellation_slot(
                        Request.Batch->Cancellations[Request.Index]->slot(),
                        CoalescerResolveCompletion{Request.Batch, Request.Index}));
            }
            catch (...)
            {
                Request.Batch->Errors[Request.Index] = MakeExceptionInfo(std::current_exception());
                PublishBatchStarted(Request.Batch, Request.Index);
                PublishBatchDone(Request.Batch, Request.Index);
            }
        }
    } // namespace

    class CoalescerOwnerImpl final : public CoalescerOwner
    {
    public:
        CoalescerOwnerImpl()
            : Latencies_(CoalescerFlights, 0U),
              SameDomain_(CoalescerSameDomain),
              IsolatedDomains_(CoalescerFlights)
        {
            for (std::size_t Index = 0; Index < CoalescerFlights; ++Index)
            {
                IsolatedDomains_[Index] = std::string(CoalescerIsolatedPrefix) +
                    std::to_string(Index) + ".perf.example.com";
            }
        }

        ~CoalescerOwnerImpl() noexcept override
        {
            (void)Stop();
        }

        [[nodiscard]] auto Start() -> bool override
        {
            Runtime = std::make_unique<PerfDnsRuntime>();
            if (!Runtime->Start())
            {
                return false;
            }
            ResolverOwner = std::make_unique<Preview::Network::Dns::Resolver>(
                IoContext.get_executor(), MakeResolverConfig(ResolverConfigRequest{*Runtime->Server(), false}));
            const auto Ready = std::make_shared<ReadySignal>();
            auto ReadyFuture = Ready->Promise.get_future();
            IoThread = std::thread(&CoalescerOwnerImpl::RunIoThread, this, Ready);
            if (ReadyFuture.wait_for(std::chrono::seconds(2)) != std::future_status::ready ||
                !ReadyFuture.get())
            {
                (void)Stop();
                return false;
            }
            return true;
        }

        [[nodiscard]] auto Stop() noexcept -> bool override
        {
            bool Stopped = true;
            if (IoThread.joinable())
            {
                RequestRoundStop();
                const auto Active = std::atomic_load_explicit(
                    &ActiveRound_, std::memory_order_acquire);
                if (Active && Active->Retired)
                {
                    auto RetiredFuture = Active->Retired->Promise.get_future();
                    if (RetiredFuture.wait_for(std::chrono::seconds(5)) !=
                        std::future_status::ready)
                    {
                        Stopped = false;
                        IoContext.stop();
                    }
                }
                const auto Released = std::make_shared<ReadySignal>();
                const auto ReleasedFuture = Released->Promise.get_future();
                if (Stopped)
                {
                    Net::post(IoContext, [this, Released]
                    {
                        ResolverOwner.reset();
                        Released->Publish(true);
                    });
                    if (ReleasedFuture.wait_for(std::chrono::seconds(5)) !=
                        std::future_status::ready)
                    {
                        Stopped = false;
                        IoContext.stop();
                    }
                }
                IoThread.join();
            }
            ResolverOwner.reset();
            if (Runtime)
            {
                Runtime->Stop();
                Runtime.reset();
            }
            return Stopped;
        }

        [[nodiscard]] auto MakeRoundSignals()
            -> std::shared_ptr<CoalescerRoundSignals> override
        {
            return std::make_shared<CoalescerRoundSignals>(IoContext.get_executor());
        }

        auto PrepareRound() -> void override
        {
            std::fill(Latencies_.begin(), Latencies_.end(), 0U);
            QueryStart = Runtime->Server()->QueryCount();
            ResponseStart = Runtime->Server()->ResponseCount();
        }

        auto LaunchRound(
            const std::size_t Flights,
            const std::shared_ptr<CoalescerRoundSignals> &Signals) -> void override
        {
            Signals->Retired = std::make_shared<ReadySignal>();
            Signals->StopRequested.store(false, std::memory_order_release);
            std::atomic_store_explicit(&ActiveRound_, Signals, std::memory_order_release);
            try
            {
                Net::co_spawn(
                    IoContext, RunRound(Flights, Signals),
                    std::bind_front(&CoalescerOwnerImpl::CompleteRound, this, Signals));
            }
            catch (...)
            {
                Signals->Ready->Publish(false);
                Signals->Fail(MakeExceptionInfo(std::current_exception()));
                Signals->Done->Publish(false);
                Signals->Retired->Publish(true);
                std::atomic_store_explicit(
                    &ActiveRound_, std::shared_ptr<CoalescerRoundSignals>{},
                    std::memory_order_release);
            }
        }

        auto OpenRound(const std::shared_ptr<CoalescerRoundSignals> &Signals) -> void override
        {
            Net::post(IoContext, [Signals]
            { (void)Signals->Begin->try_send(boost::system::error_code{}); });
        }

        [[nodiscard]] auto QueryDelta() const noexcept -> std::size_t override
        {
            return Runtime->Server()->QueryCount() - QueryStart;
        }

        [[nodiscard]] auto ResponseDelta() const noexcept -> std::size_t override
        {
            return Runtime->Server()->ResponseCount() - ResponseStart;
        }

        auto AbortRound() -> void override
        {
            RequestRoundStop();
        }

        [[nodiscard]] auto Latencies() const noexcept
            -> const std::vector<std::uint64_t> & override
        {
            return Latencies_;
        }

    private:
        auto RunIoThread(const std::shared_ptr<ReadySignal> &Ready) -> void
        {
            Ready->Publish(true);
            try
            {
                IoContext.run();
            }
            catch (...)
            {
                Ready->Publish(false);
            }
        }

        auto RunRound(const std::size_t Flights,
                      std::shared_ptr<CoalescerRoundSignals> Signals)
            -> Net::awaitable<void>
        {
            Signals->Ready->Publish(true);
            boost::system::error_code BeginError;
            co_await Signals->Begin->async_receive(
                Net::redirect_error(Net::use_awaitable, BeginError));
            if (BeginError)
            {
                Signals->Fail(MakeErrorInfo(BeginError));
                Signals->Done->Publish(false);
                Signals->Retired->Publish(true);
                std::atomic_store_explicit(
                    &ActiveRound_, std::shared_ptr<CoalescerRoundSignals>{},
                    std::memory_order_release);
                co_return;
            }
            bool Success = false;
            try
            {
                Success = co_await RunBatch(Flights, Signals);
            }
            catch (...)
            {
                Signals->Fail(MakeExceptionInfo(std::current_exception()));
            }
            Signals->Done->Publish(Success && Signals->Error.Category == "none");
            Signals->Retired->Publish(true);
            std::atomic_store_explicit(
                &ActiveRound_, std::shared_ptr<CoalescerRoundSignals>{},
                std::memory_order_release);
        }

        auto CompleteRound(const std::shared_ptr<CoalescerRoundSignals> &Signals,
                           std::exception_ptr Failure) -> void
        {
            if (Failure)
            {
                Signals->Ready->Publish(false);
                Signals->Fail(MakeExceptionInfo(Failure));
                Signals->Done->Publish(false);
            }
            Signals->Retired->Publish(true);
        }

        auto RequestRoundStop() noexcept -> void
        {
            const auto Signals = std::atomic_load_explicit(
                &ActiveRound_, std::memory_order_acquire);
            if (Signals)
            {
                Signals->StopRequested.store(true, std::memory_order_release);
                const auto Batch = std::atomic_load_explicit(
                    &Signals->ActiveBatch, std::memory_order_acquire);
                Net::post(IoContext, std::bind_front(
                    &CoalescerOwnerImpl::StopRoundOnIo, this, Signals, Batch));
            }
            if (Runtime)
            {
                Net::post(Runtime->IoContext(), [Server = Runtime->Server()]
                { Server->Close(); });
            }
        }

        auto StopRoundOnIo(const std::shared_ptr<CoalescerRoundSignals> &Signals,
                           const std::shared_ptr<CoalescerBatch> &Batch) -> void
        {
            Signals->StopRequested.store(true, std::memory_order_release);
            (void)Signals->Begin->try_send(boost::asio::error::operation_aborted);
            if (Batch)
            {
                for (const auto &Cancellation : Batch->Cancellations)
                {
                    Cancellation->emit(Net::cancellation_type::all);
                }
            }
        }

        [[nodiscard]] auto RunSameFlight(
            const std::string &Domain,
            const std::shared_ptr<CoalescerRoundSignals> &Signals)
            -> Net::awaitable<bool>
        {
            const auto Batch = std::make_shared<CoalescerBatch>(IoContext.get_executor());
            std::atomic_store_explicit(&Signals->ActiveBatch, Batch, std::memory_order_release);
            const auto ResolverValue = ResolverOwner.get();
            for (std::size_t Index = 0; Index < CoalescerWaiters; ++Index)
            {
                try
                {
                    StartCoalescerResolve(CoalescerResolveRequest{
                        &IoContext, ResolverValue, Batch, Signals, Domain,
                        "address_count", Index});
                }
                catch (...)
                {
                    Batch->Errors[Index] = MakeExceptionInfo(std::current_exception());
                    PublishBatchStarted(Batch, Index);
                    PublishBatchDone(Batch, Index);
                }
            }
            for (std::size_t Index = 0; Index < CoalescerWaiters; ++Index)
            {
                co_await Batch->Started->async_receive(Net::use_awaitable);
            }
            for (std::size_t Index = 0; Index < CoalescerWaiters; ++Index)
            {
                co_await Batch->Done->async_receive(Net::use_awaitable);
            }
            std::atomic_store_explicit(
                &Signals->ActiveBatch, std::shared_ptr<CoalescerBatch>{},
                std::memory_order_release);
            for (std::size_t Index = 0; Index < CoalescerWaiters; ++Index)
            {
                if (!Batch->Success[Index])
                {
                    Signals->Fail(Batch->Errors[Index]);
                    co_return false;
                }
            }
            co_return true;
        }

        [[nodiscard]] auto RunIsolated(
            const std::string &Domain,
            const std::shared_ptr<CoalescerRoundSignals> &Signals)
            -> Net::awaitable<bool>
        {
            const auto Batch = std::make_shared<CoalescerBatch>(IoContext.get_executor());
            std::atomic_store_explicit(&Signals->ActiveBatch, Batch, std::memory_order_release);
            const auto ResolverValue = ResolverOwner.get();
            try
            {
                StartCoalescerResolve(CoalescerResolveRequest{
                    &IoContext, ResolverValue, Batch, Signals, Domain,
                    "isolated_address_count", 0});
            }
            catch (...)
            {
                Batch->Errors[0] = MakeExceptionInfo(std::current_exception());
                PublishBatchStarted(Batch, 0);
                PublishBatchDone(Batch, 0);
            }
            co_await Batch->Done->async_receive(Net::use_awaitable);
            std::atomic_store_explicit(
                &Signals->ActiveBatch, std::shared_ptr<CoalescerBatch>{},
                std::memory_order_release);
            if (!Batch->Success[0])
            {
                Signals->Fail(Batch->Errors[0]);
                co_return false;
            }
            co_return true;
        }

        [[nodiscard]] auto RunBatch(
            const std::size_t Flights,
            const std::shared_ptr<CoalescerRoundSignals> &Signals)
            -> Net::awaitable<bool>
        {
            for (std::size_t Index = 0; Index < Flights; ++Index)
            {
                if (Signals->StopRequested.load(std::memory_order_acquire))
                {
                    Signals->Fail({"canceled", 1, "round_stopped"});
                    co_return false;
                }
                const auto Start = NowNs();
                if (!co_await RunSameFlight(SameDomain_, Signals))
                {
                    co_return false;
                }
                if (!co_await RunIsolated(IsolatedDomains_[Index], Signals))
                {
                    co_return false;
                }
                Latencies_[Index] = NowNs() - Start;
                ++Signals->CompletedOperations;
            }
            co_return true;
        }

        std::unique_ptr<PerfDnsRuntime> Runtime;
        Net::io_context IoContext;
        std::unique_ptr<Preview::Network::Dns::Resolver> ResolverOwner;
        std::thread IoThread;
        std::vector<std::uint64_t> Latencies_;
        std::string SameDomain_;
        std::vector<std::string> IsolatedDomains_;
        std::size_t QueryStart{0};
        std::size_t ResponseStart{0};
        std::shared_ptr<CoalescerRoundSignals> ActiveRound_;
    };

    auto MakeCoalescerOwner() -> std::unique_ptr<CoalescerOwner>
    {
        return std::make_unique<CoalescerOwnerImpl>();
    }

} // namespace DnsPerf
