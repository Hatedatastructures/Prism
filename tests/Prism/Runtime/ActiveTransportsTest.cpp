#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <system_error>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <Prism/Contract/Ingress/DatagramSession.hpp>
#include <Prism/Contract/Ingress/DataPlane.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Protocols/Common/ProtocolActivity.hpp>
#include <Prism/Runtime/ActiveTransports.hpp>
#include <Prism/Runtime/CarrierDomain.hpp>
#include <Prism/Runtime/ListenerConnectionDrain.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;
    using Failure = Prism::Fault::Failure;

    class MismatchedExecutorTransport final : public Prism::Transmission
    {
    public:
        MismatchedExecutorTransport(Net::any_io_executor ActivityExecutor,
                                    Net::any_io_executor ReportedExecutor)
            : Prism::Transmission(std::move(ActivityExecutor)),
              ReportedExecutor_(std::move(ReportedExecutor))
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return ReportedExecutor_;
        }
        [[nodiscard]] auto IsOpen() const -> bool override { return true; }
        [[nodiscard]] auto TransportType() const noexcept -> Type override { return Type::Tcp; }

    protected:
        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            (void)Handler;
        }
        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            (void)Handler;
        }
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            (void)Handler;
        }
        [[nodiscard]] auto OnClose() -> ControlResult override { return {}; }
        [[nodiscard]] auto OnCancel() -> ControlResult override { return {}; }

    private:
        Net::any_io_executor ReportedExecutor_;
    };

    /** @brief 可重复尝试的测试原生端点；首个 Close 留下可观察 native 失败。 */

    struct ActiveTransportWorker final
    {
        Prism::Runtime::ActiveTransports &Active;
        std::shared_ptr<Prism::PrismMockTransport> First;
        std::shared_ptr<Prism::PrismMockTransport> Second;
        std::atomic_bool &Failed;
        std::atomic<int> &FirstFailureCode;
        int Index{0};

        /** @brief 保留并发 fixture 首次失败的 typed code 供原断言输出。 */
        auto RecordFailure(Failure Error) -> void
        {
            Failed.store(true, std::memory_order_release);
            auto Expected = -1;
            (void)FirstFailureCode.compare_exchange_strong(
                Expected, static_cast<int>(Error.Code), std::memory_order_acq_rel);
        }
    };

    auto RunActiveTransportWorker(ActiveTransportWorker Worker) -> void
    {
        for (int Iteration = 0; Iteration < 10000; ++Iteration)
        {
            auto Value = ((Iteration + Worker.Index) % 2 == 0) ? Worker.First : Worker.Second;
            const auto Domain = Prism::Runtime::CarrierDomain::Create(
                Value->Executor(), Value->Activity());
            if (!Domain)
            {
                Worker.RecordFailure(Domain.error());
                continue;
            }
            auto Inbound = Worker.Active.StoreInbound(Value, *Domain);
            if (!Inbound)
            {
                Worker.RecordFailure(Inbound.error());
                continue;
            }
            auto Outbound = Worker.Active.StoreOutbound(Value, *Domain);
            if (!Outbound)
            {
                Worker.RecordFailure(Outbound.error());
                continue;
            }
            Inbound->reset();
            Outbound->reset();
            const auto Snapshot = Worker.Active.Load();
            if ((Snapshot.Inbound && Snapshot.Inbound != Worker.First &&
                 Snapshot.Inbound != Worker.Second) ||
                (Snapshot.Outbound && Snapshot.Outbound != Worker.First &&
                 Snapshot.Outbound != Worker.Second))
            {
                Worker.RecordFailure(Failure{Prism::Fault::Code::InvalidArgument});
            }
        }
    }


    TEST(ActiveTransports, ConcurrentStoreAndLoadKeepsTransmissionOwnership)
    {
        boost::asio::io_context IoContext;
        auto First = std::make_shared<Prism::PrismMockTransport>(IoContext.get_executor());
        auto Second = std::make_shared<Prism::PrismMockTransport>(IoContext.get_executor());
        std::weak_ptr<Prism::PrismMockTransport> FirstOwner = First;
        std::weak_ptr<Prism::PrismMockTransport> SecondOwner = Second;
        Prism::Runtime::ActiveTransports Active;
        std::atomic_bool Failed{false};
        std::atomic<int> FirstFailureCode{-1};
        std::vector<std::thread> Threads;
        auto Work = Net::make_work_guard(IoContext);
        std::thread IoRunner([&IoContext] { IoContext.run(); });

        for (int Index = 0; Index < 4; ++Index)
        {
            Threads.emplace_back(RunActiveTransportWorker, ActiveTransportWorker{
                Active, First, Second, Failed, FirstFailureCode, Index});
        }

        for (auto &Thread : Threads)
        {
            Thread.join();
        }
        Work.reset();
        IoRunner.join();

        EXPECT_FALSE(Failed.load(std::memory_order_acquire))
            << "first_failure_code=" << FirstFailureCode.load(std::memory_order_acquire);
        auto Final = Active.Load();
        EXPECT_TRUE(Final.Inbound);
        EXPECT_TRUE(Final.Outbound);
        Final = Prism::Runtime::ActiveTransportSnapshot{};
        EXPECT_FALSE(First->IsClosed());
        EXPECT_FALSE(Second->IsClosed());
        First.reset();
        Second.reset();

        std::expected<void, Failure> Finalized;
        std::exception_ptr Fatal;
        IoContext.restart();
        boost::asio::co_spawn(
            IoContext, Active.Finalize(),
            [&Fatal, &Finalized](std::exception_ptr Error, std::expected<void, Failure> Result)
            {
                Fatal = std::move(Error);
                Finalized = std::move(Result);
            });
        IoContext.run();

        EXPECT_FALSE(Fatal);
        std::string FinalizeDiagnostic;
        if (!Finalized)
        {
            FinalizeDiagnostic = std::string("code=") +
                std::to_string(static_cast<int>(Finalized.error().Code)) +
                " native=" + Finalized.error().Native.category().name() + "/" +
                std::to_string(Finalized.error().Native.value());
        }
        EXPECT_TRUE(Finalized) << FinalizeDiagnostic;
        EXPECT_TRUE(FirstOwner.expired());
        EXPECT_TRUE(SecondOwner.expired());
    }

    TEST(ActiveTransports, RejectsTransmissionExecutorThatDisagreesWithActivity)
    {
        Net::io_context ActivityContext;
        Net::io_context ReportedContext;
        auto Value = std::make_shared<MismatchedExecutorTransport>(
            ActivityContext.get_executor(), ReportedContext.get_executor());
        const auto Domain = Prism::Runtime::CarrierDomain::Create(
            Value->Activity()->Executor(), Value->Activity());
        ASSERT_TRUE(Domain);

        Prism::Runtime::ActiveTransports Active;
        const auto Stored = Active.StoreInbound(Value, *Domain);

        ASSERT_FALSE(Stored);
        EXPECT_EQ(Stored.error().Code, Prism::Fault::Code::InvalidArgument);
        EXPECT_TRUE(Value->IsOpen());
    }

} // namespace
