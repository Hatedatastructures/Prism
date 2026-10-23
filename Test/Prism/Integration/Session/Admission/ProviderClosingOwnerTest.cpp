/** @file ProviderClosingOwnerTest.cpp @brief 实际 Application owner 释放后 L1 保存真实 worker context/PMR，失败不标完成。 */
#include <Prism/Application/ClosingFailure.hpp>
#include <Prism/Application/RuntimeGenerationSnapshot.hpp>
#include <Prism/Application/Shutdown.hpp>
#include <Prism/Application/Startup/GenerationPhase.hpp>
#include <Prism/Composition/Provider/ProviderCatalog.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Protocols/Common/BindingLifetime.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Runtime/WorkerDispatchResult.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <expected>
#include <filesystem>
#include <TestSupport/Prism/ProviderBindings.hpp>
#include <thread>
namespace
{
    namespace Net = boost::asio;
    using Signal = Net::experimental::channel<void(boost::system::error_code)>;
    /** @brief 构造携带显式有界字节池的 provider 接入输入。 */
    [[nodiscard]] auto MakeStreamAcceptInput(Prism::SharedTransmission Inbound)
        -> Prism::Contract::StreamAcceptInput
    {
        return {std::move(Inbound),{},
            std::make_shared<Prism::Memory::BytePool>(Prism::Memory::BytePoolOptions{.BlockCount=8})};
    }

    struct PendingProviderState final
    {
        explicit PendingProviderState(Net::any_io_executor Executor)
            : Entered(Executor, 1), Release(Executor, 1)
        {
        }
        Signal Entered, Release;
        std::atomic<std::size_t> CloseRequests{0};
        std::atomic<bool> ReadReleased{false}, Destroyed{false};
    };

    class PendingProviderCarrier final : public Prism::Transmission
    {
    public:
        PendingProviderCarrier(Net::any_io_executor Executor, std::shared_ptr<PendingProviderState> State)
            : Prism::Transmission(Executor), Executor_(std::move(Executor)), State_(std::move(State))
        {
        }
        ~PendingProviderCarrier() override
        {
            State_->Destroyed.store(true, std::memory_order_release);
        }
        auto Executor() const -> ExecutorType override
        {
            return Executor_;
        }
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(ReadWork{}, Executor_), Handler,
                ReadInput{std::static_pointer_cast<PendingProviderCarrier>(Prism::Transmission::shared_from_this()),
                    Buffer});
        }
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(WriteWork{}, Executor_), Handler,
                WriteInput{std::static_pointer_cast<PendingProviderCarrier>(Prism::Transmission::shared_from_this()),
                    Buffer});
        }
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto* Inner = NextLayer())
            {
                Inner->WriteShutdown(std::move(Handler));
                return;
            }
            Prism::Transmission::PostResult(Executor_, std::move(Handler), {});
        }
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            State_->CloseRequests.fetch_add(1, std::memory_order_acq_rel);
            return {};
        }
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }
        auto IsOpen() const -> bool override
        {
            return !State_->ReadReleased.load(std::memory_order_acquire) &&
                !State_->Destroyed.load(std::memory_order_acquire);
        }

    private:
        struct ReadInput final
        {
            std::shared_ptr<PendingProviderCarrier> Owner;
            std::span<std::byte> Buffer;
        };
        struct WriteInput final
        {
            std::shared_ptr<PendingProviderCarrier> Owner;
            std::span<const std::byte> Buffer;
        };
        /** @brief 原协程体原位保留，新前门一次性映射正式结果。 */
        struct ReadWork final
        {
            template<class State>
            auto operator()(State Operation, ReadInput Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                const auto Result = co_await Net::co_spawn(Input.Owner->Executor(),
                    Input.Owner->ReadPartial(Input.Buffer), Net::deferred);
                co_return std::tuple{Result};
            }
        };
        struct WriteWork final
        {
            template<class State>
            auto operator()(State Operation, WriteInput Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                const auto Result = co_await Net::co_spawn(Input.Owner->Executor(),
                    Input.Owner->WritePartial(Input.Buffer), Net::deferred);
                co_return std::tuple{Result};
            }
        };
        [[nodiscard]] auto ReadPartial(std::span<std::byte>) -> Net::awaitable<Prism::IoResult>
        {
            (void)State_->Entered.try_send(boost::system::error_code{});
            boost::system::error_code WaitError;
            co_await State_->Release.async_receive(Net::redirect_error(Net::use_awaitable, WaitError));
            State_->ReadReleased.store(true, std::memory_order_release);
            co_return Prism::IoResult{0,
                Prism::Fault::FromNative(Prism::make_error_code(Prism::Error::NotOpen))};
        }
        [[nodiscard]] auto WritePartial(std::span<const std::byte>) -> Net::awaitable<Prism::IoResult>
        {
            co_return Prism::IoResult{0,
                Prism::Fault::FromNative(Prism::make_error_code(Prism::Error::NotOpen))};
        }
        Net::any_io_executor Executor_;
        std::shared_ptr<PendingProviderState> State_;
    };

    struct ProviderShutdownScenario final
    {
        using Runtime = Prism::Application::Application::RuntimeState;
        std::shared_ptr<Runtime> State;
        std::shared_ptr<PendingProviderState> CarrierState;
        std::shared_ptr<Signal> AcceptDone, ShutdownDone;
        std::weak_ptr<Prism::Socks5::Binding> WeakBinding;
        std::weak_ptr<const Prism::Foundation::GenerationLifetime> WeakGeneration;
        std::exception_ptr AcceptFailure, ShutdownFailure, Unexpected;
        std::expected<void, Prism::Fault::Failure> ShutdownOutcome{};
        bool AcceptEntered{false}, ShutdownTimedOut{false}, ShutdownFailed{false};
        bool ProviderSlotReset{false}, OwnerRetainedAfterTimeout{false};
        bool CloseRequestedWhileInflight{false}, AcceptCompleted{false};
    };

    auto RunProviderShutdownScenario(const std::shared_ptr<ProviderShutdownScenario>& Scenario)
        -> Net::awaitable<void>
    {
        const auto* Entry = Scenario->State->ProviderBindings->Find("pending");
        auto Factory = Entry->Stream();
        auto Binding = std::get<std::shared_ptr<Prism::Socks5::Binding>>(Entry->Owner);
        Scenario->WeakBinding = Binding;
        auto Carrier = std::make_shared<PendingProviderCarrier>(Scenario->State->Io.get_executor(),
            Scenario->CarrierState);
        auto AcceptOperation = Factory->Accept(MakeStreamAcceptInput(Carrier));
        Factory.reset();
        Binding.reset();
        Net::co_spawn(Scenario->State->Io, std::move(AcceptOperation),
            [Scenario](std::exception_ptr Failure, auto)
            {
                Scenario->AcceptFailure = std::move(Failure);
                Scenario->AcceptCompleted = true;
                (void)Scenario->AcceptDone->try_send(boost::system::error_code{});
            });
        boost::system::error_code Error;
        co_await Scenario->CarrierState->Entered.async_receive(
            Net::redirect_error(Net::use_awaitable, Error));
        Scenario->AcceptEntered = !Error;
        Scenario->State->ShutdownTimeout = std::chrono::milliseconds(5);
        auto ShutdownOperation = Prism::Application::Shutdown::ShutdownRuntime(Scenario->State);
        Net::co_spawn(Scenario->State->Io, std::move(ShutdownOperation),
            [Scenario](std::exception_ptr Failure,
                std::expected<void, Prism::Fault::Failure> Outcome)
            {
                Scenario->ShutdownFailure = std::move(Failure);
                Scenario->ShutdownOutcome = std::move(Outcome);
                (void)Scenario->ShutdownDone->try_send(boost::system::error_code{});
            });
        co_await Scenario->ShutdownDone->async_receive(Net::redirect_error(Net::use_awaitable, Error));
        Scenario->ShutdownTimedOut =
            Scenario->State->Phase.load() == Prism::Application::RuntimePhase::Failed;
        Scenario->ShutdownFailed = Scenario->State->ExitCode == 1;
        Scenario->ProviderSlotReset = !Scenario->State->ProviderBindings;
        Scenario->CloseRequestedWhileInflight = Scenario->CarrierState->CloseRequests.load() > 0 &&
            !Scenario->CarrierState->ReadReleased.load() && !Scenario->CarrierState->Destroyed.load();
        Scenario->OwnerRetainedAfterTimeout = !Scenario->WeakBinding.expired();
        if (!Scenario->OwnerRetainedAfterTimeout)
        {
            ADD_FAILURE() << "timed out provider owner was not retained";
        }
        (void)Scenario->CarrierState->Release.try_send(boost::system::error_code{});
        co_await Scenario->AcceptDone->async_receive(Net::redirect_error(Net::use_awaitable, Error));
    }

    struct Stats final
    {
        std::pmr::memory_resource* Memory{};
        std::thread::id Thread = std::this_thread::get_id();
        bool Destroyed{false}, WrongThread{false}, Open{true};
    };

    TEST(ProviderClosingOwner, ShutdownTimeoutKeepsOptionalProviderOwnerUntilLateDrain)
    {
        namespace P = Prism::Composition::Provider;
        auto Scenario = std::make_shared<ProviderShutdownScenario>();
        Scenario->State = std::make_shared<ProviderShutdownScenario::Runtime>(1, Prism::GenerationId{1},
            Prism::Network::Dns::Config{});
        /** @brief ShutdownRuntime 要求进程 worker executor 已启动。 */
        Scenario->State->StartWorkers(1);
        Scenario->CarrierState = std::make_shared<PendingProviderState>(Scenario->State->Io.get_executor());
        Scenario->AcceptDone = std::make_shared<Signal>(Scenario->State->Io.get_executor(), 1);
        Scenario->ShutdownDone = std::make_shared<Signal>(Scenario->State->Io.get_executor(), 1);
        auto Pin = Prism::Testing::ProviderPin();
        Scenario->WeakGeneration = Pin;
        auto Accounts = Prism::Testing::ProviderAccount(
            Prism::Account::Credential::Password("provider-password"));
        auto Auth = Accounts->Authenticator;
        P::Preparation Input{Pin, std::make_shared<Prism::Foundation::GenerationUseState>(),
            {{{"pending", "socks5", "socks5", {}, {}}, true, false,
                {Pin, Accounts->Credentials, Auth}}}, {}};
        auto Prepared =
            P::ProviderCatalog::Prepare(std::move(Input), {Scenario->State->Io.get_executor(), {}, {}, {}});
        ASSERT_TRUE(Prepared);
        auto Frozen = Prepared->Freeze();
        ASSERT_TRUE(Frozen);
        auto Bound = Frozen->Bind({});
        ASSERT_TRUE(Bound);
        Scenario->State->ProviderBindings = std::make_shared<P::BoundCatalog>(std::move(*Bound));
        Pin.reset();
        Accounts.reset();
        Auth.reset();
        Net::co_spawn(Scenario->State->Io, RunProviderShutdownScenario(Scenario),
            [Scenario](std::exception_ptr Failure) { Scenario->Unexpected = std::move(Failure); });
        Scenario->State->Io.run();
        EXPECT_FALSE(Scenario->Unexpected);
        EXPECT_TRUE(Scenario->AcceptEntered);
        EXPECT_TRUE(Scenario->ShutdownTimedOut);
        EXPECT_TRUE(Scenario->ShutdownFailed);
        EXPECT_FALSE(Scenario->ShutdownFailure);
        EXPECT_FALSE(Scenario->ShutdownOutcome);
        if (!Scenario->ShutdownOutcome)
        {
            EXPECT_EQ(Scenario->ShutdownOutcome.error().Code, Prism::Fault::Code::Timeout);
        }
        EXPECT_TRUE(Scenario->ProviderSlotReset);
        EXPECT_TRUE(Scenario->CloseRequestedWhileInflight);
        EXPECT_TRUE(Scenario->OwnerRetainedAfterTimeout);
        if (!Scenario->OwnerRetainedAfterTimeout)
        {
            Scenario->AcceptDone.reset();
            Scenario->ShutdownDone.reset();
            Scenario->CarrierState.reset();
            Scenario->State.reset();
            return;
        }
        EXPECT_FALSE(Scenario->AcceptFailure);
        EXPECT_TRUE(Scenario->AcceptCompleted);
        EXPECT_TRUE(Scenario->CarrierState->ReadReleased.load());
        EXPECT_TRUE(Scenario->CarrierState->Destroyed.load());
        EXPECT_TRUE(Scenario->WeakBinding.expired());
        EXPECT_TRUE(Scenario->WeakGeneration.expired());
        Scenario->AcceptDone.reset();
        Scenario->ShutdownDone.reset();
        Scenario->CarrierState.reset();
        Scenario->State.reset();
    }

    class Carrier final : public Prism::Transmission
    {
    public:
        Carrier(Net::any_io_executor Executor, std::shared_ptr<Stats> State)
            : Prism::Transmission(Executor), Executor_(std::move(Executor)), State_(std::move(State)),
              Bytes_(State_->Memory)
        {
            Bytes_.resize(128);
        }
        ~Carrier() override
        {
            CheckThread();
            State_->Destroyed = true;
        }
        auto Executor() const -> ExecutorType override
        {
            return Executor_;
        }
        /** @brief 同步确定失败；不引入 co_composed，直接交付正式结果。 */
        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Executor_, std::move(Handler), {0, NotOpen()});
        }
        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Executor_, std::move(Handler), {0, NotOpen()});
        }
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto* Inner = NextLayer())
            {
                Inner->WriteShutdown(std::move(Handler));
                return;
            }
            Prism::Transmission::PostResult(Executor_, std::move(Handler), {});
        }
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            CheckThread();
            State_->Open = false;
            return {};
        }
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            CheckThread();
            return {};
        }
        auto IsOpen() const -> bool override
        {
            CheckThread();
            return State_->Open;
        }

    private:
        [[nodiscard]] static auto NotOpen() -> Prism::Fault::Failure
        {
            return Prism::Fault::FromNative(Prism::make_error_code(Prism::Error::NotOpen));
        }
        auto CheckThread() const -> void
        {
            State_->WrongThread |= std::this_thread::get_id() != State_->Thread;
        }
        Net::any_io_executor Executor_;
        std::shared_ptr<Stats> State_;
        std::pmr::vector<std::byte> Bytes_;
    };
    TEST(ProviderClosingOwner,
        ActualApplicationFinalizerPreservesStoppedWorkerDependenciesAndRejectsCompletion)
    {
        auto Storage = Prism::Executor::ClosingStorage::ProcessStorage();
        ASSERT_EQ(Storage->Pending(), 0);
        auto State = std::make_shared<Prism::Application::Application::RuntimeState>(1,
            Prism::GenerationId{1}, Prism::Network::Dns::Config{});
        Prism::Application::ObserveClosingFailures(State);
        State->Phase.store(Prism::Application::RuntimePhase::Ready);
        /** @brief Worker::Dispatch 只接受已发布的代次。 */
        const auto Root = std::filesystem::path{PRISM_TEST_REPO_ROOT};
        auto ConfigurationGeneration =
            Prism::Application::Startup::GenerationPhase::BuildGeneration(
                {Root / "Include/Prism/Application/Configuration/PrismConfiguration.json", {}});
        ASSERT_TRUE(ConfigurationGeneration);
        Prism::Application::RuntimeGenerationServices RuntimeServices;
        auto PublishedGeneration =
            std::make_shared<Prism::Application::RuntimeGenerationSnapshot>(
                *ConfigurationGeneration, Prism::Application::AccountCatalog{},
                std::move(RuntimeServices));
        auto Publication = State->GenerationPublisher->Prepare({}, PublishedGeneration, {});
        ASSERT_TRUE(Publication);
        ASSERT_TRUE(State->GenerationPublisher->Publish(*Publication));
        PublishedGeneration.reset();
        auto* Worker = State->Process->Workers().Find(Prism::WorkerId{1});
        ASSERT_NE(Worker, nullptr);
        bool CommandExecuted = false;
        ASSERT_EQ(Worker->Dispatch(Worker->Generation(),
                      [&CommandExecuted] { CommandExecuted = true; }),
            Prism::Runtime::WorkerDispatchResult::Accepted);
        std::weak_ptr<Prism::Executor::ContextOwner> WeakWorker =
                                                       Prism::Executor::ContextOwner::Find(Worker->Executor()),
                                                       WeakControl = State->ControlContext;
        std::weak_ptr<Prism::Application::Application::RuntimeState> WeakState = State;
        auto Status = std::make_shared<Stats>();
        Status->Memory = Worker->Resources().MemoryResource;
        auto Pin = Prism::Testing::ProviderPin();
        std::weak_ptr<const Prism::Foundation::GenerationLifetime> WeakPin = Pin;
        auto Scope = std::make_shared<Prism::Protocols::BindingLifetime>(State->Io.get_executor(), Pin);
        auto Inner = std::make_shared<Carrier>(Worker->Executor(), Status);
        auto Activity = Scope->Enter(Inner);
        ASSERT_TRUE(Activity);
        auto Handle = std::make_shared<Prism::Protocols::BoundTransmission>(Activity);
        Prism::Executor::ContextOwner::Find(Worker->Executor())->Io.stop();
        Pin.reset();
        Inner.reset();
        Activity.reset();
        std::thread Drop(
            [Value = std::move(Handle), Lifetime = std::move(Scope)]() mutable
            {
                Value.reset();
                Lifetime.reset();
            });
        Drop.join();
        EXPECT_TRUE(State->ProtocolDrainFailed.load());
        EXPECT_EQ(State->Phase.load(), Prism::Application::RuntimePhase::Failed);
        EXPECT_TRUE(Storage->IsSealed());
        EXPECT_EQ(Storage->Pending(), 1);
        EXPECT_FALSE(Status->Destroyed);
        State->Io.run();
        Prism::Application::Shutdown::FinalizeRuntimeResources(State);
        EXPECT_FALSE(State->ResourcesFinalized.load());
        EXPECT_EQ(State->ExitCode, 1);
        EXPECT_FALSE(State->Process);
        State.reset();
        EXPECT_FALSE(WeakWorker.expired());
        EXPECT_FALSE(WeakControl.expired());
        auto WorkerContext = WeakWorker.lock(), ControlContext = WeakControl.lock();
        WorkerContext->Io.restart();
        Storage->Retry();
        WorkerContext->Io.run();
        ControlContext->Io.restart();
        ControlContext->Io.run();
        EXPECT_TRUE(WeakState.expired());
        Storage->Collect();
        EXPECT_EQ(Storage->Pending(), 0);
        EXPECT_TRUE(Status->Destroyed);
        EXPECT_FALSE(Status->Open);
        EXPECT_FALSE(Status->WrongThread);
        EXPECT_TRUE(WeakPin.expired());
        EXPECT_FALSE(CommandExecuted);
        WorkerContext.reset();
        ControlContext.reset();
        EXPECT_TRUE(WeakWorker.expired());
        EXPECT_TRUE(WeakControl.expired());
    }
} // namespace
