/** @file ProviderClosingOwnerTest.cpp @brief 实际 Application owner 释放后 L1 保存真实 worker context/PMR，失败不标完成。 */
#include <Preview/Application/ClosingFailure.hpp>
#include <Preview/Application/Shutdown.hpp>
#include <Preview/Composition/Provider/ProviderCatalog.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>
#include <Preview/Protocols/Common/BindingLifetime.hpp>
#include <Preview/Transport/Detail/IoCompletion.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Runtime/WorkerDispatchResult.hpp>

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
#include <TestSupport/Preview/ProviderBindings.hpp>
#include <thread>
namespace
{
    namespace Net = boost::asio;
    using Signal = Net::experimental::channel<void(boost::system::error_code)>;
    /** @brief 构造携带显式有界字节池的 provider 接入输入。 */
    [[nodiscard]] auto MakeStreamAcceptInput(Preview::SharedTransmission Inbound)
        -> Preview::Contract::StreamAcceptInput
    {
        return {std::move(Inbound),{},
            std::make_shared<Preview::Memory::BytePool>(Preview::Memory::BytePoolOptions{.BlockCount=8})};
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

    class PendingProviderCarrier final : public Preview::Transmission
    {
    public:
        PendingProviderCarrier(Net::any_io_executor Executor, std::shared_ptr<PendingProviderState> State)
            : Preview::Transmission(Executor), Executor_(std::move(Executor)), State_(std::move(State))
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
            Net::async_initiate<Completion, void(Preview::IoResult)>(
                Net::co_composed<void(Preview::IoResult)>(ReadWork{}, Executor_), Handler,
                ReadInput{std::static_pointer_cast<PendingProviderCarrier>(Preview::Transmission::shared_from_this()),
                    Buffer});
        }
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Net::async_initiate<Completion, void(Preview::IoResult)>(
                Net::co_composed<void(Preview::IoResult)>(WriteWork{}, Executor_), Handler,
                WriteInput{std::static_pointer_cast<PendingProviderCarrier>(Preview::Transmission::shared_from_this()),
                    Buffer});
        }
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto* Inner = NextLayer())
            {
                Inner->WriteShutdown(std::move(Handler));
                return;
            }
            Preview::Transport::Detail::PostResult(Executor_, std::move(Handler), {});
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
                Preview::Transport::Detail::ConfigureIo(Operation);
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
                Preview::Transport::Detail::ConfigureIo(Operation);
                const auto Result = co_await Net::co_spawn(Input.Owner->Executor(),
                    Input.Owner->WritePartial(Input.Buffer), Net::deferred);
                co_return std::tuple{Result};
            }
        };
        [[nodiscard]] auto ReadPartial(std::span<std::byte>) -> Net::awaitable<Preview::IoResult>
        {
            (void)State_->Entered.try_send(boost::system::error_code{});
            boost::system::error_code WaitError;
            co_await State_->Release.async_receive(Net::redirect_error(Net::use_awaitable, WaitError));
            State_->ReadReleased.store(true, std::memory_order_release);
            co_return Preview::IoResult{0,
                Preview::Fault::FromNative(Preview::make_error_code(Preview::Error::NotOpen))};
        }
        [[nodiscard]] auto WritePartial(std::span<const std::byte>) -> Net::awaitable<Preview::IoResult>
        {
            co_return Preview::IoResult{0,
                Preview::Fault::FromNative(Preview::make_error_code(Preview::Error::NotOpen))};
        }
        Net::any_io_executor Executor_;
        std::shared_ptr<PendingProviderState> State_;
    };

    struct ProviderShutdownScenario final
    {
        using Runtime = Preview::Application::Application::RuntimeState;
        std::shared_ptr<Runtime> State;
        std::shared_ptr<PendingProviderState> CarrierState;
        std::shared_ptr<Signal> AcceptDone, ShutdownDone;
        std::weak_ptr<Preview::Socks5::Binding> WeakBinding;
        std::weak_ptr<const Preview::Foundation::GenerationLifetime> WeakGeneration;
        std::exception_ptr AcceptFailure, ShutdownFailure, Unexpected;
        std::expected<void, Preview::Fault::Failure> ShutdownOutcome{};
        bool AcceptEntered{false}, ShutdownTimedOut{false}, ShutdownFailed{false};
        bool ProviderSlotReset{false}, OwnerRetainedAfterTimeout{false};
        bool CloseRequestedWhileInflight{false}, AcceptCompleted{false};
    };

    auto RunProviderShutdownScenario(const std::shared_ptr<ProviderShutdownScenario>& Scenario)
        -> Net::awaitable<void>
    {
        const auto* Entry = Scenario->State->ProviderBindings->Find("pending");
        auto Factory = Entry->Stream();
        auto Binding = std::get<std::shared_ptr<Preview::Socks5::Binding>>(Entry->Owner);
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
        auto ShutdownOperation = Preview::Application::Shutdown::ShutdownRuntime(Scenario->State);
        Net::co_spawn(Scenario->State->Io, std::move(ShutdownOperation),
            [Scenario](std::exception_ptr Failure,
                std::expected<void, Preview::Fault::Failure> Outcome)
            {
                Scenario->ShutdownFailure = std::move(Failure);
                Scenario->ShutdownOutcome = std::move(Outcome);
                (void)Scenario->ShutdownDone->try_send(boost::system::error_code{});
            });
        co_await Scenario->ShutdownDone->async_receive(Net::redirect_error(Net::use_awaitable, Error));
        Scenario->ShutdownTimedOut =
            Scenario->State->Phase.load() == Preview::Application::RuntimePhase::Failed;
        Scenario->ShutdownFailed = Scenario->State->ExitCode == 1;
        Scenario->ProviderSlotReset = !Scenario->State->ProviderBindings.has_value();
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
        namespace P = Preview::Composition::Provider;
        auto Scenario = std::make_shared<ProviderShutdownScenario>();
        Scenario->State = std::make_shared<ProviderShutdownScenario::Runtime>(1, Preview::GenerationId{1},
            Preview::Network::Dns::Config{});
        Scenario->CarrierState = std::make_shared<PendingProviderState>(Scenario->State->Io.get_executor());
        Scenario->AcceptDone = std::make_shared<Signal>(Scenario->State->Io.get_executor(), 1);
        Scenario->ShutdownDone = std::make_shared<Signal>(Scenario->State->Io.get_executor(), 1);
        auto Pin = Preview::Testing::ProviderPin();
        Scenario->WeakGeneration = Pin;
        auto Accounts = Preview::Testing::ProviderAccount(
            Preview::Account::Credential::Password("provider-password"));
        auto Auth = Accounts->Authenticator;
        P::Preparation Input{Pin,
            {{{"pending", "socks5", "socks5", {}, {}}, true, false,
                {Pin, Accounts->Credentials, Auth}}}};
        auto Prepared =
            P::ProviderCatalog::Prepare(std::move(Input), {Scenario->State->Io.get_executor(), {}, {}, {}});
        ASSERT_TRUE(Prepared);
        auto Frozen = Prepared->Freeze();
        ASSERT_TRUE(Frozen);
        auto Bound = Frozen->Bind({});
        ASSERT_TRUE(Bound);
        Scenario->State->ProviderBindings.emplace(std::move(*Bound));
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
            EXPECT_EQ(Scenario->ShutdownOutcome.error().Code, Preview::Fault::Code::Timeout);
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

    class Carrier final : public Preview::Transmission
    {
    public:
        Carrier(Net::any_io_executor Executor, std::shared_ptr<Stats> State)
            : Preview::Transmission(Executor), Executor_(std::move(Executor)), State_(std::move(State)),
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
            Preview::Transport::Detail::PostResult(Executor_, std::move(Handler), {0, NotOpen()});
        }
        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            Preview::Transport::Detail::PostResult(Executor_, std::move(Handler), {0, NotOpen()});
        }
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto* Inner = NextLayer())
            {
                Inner->WriteShutdown(std::move(Handler));
                return;
            }
            Preview::Transport::Detail::PostResult(Executor_, std::move(Handler), {});
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
        [[nodiscard]] static auto NotOpen() -> Preview::Fault::Failure
        {
            return Preview::Fault::FromNative(Preview::make_error_code(Preview::Error::NotOpen));
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
        auto Storage = Preview::Executor::ClosingStorage::ProcessStorage();
        ASSERT_EQ(Storage->Pending(), 0);
        auto State = std::make_shared<Preview::Application::Application::RuntimeState>(1,
            Preview::GenerationId{1}, Preview::Network::Dns::Config{});
        Preview::Application::ObserveClosingFailures(State);
        State->Phase.store(Preview::Application::RuntimePhase::Ready);
        auto* Worker = State->Process->Workers().Find(Preview::WorkerId{1});
        ASSERT_NE(Worker, nullptr);
        bool CommandExecuted = false;
        ASSERT_EQ(Worker->Dispatch(Worker->Generation(),
                      [&CommandExecuted] { CommandExecuted = true; }),
            Preview::Runtime::WorkerDispatchResult::Accepted);
        std::weak_ptr<Preview::Executor::ContextOwner> WeakWorker = Worker->Resources().Execution,
                                                       WeakControl = State->ControlContext;
        std::weak_ptr<Preview::Application::Application::RuntimeState> WeakState = State;
        auto Status = std::make_shared<Stats>();
        Status->Memory = Worker->Resources().MemoryResource;
        auto Pin = Preview::Testing::ProviderPin();
        std::weak_ptr<const Preview::Foundation::GenerationLifetime> WeakPin = Pin;
        auto Scope = std::make_shared<Preview::Protocols::BindingLifetime>(State->Io.get_executor(), Pin);
        auto Inner = std::make_shared<Carrier>(Worker->Executor(), Status);
        auto Activity = Scope->Enter(Inner);
        ASSERT_TRUE(Activity);
        auto Handle = std::make_shared<Preview::Protocols::BoundTransmission>(Activity);
        Worker->Resources().IoContext.stop();
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
        EXPECT_EQ(State->Phase.load(), Preview::Application::RuntimePhase::Failed);
        EXPECT_TRUE(Storage->IsSealed());
        EXPECT_EQ(Storage->Pending(), 1);
        EXPECT_FALSE(Status->Destroyed);
        State->Io.run();
        Preview::Application::Shutdown::FinalizeRuntimeResources(State);
        EXPECT_FALSE(State->ResourcesFinalized.load());
        EXPECT_EQ(State->ExitCode, 1);
        EXPECT_FALSE(State->Process);
        State.reset();
        EXPECT_TRUE(WeakState.expired());
        EXPECT_FALSE(WeakWorker.expired());
        EXPECT_FALSE(WeakControl.expired());
        auto WorkerContext = WeakWorker.lock(), ControlContext = WeakControl.lock();
        WorkerContext->Io.restart();
        Storage->Retry();
        WorkerContext->Io.run();
        ControlContext->Io.restart();
        ControlContext->Io.run();
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
