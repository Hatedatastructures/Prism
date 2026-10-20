/** @file BindingRetentionTest.cpp @brief 真实挂起读期间协议绑定保留与完整退休回执。 */
#include <gtest/gtest.h>
#include <TestSupport/Prism/ProviderBindings.hpp>
#include <Prism/Protocols/Socks5/Binding.hpp>
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Executor/FatalState.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <array>
#include <atomic>
#include <chrono>
#include <expected>
#include <future>
#include <thread>
#include <semaphore>
#include <memory_resource>
#include <system_error>
#include <string_view>
namespace
{
    namespace Net=boost::asio;
    enum class DriverReceipt { LowerDrainFailed, LowerDrainSucceeded, CloseSucceeded, ReadHandlerReturned, CarrierDestroyed };
    using DriverReceiptChannel = Net::experimental::concurrent_channel<
        void(boost::system::error_code, DriverReceipt)>;
    using ReadSignal = Net::experimental::concurrent_channel<void(boost::system::error_code)>;
    struct PendingReadGate final
    {
        explicit PendingReadGate(Net::any_io_executor Executor)
            : Entered(Executor, 1), Released(std::move(Executor), 1) {}
        ReadSignal Entered, Released;
        std::binary_semaphore Started{0};
    };
    struct Stats final
    {
        std::thread::id ExecutorThread=std::this_thread::get_id();
        std::atomic<bool> Throws{false};
        bool ExecutorThrows{false},Destroyed{false},Open{true};
        std::atomic<bool> WrongThread{false};
        std::pmr::memory_resource* Memory{std::pmr::get_default_resource()};
        std::atomic<int> ClosedCalls{0};
        std::atomic<bool> RecoveryCompleted{false};
        std::atomic<int> LowerDrainCompleted{0};
        std::atomic<int> LowerDrainFailed{0};
        std::atomic<int> LowerDrainSucceeded{0};
        std::atomic<int> LowerDrainAtSuccessfulClose{0};
        std::shared_ptr<PendingReadGate> ReadGate;
        std::atomic<bool> ReadHandlerReturned{false}, ReadHandlerFailed{false};
        std::atomic<int> ReadBytes{0}, ReadFailureCode{0};
        std::shared_ptr<DriverReceiptChannel> Receipts;
        std::atomic<bool> ReceiptDropped{false};
        auto PublishReceipt(DriverReceipt Receipt) noexcept -> void
        {
            if (!Receipts) return;
            try
            {
                if (!Receipts->try_send(boost::system::error_code{}, Receipt))
                    ReceiptDropped.store(true, std::memory_order_release);
            }
            catch (...) { ReceiptDropped.store(true, std::memory_order_release); }
        }
    };
    /** @brief 在启动 source executor 前登记有限容量的真实阶段回执通道。 */
    auto AttachRecoveryReceipts(const std::shared_ptr<Stats>& State, Net::any_io_executor Executor) -> void
    { State->Receipts = std::make_shared<DriverReceiptChannel>(std::move(Executor), 64); }
    auto AttachReadGate(const std::shared_ptr<Stats>& State, Net::any_io_executor Executor) -> void
    { State->ReadGate = std::make_shared<PendingReadGate>(std::move(Executor)); }
    auto ReadBoundTransmission(
        std::shared_ptr<Prism::Protocols::BoundTransmission> Transmission,
        std::shared_ptr<Stats> State) -> Net::awaitable<void>
    {
        auto Buffer = std::make_shared<std::array<std::byte, 1>>();
        const auto Result = co_await Transmission->ReadSome(*Buffer);
        State->ReadBytes.store(static_cast<int>(Result.Bytes), std::memory_order_release);
        State->ReadFailureCode.store(static_cast<int>(Result.Failure.Code), std::memory_order_release);
    }
    auto ScheduleBoundRead(Net::any_io_executor Executor,
        std::shared_ptr<Prism::Protocols::BoundTransmission> Transmission,
        std::shared_ptr<Stats> State) -> void
    {
        Net::co_spawn(std::move(Executor), ReadBoundTransmission(std::move(Transmission), State),
            [State](std::exception_ptr Error)
        {
            State->ReadHandlerFailed.store(static_cast<bool>(Error), std::memory_order_release);
            State->ReadHandlerReturned.store(true, std::memory_order_release);
            State->PublishReceipt(DriverReceipt::ReadHandlerReturned);
        });
    }
    struct DriveReceipt final
    {
        bool Completed{false};
        std::exception_ptr Failure;
    };
    struct RetainedHandleScenario final
    {
        std::shared_ptr<Prism::Protocols::BindingLifetime> Lifetime;
        std::shared_ptr<Prism::Protocols::BoundTransmission> Transmission;
        std::shared_ptr<Stats> State;
        std::shared_ptr<Prism::Executor::ClosingStorage> Storage;
        std::weak_ptr<Prism::Protocols::BindingLifetime::Activity> WeakBindingActivity;
        std::weak_ptr<Prism::Contract::CarrierActivity> WeakCarrierActivity, WeakWrapperActivity;
        std::weak_ptr<Prism::Protocols::BoundTransmission> WeakTransmission;
        std::size_t PendingBefore{0}, PendingAfterBindingFailure{0}, PendingAfterWrapperFailure{0};
    };
    /** @brief 首轮只等待真实关闭回执；不代替测试提前触发下一轮 owner 退休。 */
    auto AwaitFirstCloseReceipt(std::shared_ptr<Stats> State) -> Net::awaitable<void>
    {
        while (co_await State->Receipts->async_receive(Net::use_awaitable) !=
               DriverReceipt::CloseSucceeded)
        {
        }
    }
    /** @brief 等待底层载体析构回执，驱动显式重试直到实物退栈。 */
    auto AwaitCarrierDestroyed(
        std::shared_ptr<Stats> State,
        std::shared_ptr<Prism::Executor::ClosingStorage> Storage,
        std::shared_ptr<Prism::Contract::CarrierActivity> WrapperActivity) -> Net::awaitable<void>
    {
        bool ReadReturned = false, LowerDrained = false, CarrierDestroyed = false;
        while (!ReadReturned || !LowerDrained || !CarrierDestroyed)
        {
            const auto Receipt = co_await State->Receipts->async_receive(Net::use_awaitable);
            if (Receipt == DriverReceipt::ReadHandlerReturned) ReadReturned = true;
            if (Receipt == DriverReceipt::LowerDrainSucceeded &&
                State->LowerDrainSucceeded.load(std::memory_order_acquire) >
                    State->LowerDrainAtSuccessfulClose.load(std::memory_order_acquire)) LowerDrained = true;
            if (Receipt == DriverReceipt::CarrierDestroyed) CarrierDestroyed = true;
            Storage->Collect();
            if (!CarrierDestroyed) Storage->Retry();
        }
        const auto WrapperDrain = co_await WrapperActivity->Drain();
        if (!WrapperDrain) throw std::runtime_error("wrapper activity failed after gated read completion");
        WrapperActivity.reset();
        Storage->Collect();
    }
    /** @brief 单次关闭恢复的 executor 与重试握手 owner。 */
    struct CarrierExecutorRecovery final
    {
        std::shared_ptr<Prism::Executor::ContextOwner> Context;
        std::shared_ptr<Stats> State;
        std::shared_ptr<Prism::Executor::ClosingStorage> Storage;
        std::shared_ptr<Prism::Contract::CarrierActivity> WrapperActivity;
        std::size_t PendingBefore{0}, PendingAfterFirstRetry{0};
        bool DriveInitialOperation{false};
        std::atomic<bool> Stalled{false};
        std::exception_ptr DriverFailure;
        std::binary_semaphore Start{0}, RestartReady{0}, OperationComplete{0};
        std::binary_semaphore BeginRetirement{0}, FirstRetryComplete{0};
        std::binary_semaphore ContinueRetirement{0}, Retired{0};
        auto CompleteOperation(std::promise<DriveReceipt>& Completion,
                               std::exception_ptr Failure) -> void
        {
            Completion.set_value(DriveReceipt{true,std::move(Failure)});
            OperationComplete.release();
        }
        /** @brief 保存阶段异常并停止当前 source executor run。 */
        auto StopStage(std::exception_ptr Error) noexcept -> void
        {
            if (Error)
            {
                DriverFailure = std::move(Error);
                Stalled.store(true, std::memory_order_release);
            }
            Context->Io.stop();
        }
        /** @brief 每阶段由真实协程回执停下本 source executor，再显式重启下一阶段。 */
        auto Run() -> void
        {
            Start.acquire();
            Context->Io.run();
            if (!Context->Fatal->HasFailure() || !Context->Io.stopped()) return;
            Context->Io.restart();
            RestartReady.release();
            if (DriveInitialOperation) Context->Io.run();
            OperationComplete.acquire();
            BeginRetirement.acquire();
            Context->Io.restart();
            Storage->Retry();
            Net::co_spawn(Context->Io, AwaitFirstCloseReceipt(State),
                [this](std::exception_ptr Error) { StopStage(std::move(Error)); });
            Context->Io.run();
            Storage->Collect();
            PendingAfterFirstRetry = Storage->Pending();
            FirstRetryComplete.release();
            if (Stalled.load(std::memory_order_acquire))
            {
                Retired.release();
                return;
            }
            ContinueRetirement.acquire();
            Context->Io.restart();
            Storage->Retry();
            Net::co_spawn(Context->Io, AwaitCarrierDestroyed(State, Storage, std::move(WrapperActivity)),
                [this](std::exception_ptr Error) { StopStage(std::move(Error)); });
            Context->Io.run();
            Storage->Collect();
            Retired.release();
        }
    };
    class ObservedCarrierActivity final : public Prism::Contract::CarrierActivity
    {
    public:
        ObservedCarrierActivity(std::shared_ptr<Prism::Contract::CarrierActivity> Inner,
                                std::shared_ptr<Stats> State)
            : Inner_(std::move(Inner)), State_(std::move(State)) {}
        auto Seal() noexcept -> void override { Inner_->Seal(); }
        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        { return Inner_->IsRetired(); }
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        { return Inner_->Executor(); }
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            auto Result = co_await Inner_->Drain();
            State_->LowerDrainCompleted.fetch_add(1, std::memory_order_acq_rel);
            if (Result) State_->LowerDrainSucceeded.fetch_add(1, std::memory_order_acq_rel);
            else State_->LowerDrainFailed.fetch_add(1, std::memory_order_acq_rel);
            State_->PublishReceipt(Result ? DriverReceipt::LowerDrainSucceeded : DriverReceipt::LowerDrainFailed);
            co_return Result;
        }
    private:
        std::shared_ptr<Prism::Contract::CarrierActivity> Inner_;
        std::shared_ptr<Stats> State_;
    };
    class ClosingTransport final : public Prism::Transmission
    {
    public:
        ClosingTransport(Net::any_io_executor Executor,std::shared_ptr<Stats> Value)
            :Prism::Transmission(Executor),Executor_(std::move(Executor)),Stats_(std::move(Value)),Buffer_(Stats_->Memory)
        {
            Buffer_.resize(128);
            Activity_ = std::make_shared<ObservedCarrierActivity>(Prism::Transmission::Activity(), Stats_);
        }
        ~ClosingTransport() override
        {
            CheckThread();
            Stats_->Destroyed = true;
            Stats_->PublishReceipt(DriverReceipt::CarrierDestroyed);
        }
        auto Executor() const->ExecutorType override
        {if(Stats_->ExecutorThrows)throw std::runtime_error("executor unavailable");return Executor_;}
        auto StartRead(std::span<std::byte> Buffer,Completion Handler)->void override
        {
            auto Owner=std::static_pointer_cast<ClosingTransport>(Prism::Transmission::shared_from_this());
            Net::async_initiate<Completion,void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(ReadWork{},Executor_),Handler,
                ReadInput{std::move(Owner),Buffer});
        }
        auto StartWrite(std::span<const std::byte>,Completion Handler)->void override
        {Prism::Transmission::PostResult(Executor_,std::move(Handler),NotOpen());}
        auto StartWriteShutdown(Completion Handler)->void override
        {Prism::Transmission::PostResult(Executor_,std::move(Handler),{});}
        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        { return Activity_; }
        [[nodiscard]] auto OnCancel()->ControlResult override{CheckThread();return {};}
        [[nodiscard]] auto OnClose()->ControlResult override
        {
            CheckThread();
            ++Stats_->ClosedCalls;
            if(Stats_->Throws)throw std::runtime_error("actual close failure");
            Stats_->Open=false;
            if (Stats_->ClosedCalls.load(std::memory_order_acquire) > 1)
            {
                Stats_->LowerDrainAtSuccessfulClose.store(
                    Stats_->LowerDrainSucceeded.load(std::memory_order_acquire),
                    std::memory_order_release);
                Stats_->RecoveryCompleted.store(true,std::memory_order_release);
                Stats_->PublishReceipt(DriverReceipt::CloseSucceeded);
            }
            return {};
        }
        auto IsOpen() const->bool override{CheckThread();return Stats_->Open;}
    private:
        struct ReadInput final
        {
            std::shared_ptr<ClosingTransport> Owner;
            std::span<std::byte> Buffer;
        };
        struct ReadWork final
        {
            template<class Operation>
            auto operator()(Operation Work,ReadInput Input) const->void
            {
                Prism::Transmission::ConfigureIo(Work);
                const auto Result=co_await Net::co_spawn(Input.Owner->Executor(),
                    Input.Owner->ReadPending(Input.Buffer),Net::deferred);
                co_return std::tuple{Result};
            }
        };
        auto ReadPending(std::span<std::byte> Buffer)->Net::awaitable<Prism::IoResult>
        {
            const auto Gate=Stats_->ReadGate;
            if(!Gate || Buffer.empty())co_return NotOpen();
            Gate->Started.release();
            (void)Gate->Entered.try_send(boost::system::error_code{});
            co_await Gate->Released.async_receive(Net::use_awaitable);
            Buffer.front()=std::byte{0x5a};
            co_return Prism::IoResult{1,{}};
        }
        /** @brief 载体已失效的确定失败；保留协议私有 NotOpen 的原生 category/value。 */
        static auto NotOpen()->Prism::IoResult
        {return Prism::IoResult{0,Prism::Fault::FromNative(Prism::make_error_code(Prism::Error::NotOpen))};}
        auto CheckThread() const->void
        { if(std::this_thread::get_id()!=Stats_->ExecutorThread)Stats_->WrongThread.store(true,std::memory_order_release); }
        Net::any_io_executor Executor_;
        std::shared_ptr<Stats> Stats_;
        std::pmr::vector<std::byte> Buffer_;
        std::shared_ptr<ObservedCarrierActivity> Activity_;
    };
    /** @brief 精确验证首个关闭异常仍由 FatalState 保留。 */
    [[nodiscard]] auto HasFatalCloseCause(const std::shared_ptr<Prism::Executor::FatalState>& Fatal) -> bool
    {
        if (!Fatal || !Fatal->HasFailure()) return false;
        try
        {
            std::rethrow_exception(Fatal->Error());
        }
        catch (const std::runtime_error& Error)
        {
            return std::string_view(Error.what()) == "actual close failure";
        }
        catch (...)
        {
            return false;
        }
    }

    auto VerifyRetiredHandle(std::shared_ptr<RetainedHandleScenario> Scenario)->Net::awaitable<void>
    {
        const auto Original=co_await Net::this_coro::executor;
        ScheduleBoundRead(Original,Scenario->Transmission,Scenario->State);
        co_await Scenario->State->ReadGate->Entered.async_receive(Net::use_awaitable);
        Scenario->Lifetime->Close();bool Failed=false;
        const auto DrainResult=co_await Scenario->Lifetime->Drain();
        Failed=!DrainResult;
        if(!DrainResult)EXPECT_EQ(DrainResult.error().Code,Prism::Fault::Code::Blocked);
        Scenario->PendingAfterBindingFailure=Scenario->Storage->Pending();
        EXPECT_EQ(Scenario->PendingAfterBindingFailure,Scenario->PendingBefore+3U);
        EXPECT_TRUE(Scenario->WeakBindingActivity.lock());EXPECT_TRUE(Scenario->WeakCarrierActivity.lock());
        const auto Transmission=Scenario->Transmission;
        EXPECT_TRUE(Failed);EXPECT_EQ(&Net::query(Transmission->Executor(),Net::execution::context),&Net::query(Original,Net::execution::context));
        EXPECT_NE(Transmission->NextLayer(),nullptr);EXPECT_TRUE(Transmission->IsOpen());
        std::array<std::byte,1> Buffer{};std::error_code Error;
        const auto Read=co_await Transmission->ReadSome(Buffer);Error=Prism::Fault::ToNative(Read.Failure);
        EXPECT_EQ(Read.Bytes,0);EXPECT_EQ(Error,Prism::make_error_code(Prism::Error::NotOpen));
        EXPECT_EQ(Read.Failure.Native,Prism::make_error_code(Prism::Error::NotOpen));
        const auto Write=co_await Transmission->WriteSome(Buffer);Error=Prism::Fault::ToNative(Write.Failure);
        EXPECT_EQ(Write.Bytes,0);EXPECT_EQ(Error,Prism::make_error_code(Prism::Error::NotOpen));
        EXPECT_EQ(Write.Failure.Native,Prism::make_error_code(Prism::Error::NotOpen));
        (void)Transmission->Cancel();
        (void)co_await Transmission->WriteShutdown();
        Scenario->PendingAfterWrapperFailure=Scenario->Storage->Pending();
        EXPECT_EQ(Scenario->PendingAfterWrapperFailure,Scenario->PendingBefore+5U);
        EXPECT_TRUE(Scenario->WeakWrapperActivity.lock());
        Transmission->SetTimeout(std::chrono::milliseconds(1));
    }
    TEST(BindingLifetime, RetainedHandleUsesStableExecutorAndRejectsIoAfterRetirement)
    {
        auto Storage=std::make_shared<Prism::Executor::ClosingStorage>();
        const auto PendingBefore=Storage->Pending();
        auto Context=Prism::Executor::ContextOwner::Create(Storage);
        auto& Io=Context->Io;auto Fatal=Context->Fatal;
        auto State=std::make_shared<Stats>();State->Throws=true;
        AttachRecoveryReceipts(State, Io.get_executor());AttachReadGate(State, Io.get_executor());
        auto Pin=Prism::Testing::ProviderPin();std::weak_ptr<const Prism::Foundation::GenerationLifetime> Weak=Pin;
        auto Lifetime=std::make_shared<Prism::Protocols::BindingLifetime>(Io.get_executor(),Pin);
        auto Carrier=std::make_shared<ClosingTransport>(Io.get_executor(),State);
        std::weak_ptr<Prism::Transmission> WeakCarrier=Carrier;const auto CarrierIdentity=Carrier.get();
        auto Activity=Lifetime->Enter(Carrier);auto Transmission=std::make_shared<Prism::Protocols::BoundTransmission>(Activity);
        auto Scenario=std::make_shared<RetainedHandleScenario>();
        Scenario->Lifetime=Lifetime;Scenario->Transmission=Transmission;Scenario->State=State;Scenario->Storage=Storage;
        Scenario->PendingBefore=PendingBefore;Scenario->WeakBindingActivity=Activity;
        Scenario->WeakCarrierActivity=Carrier->Activity();Scenario->WeakWrapperActivity=Transmission->Activity();
        Scenario->WeakTransmission=Transmission;
        Pin.reset();Carrier.reset();Activity.reset();
        std::promise<DriveReceipt> Completion;
        auto CompletionResult=Completion.get_future();
        auto Recovery=std::make_shared<CarrierExecutorRecovery>();
        Recovery->Context = Context;
        Recovery->State = State;
        Recovery->Storage = Storage;
        Recovery->WrapperActivity=Transmission->Activity();
        Recovery->PendingBefore = PendingBefore;
        Recovery->DriveInitialOperation = true;
        // 场景拥有两个句柄；释放 setup 的局部副本，后续跨线程 drop 才能交付其最终引用。
        Lifetime.reset();
        Transmission.reset();
        std::thread ExecutorThread([&,Recovery]{
            Recovery->State->ExecutorThread=std::this_thread::get_id();
            Net::co_spawn(Io,VerifyRetiredHandle(Scenario),[&,Recovery](std::exception_ptr Error)
                {Recovery->CompleteOperation(Completion,std::move(Error));Io.stop();});
            Recovery->Start.release();Recovery->Run();
        });
        const auto OperationReceipt=CompletionResult.get();
        EXPECT_TRUE(OperationReceipt.Completed);
        if(OperationReceipt.Failure)
        {
            if(Fatal->HasFailure())
            {
                State->Throws=false;
                Recovery->RestartReady.acquire();
                Recovery->BeginRetirement.release();
                Recovery->FirstRetryComplete.acquire();
                if (!Recovery->Stalled.load(std::memory_order_acquire))
                    Recovery->ContinueRetirement.release();
                Recovery->Retired.acquire();
            }
            ExecutorThread.join();
            std::rethrow_exception(OperationReceipt.Failure);
        }
        EXPECT_FALSE(State->Destroyed);EXPECT_FALSE(Weak.expired());
        auto RetainedTransmission=std::move(Scenario->Transmission);
        auto RetainedLifetime=std::move(Scenario->Lifetime);
        std::thread Drop([Value=std::move(RetainedTransmission)]()mutable{Value.reset();});Drop.join();
        RetainedLifetime.reset();Storage->Collect();
        {
            const auto Retained=WeakCarrier.lock();
            EXPECT_TRUE(Retained);EXPECT_EQ(Retained.get(),CarrierIdentity);
        }
        EXPECT_EQ(Storage->Pending(),PendingBefore+5U);
        EXPECT_TRUE(Scenario->WeakBindingActivity.lock());EXPECT_TRUE(Scenario->WeakCarrierActivity.lock());
        EXPECT_TRUE(Scenario->WeakWrapperActivity.lock());EXPECT_TRUE(Scenario->WeakTransmission.lock());
        EXPECT_FALSE(State->Destroyed);EXPECT_FALSE(State->WrongThread.load());EXPECT_FALSE(Weak.expired());
        EXPECT_TRUE(Fatal->HasFailure());EXPECT_TRUE(HasFatalCloseCause(Fatal));

        State->Throws=false;
        Recovery->RestartReady.acquire();
        Recovery->BeginRetirement.release();
        Recovery->FirstRetryComplete.acquire();
        if (Recovery->Stalled.load(std::memory_order_acquire))
        {
            Recovery->Retired.acquire();
            ExecutorThread.join();
            EXPECT_FALSE(Recovery->Stalled.load(std::memory_order_acquire));
            return;
        }
        EXPECT_GT(Recovery->PendingAfterFirstRetry,PendingBefore);
        EXPECT_EQ(State->ClosedCalls.load(),2);
        EXPECT_FALSE(State->Open);
        EXPECT_FALSE(State->WrongThread.load());
        EXPECT_FALSE(State->Destroyed);EXPECT_FALSE(Weak.expired());
        EXPECT_TRUE(WeakCarrier.lock());EXPECT_TRUE(Scenario->WeakBindingActivity.lock());
        EXPECT_TRUE(Fatal->HasFailure());EXPECT_TRUE(HasFatalCloseCause(Fatal));
        EXPECT_FALSE(State->ReadHandlerReturned.load(std::memory_order_acquire));
        EXPECT_EQ(State->LowerDrainSucceeded.load(std::memory_order_acquire),
            State->LowerDrainAtSuccessfulClose.load(std::memory_order_acquire));
        EXPECT_TRUE(State->ReadGate->Released.try_send(boost::system::error_code{}));
        Recovery->ContinueRetirement.release();
        Recovery->Retired.acquire();
        EXPECT_FALSE(Recovery->Stalled.load(std::memory_order_acquire));
        ExecutorThread.join();
        EXPECT_FALSE(static_cast<bool>(Recovery->DriverFailure));
        EXPECT_FALSE(State->ReceiptDropped.load(std::memory_order_acquire));
        Storage->Collect();
        EXPECT_EQ(Storage->Pending(),PendingBefore);
        EXPECT_TRUE(State->Destroyed);
        EXPECT_TRUE(Weak.expired());
        EXPECT_TRUE(WeakCarrier.expired());
        EXPECT_TRUE(Scenario->WeakCarrierActivity.expired());
        EXPECT_TRUE(Scenario->WeakBindingActivity.expired());
        EXPECT_TRUE(Scenario->WeakWrapperActivity.expired());
        EXPECT_TRUE(Scenario->WeakTransmission.expired());
        EXPECT_TRUE(State->ReadHandlerReturned.load(std::memory_order_acquire));
        EXPECT_FALSE(State->ReadHandlerFailed.load(std::memory_order_acquire));
        EXPECT_EQ(State->ReadBytes.load(std::memory_order_acquire),1);
        EXPECT_EQ(State->ReadFailureCode.load(std::memory_order_acquire),0);
    }
}
