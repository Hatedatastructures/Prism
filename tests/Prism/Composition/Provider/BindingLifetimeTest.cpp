/** @file BindingLifetimeTest.cpp @brief 跨线程弃值与真实虚关闭失败的 executor/退栈/pin 合同。 */
#include <gtest/gtest.h>
#include <TestSupport/Prism/ProviderBindings.hpp>
#include <Prism/Protocols/Socks5/Prepared.hpp>
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Executor/FatalState.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>
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
    namespace Net = boost::asio;

    /** @brief 解析 SOCKS5 测试目标并保留非法 host/port 的 typed 拒绝。 */
    [[nodiscard]] auto ResolveSocksTestTarget(Prism::Network::Target Target)
        -> Net::awaitable<std::expected<Net::ip::udp::endpoint, Prism::Fault::Failure>>
    {
        const auto Address = Prism::Network::IpAddress(Target.Host);
        if (!Address || Target.Port == 0)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
        }
        co_return Net::ip::udp::endpoint{*Address, Target.Port};
    }
    enum class DriverReceipt { LowerDrainFailed, LowerDrainSucceeded, CloseSucceeded, CarrierDestroyed };
    using DriverReceiptChannel = Net::experimental::concurrent_channel<
        void(boost::system::error_code, DriverReceipt)>;
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
    struct DriveReceipt final
    {
        bool Completed{false};
        std::exception_ptr Failure;
    };
    struct RetainedHandleScenario final
    {
        std::shared_ptr<Prism::Protocols::BindingLifetime> Lifetime;
        std::shared_ptr<Prism::Protocols::BoundTransmission> Transmission;
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
        std::shared_ptr<Prism::Executor::ClosingStorage> Storage) -> Net::awaitable<void>
    {
        while (!State->Destroyed)
        {
            const auto Receipt = co_await State->Receipts->async_receive(Net::use_awaitable);
            Storage->Collect();
            if (Receipt != DriverReceipt::CarrierDestroyed) Storage->Retry();
        }
        Storage->Collect();
    }
    /** @brief 单次关闭恢复的 executor 与重试握手 owner。 */
    struct CarrierExecutorRecovery final
    {
        std::shared_ptr<Prism::Executor::ContextOwner> Context;
        std::shared_ptr<Stats> State;
        std::shared_ptr<Prism::Executor::ClosingStorage> Storage;
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
            Net::co_spawn(Context->Io, AwaitCarrierDestroyed(State, Storage),
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
        auto StartRead(std::span<std::byte>,Completion Handler)->void override
        {Prism::Transport::Detail::PostResult(Executor_,std::move(Handler),NotOpen());}
        auto StartWrite(std::span<const std::byte>,Completion Handler)->void override
        {Prism::Transport::Detail::PostResult(Executor_,std::move(Handler),NotOpen());}
        auto StartWriteShutdown(Completion Handler)->void override
        {Prism::Transport::Detail::PostResult(Executor_,std::move(Handler),{});}
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

    auto RunClose(bool Throws)->void
    {
        auto Storage=std::make_shared<Prism::Executor::ClosingStorage>();
        const auto PendingBefore=Storage->Pending();
        auto Context=Prism::Executor::ContextOwner::Create(Storage);
        auto& Io=Context->Io;auto Fatal=Context->Fatal;
        auto State=std::make_shared<Stats>();State->Throws=Throws;
        if (Throws) AttachRecoveryReceipts(State, Io.get_executor());
        auto Pin=Prism::Testing::ProviderPin();std::weak_ptr<const Prism::Foundation::GenerationLifetime> Weak=Pin;
        auto Lifetime=std::make_shared<Prism::Protocols::BindingLifetime>(Io.get_executor(),Pin);
        auto Carrier=std::make_shared<ClosingTransport>(Io.get_executor(),State);
        std::weak_ptr<Prism::Transmission> WeakCarrier=Carrier;const auto CarrierIdentity=Carrier.get();
        std::weak_ptr<Prism::Executor::ContextOwner> WeakContext=Context;
        auto Activity=Lifetime->Enter(Carrier);auto Transmission=std::make_shared<Prism::Protocols::BoundTransmission>(Activity);
        std::weak_ptr<Prism::Protocols::BindingLifetime::Activity> WeakBindingActivity=Activity;
        std::weak_ptr<Prism::Contract::CarrierActivity> WeakCarrierActivity=Carrier->Activity();
        Carrier.reset();Activity.reset();Pin.reset();
        std::thread Drop([Value=std::move(Transmission)]() mutable {Value.reset();});Drop.join();
        EXPECT_FALSE(State->Destroyed);EXPECT_EQ(State->ClosedCalls.load(),0);bool Failed=false;
        Prism::Fault::Failure DrainFailure;
        auto Recovery=std::make_shared<CarrierExecutorRecovery>();
        Recovery->Context = Context;
        Recovery->State = State;
        Recovery->Storage = Storage;
        Recovery->PendingBefore = PendingBefore;
        Recovery->DriveInitialOperation = true;
        Net::io_context DrainIo;
        DriveReceipt OperationReceipt;
        auto Operation=[&]()->Net::awaitable<void>
        {
            Lifetime->Close();
            Recovery->Start.release();
            const auto Result=co_await Lifetime->Drain();
            Failed=!Result;
            if(!Result)DrainFailure=Result.error();
        };
        std::thread ExecutorThread([&,Recovery]
        {
            Recovery->State->ExecutorThread=std::this_thread::get_id();
            Recovery->Run();
        });
        Net::co_spawn(DrainIo,Operation(),[&,Recovery](std::exception_ptr Error)
        {
            OperationReceipt.Failure=std::move(Error);OperationReceipt.Completed=true;
            Recovery->OperationComplete.release();
            if(Throws)Net::post(Context->Io,[SourceContext=Context]{SourceContext->Io.stop();});
        });
        DrainIo.run();
        EXPECT_TRUE(OperationReceipt.Completed);
        if(Throws)
        {
            Recovery->RestartReady.acquire();
            EXPECT_EQ(DrainFailure.Code,Prism::Fault::Code::Blocked);EXPECT_FALSE(DrainFailure.Native);
            EXPECT_FALSE(State->Destroyed);EXPECT_FALSE(Weak.expired());EXPECT_TRUE(State->Open);
            EXPECT_EQ(Storage->Pending(),PendingBefore+3U);EXPECT_TRUE(Fatal->HasFailure());
            {
                const auto RetainedCarrier=WeakCarrier.lock();
                EXPECT_TRUE(RetainedCarrier);EXPECT_EQ(RetainedCarrier.get(),CarrierIdentity);
            }
            EXPECT_TRUE(WeakCarrierActivity.lock());EXPECT_TRUE(WeakBindingActivity.lock());
            EXPECT_FALSE(WeakContext.expired());EXPECT_TRUE(HasFatalCloseCause(Fatal));
        }
        if(Throws)
        {
            State->Throws=false;
            Recovery->BeginRetirement.release();
            Recovery->FirstRetryComplete.acquire();
            if (Recovery->Stalled.load(std::memory_order_acquire))
            {
                Recovery->Retired.acquire();
                ExecutorThread.join();
                EXPECT_FALSE(Recovery->Stalled.load(std::memory_order_acquire));
                return;
            }
            EXPECT_GT(Recovery->PendingAfterFirstRetry, PendingBefore);
            EXPECT_TRUE(State->RecoveryCompleted.load(std::memory_order_acquire));
            EXPECT_FALSE(State->Destroyed);EXPECT_FALSE(Weak.expired());
            EXPECT_TRUE(WeakCarrier.lock());EXPECT_TRUE(WeakBindingActivity.lock());
            EXPECT_TRUE(Fatal->HasFailure());EXPECT_TRUE(HasFatalCloseCause(Fatal));
            Recovery->ContinueRetirement.release();
            Recovery->Retired.acquire();
        }
        ExecutorThread.join();
        EXPECT_FALSE(static_cast<bool>(Recovery->DriverFailure));
        EXPECT_FALSE(State->ReceiptDropped.load(std::memory_order_acquire));
        if(OperationReceipt.Failure)std::rethrow_exception(OperationReceipt.Failure);
        EXPECT_EQ(Failed,Throws);EXPECT_FALSE(State->WrongThread.load());
        if (Throws) EXPECT_TRUE(State->RecoveryCompleted.load(std::memory_order_acquire));
        int ExpectedCloseCalls = 1;
        if (Throws) ExpectedCloseCalls = 2;
        EXPECT_EQ(State->ClosedCalls.load(), ExpectedCloseCalls);
        if(Throws)
        {
            EXPECT_FALSE(State->Open);EXPECT_TRUE(Fatal->HasFailure());
            EXPECT_TRUE(HasFatalCloseCause(Fatal));

        }
        else
        {
            EXPECT_TRUE(State->Destroyed);EXPECT_TRUE(Weak.expired());EXPECT_FALSE(State->Open);
            EXPECT_EQ(Storage->Pending(),PendingBefore);EXPECT_TRUE(WeakCarrier.expired());
            EXPECT_TRUE(WeakCarrierActivity.expired());EXPECT_TRUE(WeakBindingActivity.expired());
        }
        Lifetime.reset();
        Storage->Collect();
        if (Throws)
        {
            EXPECT_EQ(Storage->Pending(),PendingBefore);
            EXPECT_TRUE(State->Destroyed);
            EXPECT_TRUE(WeakCarrier.expired());
            EXPECT_TRUE(WeakCarrierActivity.expired());
            EXPECT_TRUE(WeakBindingActivity.expired());
            EXPECT_TRUE(Weak.expired());
            EXPECT_FALSE(State->WrongThread.load());
        }
    }
    TEST(BindingLifetime, CrossThreadDropClosesOnCarrierExecutorAndDrainWaits){RunClose(false);}
    TEST(BindingLifetime, ThrowingCloseRetiresProtocolOwnerOnExecutorAndReportsFailure){RunClose(true);}
    TEST(BindingLifetime, SsExternalFactoryAcceptAndCloseDrainAcrossExecutorsKeepOnePreparedSnapshot)
    {
        for(int Round=0;Round<10;++Round)
        {
            Net::io_context InputIo,ControlIo;auto Guard=Net::make_work_guard(InputIo);
            auto Pin=Prism::Testing::ProviderPin();auto Accounts=Prism::Testing::ProviderAccount(
                Prism::Account::Credential::Psk(std::string(16,'q')));
            auto Prepared=Prism::Shadowsocks2022::Prepare({"race",Pin,{}},{ControlIo.get_executor(),
                {Pin,Accounts->Credentials,Accounts->Authenticator},{},{},{}});
            ASSERT_TRUE(Prepared);auto Bound=Prism::Shadowsocks2022::Bind(std::move(*Prepared),{});ASSERT_TRUE(Bound);
            auto Factory=*Bound;std::atomic<int> Completed{0};std::atomic<bool> Unexpected{false};
            auto Bytes=std::make_shared<Prism::Memory::BytePool>(
                Prism::Memory::BytePoolOptions{.BlockCount=128});
            for(int I=0;I<100;++I)
            {
                auto [ClientValue,ServerValue]=Prism::MakeMemoryPair(InputIo.get_executor());
                auto Client=std::make_shared<Prism::MemoryStream>(std::move(ClientValue));
                auto Server=std::make_shared<Prism::MemoryStream>(std::move(ServerValue));
                Net::co_spawn(InputIo,Factory->Accept({Server,{},Bytes}),[&Completed,&Unexpected,Client](std::exception_ptr Error,auto)
                {if(Error)Unexpected.store(true);Client->Close();++Completed;});
            }
            std::thread Worker([&]{InputIo.run();});Factory->Close();bool Drained=false;
            auto Drain=[&]()->Net::awaitable<void>{Drained=static_cast<bool>(co_await Factory->Drain());};
            Net::co_spawn(ControlIo,Drain(),[&](std::exception_ptr Error){if(Error)Unexpected.store(true);});ControlIo.run();
            Guard.reset();Worker.join();EXPECT_TRUE(Drained);EXPECT_FALSE(Unexpected.load());EXPECT_EQ(Completed.load(),100);
        }
    }
    TEST(BindingLifetime, DroppingBindingKeepsFailedCarrierUntilExecutorRetirement)
    {
        auto Storage=std::make_shared<Prism::Executor::ClosingStorage>();
        const auto PendingBefore=Storage->Pending();
        auto Context=Prism::Executor::ContextOwner::Create(Storage);
        auto& Io=Context->Io;auto Fatal=Context->Fatal;
        auto State=std::make_shared<Stats>();State->Throws=true;
        AttachRecoveryReceipts(State, Io.get_executor());
        auto Pin=Prism::Testing::ProviderPin();std::weak_ptr<const Prism::Foundation::GenerationLifetime> Weak=Pin;
        auto Lifetime=std::make_shared<Prism::Protocols::BindingLifetime>(Io.get_executor(),Pin);
        auto Carrier=std::make_shared<ClosingTransport>(Io.get_executor(),State);
        std::weak_ptr<Prism::Transmission> WeakCarrier=Carrier;const auto CarrierIdentity=Carrier.get();
        auto Activity=Lifetime->Enter(Carrier);
        std::weak_ptr<Prism::Protocols::BindingLifetime::Activity> WeakBindingActivity=Activity;
        std::weak_ptr<Prism::Contract::CarrierActivity> WeakCarrierActivity=Carrier->Activity();
        auto Transmission=std::make_shared<Prism::Protocols::BoundTransmission>(Activity);
        auto Recovery=std::make_shared<CarrierExecutorRecovery>();
        Recovery->Context=Context;Recovery->State=State;Recovery->Storage=Storage;
        Recovery->PendingBefore=PendingBefore;
        std::thread ExecutorThread([Recovery]
        {
            Recovery->State->ExecutorThread=std::this_thread::get_id();
            Recovery->Run();
        });
        Carrier.reset();Activity.reset();Pin.reset();Transmission.reset();
        EXPECT_FALSE(State->Destroyed);
        Recovery->Start.release();
        Recovery->RestartReady.acquire();
        std::thread Drop([Value=std::move(Lifetime)]() mutable {Value.reset();});Drop.join();
        Recovery->OperationComplete.release();
        const DriveReceipt RetentionReceipt{Storage->Pending() >= PendingBefore + 3U, {}};
        EXPECT_TRUE(RetentionReceipt.Completed);
        if(RetentionReceipt.Failure)std::rethrow_exception(RetentionReceipt.Failure);
        EXPECT_FALSE(State->Destroyed);
        EXPECT_FALSE(Weak.expired());
        EXPECT_FALSE(State->WrongThread.load());
        Storage->Collect();
        {
            const auto Retained=WeakCarrier.lock();
            EXPECT_TRUE(Retained);EXPECT_EQ(Retained.get(),CarrierIdentity);
        }
        EXPECT_EQ(Storage->Pending(),PendingBefore+3U);
        EXPECT_FALSE(State->Destroyed);EXPECT_FALSE(Weak.expired());EXPECT_FALSE(State->WrongThread.load());
        EXPECT_TRUE(WeakCarrierActivity.lock());EXPECT_TRUE(WeakBindingActivity.lock());
        EXPECT_TRUE(Fatal->HasFailure());EXPECT_TRUE(HasFatalCloseCause(Fatal));

        State->Throws=false;
        Recovery->BeginRetirement.release();
        Recovery->FirstRetryComplete.acquire();
        if (Recovery->Stalled.load(std::memory_order_acquire))
        {
            Recovery->Retired.acquire();
            ExecutorThread.join();
            EXPECT_FALSE(Recovery->Stalled.load(std::memory_order_acquire));
            return;
        }
        EXPECT_EQ(State->ClosedCalls.load(),2);
        EXPECT_FALSE(State->Open);
        EXPECT_FALSE(State->WrongThread.load());
        EXPECT_GT(Storage->Pending(),PendingBefore);
        EXPECT_EQ(Recovery->PendingAfterFirstRetry,Storage->Pending());
        EXPECT_FALSE(State->Destroyed);EXPECT_FALSE(Weak.expired());
        EXPECT_TRUE(WeakCarrier.lock());EXPECT_TRUE(WeakCarrierActivity.lock());
        EXPECT_TRUE(Fatal->HasFailure());EXPECT_TRUE(HasFatalCloseCause(Fatal));
        Recovery->ContinueRetirement.release();
        Recovery->Retired.acquire();
        EXPECT_FALSE(Recovery->Stalled.load(std::memory_order_acquire));
        ExecutorThread.join();
        EXPECT_FALSE(static_cast<bool>(Recovery->DriverFailure));
        EXPECT_FALSE(State->ReceiptDropped.load(std::memory_order_acquire));
        EXPECT_EQ(Storage->Pending(),PendingBefore);
        EXPECT_TRUE(State->Destroyed);
        EXPECT_TRUE(Weak.expired());
        EXPECT_TRUE(WeakCarrier.expired());
        EXPECT_TRUE(WeakCarrierActivity.expired());
        EXPECT_TRUE(WeakBindingActivity.expired());
    }
    auto VerifyRetiredHandle(std::shared_ptr<RetainedHandleScenario> Scenario)->Net::awaitable<void>
    {
        const auto Original=co_await Net::this_coro::executor;
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
    TEST(BindingLifetime, ConstructorFailureReturnsTheOriginalAdmissionReservation)
    {
        Net::io_context Io;auto Pin=Prism::Testing::ProviderPin();auto State=std::make_shared<Stats>();State->ExecutorThrows=true;
        auto Lifetime=std::make_shared<Prism::Protocols::BindingLifetime>(Io.get_executor(),Pin);
        auto Carrier=std::make_shared<ClosingTransport>(Io.get_executor(),State);
        EXPECT_THROW((void)Lifetime->Enter(Carrier),std::runtime_error);State->ExecutorThrows=false;
        bool Drained=false;auto Run=[&]()->Net::awaitable<void>{Drained=static_cast<bool>(co_await Lifetime->Drain());Carrier->Close();};
        Net::co_spawn(Io,Run(),[](std::exception_ptr Failure){EXPECT_FALSE(Failure);});Io.run();
        EXPECT_TRUE(Drained);EXPECT_FALSE(State->WrongThread.load());
    }
    TEST(BindingLifetime, StoppedCarrierContextAndPmrRemainOwnedUntilL1RetirementOnRestart)
    {
        auto Storage=std::make_shared<Prism::Executor::ClosingStorage>();
        auto Control=Prism::Executor::ContextOwner::Create(Storage),Worker=Prism::Executor::ContextOwner::Create(Storage);
        std::weak_ptr<Prism::Executor::ContextOwner> WeakControl=Control,WeakWorker=Worker;
        auto State=std::make_shared<Stats>();State->Memory=&Worker->Pool;
        auto Pin=Prism::Testing::ProviderPin();std::weak_ptr<const Prism::Foundation::GenerationLifetime> WeakPin=Pin;
        auto Lifetime=std::make_shared<Prism::Protocols::BindingLifetime>(Control->Io.get_executor(),Pin);
        auto Carrier=std::make_shared<ClosingTransport>(Worker->Io.get_executor(),State);
        auto Activity=Lifetime->Enter(Carrier);auto Transmission=std::make_shared<Prism::Protocols::BoundTransmission>(Activity);
        Worker->Io.stop();Pin.reset();Carrier.reset();Activity.reset();
        std::thread Drop([Handle=std::move(Transmission),Scope=std::move(Lifetime)]()mutable{Handle.reset();Scope.reset();});Drop.join();
        Worker.reset();Control.reset();EXPECT_FALSE(WeakControl.expired());EXPECT_FALSE(WeakWorker.expired());
        EXPECT_FALSE(WeakPin.expired());EXPECT_FALSE(State->Destroyed);EXPECT_EQ(Storage->Pending(),1);EXPECT_TRUE(Storage->IsSealed());
        Worker=WeakWorker.lock();Control=WeakControl.lock();Worker->Io.restart();Storage->Retry();Worker->Io.run();
        Control->Io.restart();Control->Io.run();Storage->Collect();EXPECT_EQ(Storage->Pending(),0);
        EXPECT_TRUE(State->Destroyed);EXPECT_FALSE(State->WrongThread.load());EXPECT_EQ(State->ClosedCalls.load(),1);EXPECT_TRUE(WeakPin.expired());
        Worker.reset();Control.reset();EXPECT_TRUE(WeakControl.expired());EXPECT_TRUE(WeakWorker.expired());
    }

    TEST(BindingLifetime, Socks5AdmissionViewsReleaseAuthOwnerAfterDrain)
    {
        Net::io_context Io;
        auto Pin=Prism::Testing::ProviderPin();
        std::weak_ptr<const Prism::Foundation::GenerationLifetime> WeakPin=Pin;
        auto Directory=Prism::Testing::ProviderAccount(
            Prism::Account::Credential::Password("binding-view-password"));
        std::weak_ptr<Prism::Account::AccountStore> WeakDirectory=Directory->Store;
        auto Auth=Directory->Authenticator;
        std::weak_ptr<Prism::Authenticator> WeakAuth=Auth;
        Prism::Contract::DatagramServices Datagrams;
        Datagrams.Resolve = ResolveSocksTestTarget;
        Prism::Socks5::ServerConfig Config;
        Config.EnableAuth=true;Config.EnableUdp=true;Config.Authenticator=Auth;
        auto Prepared=Prism::Socks5::Prepare({"binding-view",Pin,Config},
            {Io.get_executor(),{Pin,Directory->Credentials,Auth},Datagrams});
        ASSERT_TRUE(Prepared);
        auto Bound=Prism::Socks5::Bind(std::move(*Prepared),{});
        ASSERT_TRUE(Bound);
        auto Base=std::move(*Bound);
        auto Derived=Base->WithAdmission(Prism::Socks5::Binding::AdmissionPolicy{
            .Mux={},.UdpEnabled=false});
        ASSERT_TRUE(Derived);
        Config.Authenticator.reset();
        Auth.reset();Directory.reset();Pin.reset();
        EXPECT_FALSE(WeakAuth.expired());
        EXPECT_FALSE(WeakDirectory.expired());
        EXPECT_FALSE(WeakPin.expired());

        bool Drained=false;
        std::exception_ptr Failure;
        {
            auto Drain=[Base,Derived,&Drained]() mutable ->Net::awaitable<void>
            {
                Base->Close();Derived->Close();
                Drained=static_cast<bool>(co_await Base->Drain());
            };
            Net::co_spawn(Io,Drain(),[&Failure](std::exception_ptr Error){Failure=std::move(Error);});
            Io.run();
        }
        EXPECT_FALSE(Failure);EXPECT_TRUE(Drained);
        EXPECT_TRUE(WeakAuth.expired());
        EXPECT_TRUE(WeakDirectory.expired());
        EXPECT_TRUE(WeakPin.expired());
        Base.reset();Derived.reset();
        EXPECT_TRUE(WeakAuth.expired());
        EXPECT_TRUE(WeakDirectory.expired());
        EXPECT_TRUE(WeakPin.expired());
    }
}
