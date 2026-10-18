/**
 * @file TransmissionLayerTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "CoreTransmissionTestSupport.hpp"
#include "TransportResources.hpp"
#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Transport/Detail/IoActivity.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/post.hpp>
#include <atomic>
#include <chrono>
#include <future>
#include <thread>

namespace
{
    struct NativeCloseRetryState final
    {
        std::thread::id ExecutorThread{std::this_thread::get_id()};
        std::weak_ptr<Prism::Transmission> WeakCarrier;
        std::weak_ptr<Prism::Contract::CarrierActivity> WeakActivity;
        Prism::Fault::Failure CloseFailure{Prism::Fault::FromNative(std::make_error_code(std::errc::io_error))};
        Prism::Fault::Failure CancelFailure{Prism::Fault::Code::Blocked};
        std::atomic<std::size_t> CloseCalls{0}, CancelCalls{0};
        std::size_t PendingAtFailure{0};
        std::atomic<bool> Open{true}, WrongThread{false}, RetryRequested{false}, RecoveryCompleted{false};
        std::atomic<bool> ObserveRetryCloseReturned{false};
        bool FailFirstClose{true}, FailFirstCancel{false}, FailRetryCancel{false};
        bool BlockActivityOnSecondCancel{false};
        std::atomic<bool> ActivityBlocked{false};
        std::promise<void> FirstCloseReturned, RetryCloseReturned;
        bool CarrierRetainedAtFailure{false}, ActivityRetainedAtFailure{false};
    };

    /** @brief 首次返回真实 native close 错误，重试在同一 executor 完成关闭。 */
    class NativeCloseRetryTransmission final : public Prism::Transmission
    {
    public:
        NativeCloseRetryTransmission(Net::any_io_executor Executor, std::shared_ptr<NativeCloseRetryState> State)
            : Prism::Transmission(Executor), Executor_(std::move(Executor)), State_(std::move(State)) {}
        auto Executor() const -> ExecutorType override { return Executor_; }
        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        { Prism::Transport::Detail::PostResult(Executor_, std::move(Handler), {0, {Prism::Fault::Code::Eof}}); }
        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        { Prism::Transport::Detail::PostResult(Executor_, std::move(Handler), {0, {Prism::Fault::Code::Canceled}}); }
        auto StartWriteShutdown(Completion Handler) -> void override
        { Prism::Transport::Detail::PostResult(Executor_, std::move(Handler), {0, {}}); }
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            if (State_->ExecutorThread != std::this_thread::get_id())
                State_->WrongThread.store(true, std::memory_order_release);
            const auto CloseCall = State_->CloseCalls.fetch_add(1, std::memory_order_acq_rel) + 1;
            if (CloseCall == 1)
            {
                if (State_->FailFirstClose)
                {
                    NotifyCloseReturned();
                    return std::unexpected(State_->CloseFailure);
                }
                State_->Open.store(false, std::memory_order_release);
                State_->RecoveryCompleted.store(true, std::memory_order_release);
                NotifyCloseReturned();
                return {};
            }
            State_->Open.store(false, std::memory_order_release);
            State_->RecoveryCompleted.store(true, std::memory_order_release);
            if (CloseCall == 2 && State_->ObserveRetryCloseReturned.load(std::memory_order_acquire))
                NotifyRetryCloseReturned();
            return {};
        }
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            if (State_->ExecutorThread != std::this_thread::get_id())
                State_->WrongThread.store(true, std::memory_order_release);
            const auto CancelCall = State_->CancelCalls.fetch_add(1, std::memory_order_acq_rel) + 1;
            if (State_->BlockActivityOnSecondCancel && CancelCall == 2)
            {
                if (auto Activity = std::dynamic_pointer_cast<Prism::Transport::Detail::IoActivity>(
                        State_->WeakActivity.lock()))
                {
                    Activity->Block(State_->CancelFailure);
                    State_->ActivityBlocked.store(true, std::memory_order_release);
                }
            }
            if (State_->FailFirstCancel && CancelCall == 1)
                return std::unexpected(State_->CancelFailure);
            if (State_->FailRetryCancel && CancelCall == 3)
                return std::unexpected(State_->CancelFailure);
            return {};
        }
        [[nodiscard]] auto IsOpen() const -> bool override { return State_->Open.load(std::memory_order_acquire); }
    private:
        /** @brief 在当前控制交付退栈后通知测试线程。 */
        auto NotifyCloseReturned() -> void
        {
            auto State = State_;
            Net::post(Executor_, [State] { State->FirstCloseReturned.set_value(); });
        }
        /** @brief 重试关闭处理器退栈后通知测试驱动。 */
        auto NotifyRetryCloseReturned() -> void
        {
            auto State = State_;
            Net::post(Executor_, [State] { State->RetryCloseReturned.set_value(); });
        }
        Net::any_io_executor Executor_;
        std::shared_ptr<NativeCloseRetryState> State_;
    };
}

TEST(CoreTransmission, ConceptSatisfied)
    {
        // 基类与 mock 均满足 TransmissionLike 概念
        static_assert(Prism::TransmissionLike<Prism::Transmission>);
        static_assert(Prism::TransmissionLike<LeafTransmission>);
        static_assert(Prism::TransmissionLike<MockTransmission>);
    }

TEST(CoreTransmission, TransportTypeLeaf)
    {
        // 叶子：NextLayer() 为空 → 默认返回 Tcp
        Net::io_context Loop;
        auto TransportOwner17 = std::make_shared<LeafTransmission>(Loop.get_executor());
        auto& TransportObject = *TransportOwner17;
        EXPECT_EQ(TransportObject.TransportType(), Prism::Transmission::Type::Tcp);
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner17));
    }

TEST(CoreTransmission, TransportTypeDelegate)
    {
        // 装饰器链：委托给底层传输获取真实类型
        Net::io_context Loop;
        auto TransportOwner16 = std::make_shared<UdpDecorator>(Loop.get_executor());
        auto& Leaf = *TransportOwner16;
        auto TransportOwner15 = std::make_shared<MockTransmission>(Loop.get_executor(), &Leaf);
        auto& Mid = *TransportOwner15;
        auto TransportOwner14 = std::make_shared<MockTransmission>(Loop.get_executor(), &Mid);
        auto& Top = *TransportOwner14;

        EXPECT_EQ(Leaf.TransportType(), Prism::Transmission::Type::Udp);
        EXPECT_EQ(Mid.TransportType(), Prism::Transmission::Type::Udp);
        EXPECT_EQ(Top.TransportType(), Prism::Transmission::Type::Udp);
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner14));
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner15));
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner16));
    }

TEST(CoreTransmission, GetExecutor)
    {
        Net::io_context Loop;
        auto TransportOwner13 = std::make_shared<LeafTransmission>(Loop.get_executor());
        auto& TransportObject = *TransportOwner13;
        // get_executor() 兼容 Asio Executor 概念，委托 Executor()
        EXPECT_EQ(TransportObject.get_executor(), Loop.get_executor());
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner13));
    }

TEST(CoreTransmission, NextLayerDefault)
    {
        // 基类默认实现：叶子节点返回 nullptr（const 与非 const 版本）
        Net::io_context Loop;
        auto TransportOwner12 = std::make_shared<LeafTransmission>(Loop.get_executor());
        auto& TransportObject = *TransportOwner12;
        EXPECT_EQ(TransportObject.NextLayer(), nullptr);
        const auto &ConstTransport = TransportObject;
        EXPECT_EQ(ConstTransport.NextLayer(), nullptr);
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner12));
    }

TEST(CoreTransmission, LowestLayerSuccess)
    {
        // 沿装饰器链导航到链底并转型成功
        Net::io_context Loop;
        auto ThirdEnd = std::make_unique<MockTransmission>(Loop.get_executor());
        auto RightEnd = std::make_unique<MockTransmission>(Loop.get_executor(), ThirdEnd.get());
        auto LeftEnd = std::make_unique<MockTransmission>(Loop.get_executor(), RightEnd.get());

        EXPECT_EQ(LeftEnd->lowest_layer<MockTransmission>(), ThirdEnd.get());
        EXPECT_EQ(LeftEnd->lowest_layer<Prism::Transmission>(), ThirdEnd.get());

        // const 版本
        const auto *ConstLeft = LeftEnd.get();
        EXPECT_EQ(ConstLeft->lowest_layer<MockTransmission>(), ThirdEnd.get());
        EXPECT_EQ(ConstLeft->lowest_layer<Prism::Transmission>(), ThirdEnd.get());
    }

TEST(CoreTransmission, LowestLayerTypeMiss)
    {
        // dynamic_cast 失败 → 返回 nullptr
        Net::io_context Loop;
        auto ThirdEnd = std::make_unique<MockTransmission>(Loop.get_executor());
        auto LeftEnd = std::make_unique<MockTransmission>(Loop.get_executor(), ThirdEnd.get());

        EXPECT_EQ(LeftEnd->lowest_layer<UdpDecorator>(), nullptr);
        const auto *ConstLeft = LeftEnd.get();
        EXPECT_EQ(ConstLeft->lowest_layer<UdpDecorator>(), nullptr);
    }

TEST(CoreTransmission, ReleaseDefault)
    {
        // 基类默认实现：返回空共享指针（经基类引用虚调用，确保入口计数）
        Net::io_context Loop;
        auto TransportOwner11 = std::make_shared<IntermediateTransmission>(Loop.get_executor());
        auto& TransportObject = *TransportOwner11;
        Prism::Transmission &ref = TransportObject;
        auto ReceivedCount = ref.Release();
        EXPECT_EQ(ReceivedCount, nullptr);
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner11));
    }

TEST(CoreTransmission, ReleaseOverride)
    {
        // 覆写路径：转移底层传输所有权
        Net::io_context Loop;
        auto Inner = std::make_shared<MockTransmission>(Loop.get_executor());
        auto TransportOwner10 = std::make_shared<MockTransmission>(Loop.get_executor());
        auto& TransportObject = *TransportOwner10;
        TransportObject.SetRelease(Inner);

        auto ReceivedCount = TransportObject.Release();
        EXPECT_EQ(ReceivedCount.get(), Inner.get());
        // 第二次调用：已转移，返回空
        auto Again = TransportObject.Release();
        EXPECT_EQ(Again, nullptr);
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner10));
    }

TEST(CoreTransmission, CloseCancel)
    {
        Net::io_context Loop;
        auto TransportOwner9 = std::make_shared<MockTransmission>(Loop.get_executor());
        auto& TransportObject = *TransportOwner9;
        const auto Closed = TransportObject.Close();
        Loop.run();
        EXPECT_TRUE(Closed.has_value());
        EXPECT_TRUE(TransportObject.Closed_);
        const auto Canceled = TransportObject.Cancel();
        EXPECT_TRUE(Canceled.has_value());
        const auto Drain = Prism::Testing::DriveDrain(Loop, TransportOwner9);
        EXPECT_TRUE(Drain.has_value());
    }

TEST(CoreTransmission, AsyncReadFull)
    {
        // 单轮读满
        Net::io_context Loop;
        auto TransportOwner8 = std::make_shared<MockTransmission>(Loop.get_executor());
        auto& TransportObject = *TransportOwner8;
        TransportObject.SetReadData({std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4},
                         std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}});
        std::byte IoBuffer[8]{};
        Prism::Fault::Failure OperationFailure;
        std::size_t Done = 0;

        Net::co_spawn(
            Loop.get_executor(),
            [&]() -> Net::awaitable<void>
            {
                Done = ([&](Prism::IoResult Result) { OperationFailure = Result.Failure; return Result.Bytes; })(co_await TransportObject.ReadExact(IoBuffer));
            },
            Net::detached);
        Loop.run();

        EXPECT_EQ(Done, 8);
        EXPECT_TRUE(OperationFailure.Succeeded());
        for (std::size_t Iteration = 0; Iteration < 8; ++Iteration)
        {
            EXPECT_EQ(IoBuffer[Iteration], static_cast<std::byte>(Iteration + 1));
        }
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner8));
    }

TEST(CoreTransmission, AsyncReadChunked)
    {
        // 分块读取：多次 async_read_some 直至读满
        Net::io_context Loop;
        auto TransportOwner7 = std::make_shared<MockTransmission>(Loop.get_executor());
        auto& TransportObject = *TransportOwner7;
        TransportObject.SetReadData({std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4},
                         std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}});
        TransportObject.SetReadMax(3);
        std::byte IoBuffer[8]{};
        Prism::Fault::Failure OperationFailure;
        std::size_t Done = 0;

        Net::co_spawn(
            Loop.get_executor(),
            [&]() -> Net::awaitable<void>
            {
                Done = ([&](Prism::IoResult Result) { OperationFailure = Result.Failure; return Result.Bytes; })(co_await TransportObject.ReadExact(IoBuffer));
            },
            Net::detached);
        Loop.run();

        EXPECT_EQ(Done, 8);
        EXPECT_TRUE(OperationFailure.Succeeded());
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner7));
    }

TEST(CoreTransmission, AsyncReadEof)
    {
        // 数据耗尽（EOF）：提前返回已读字节数
        Net::io_context Loop;
        auto TransportOwner6 = std::make_shared<MockTransmission>(Loop.get_executor());
        auto& TransportObject = *TransportOwner6;
        TransportObject.SetReadData({std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}});
        std::byte IoBuffer[8]{};
        Prism::Fault::Failure OperationFailure;
        std::size_t Done = 0;

        Net::co_spawn(
            Loop.get_executor(),
            [&]() -> Net::awaitable<void>
            {
                Done = ([&](Prism::IoResult Result) { OperationFailure = Result.Failure; return Result.Bytes; })(co_await TransportObject.ReadExact(IoBuffer));
            },
            Net::detached);
        Loop.run();

        EXPECT_EQ(Done, 4);
        EXPECT_EQ(OperationFailure.Code, Prism::Fault::Code::Eof);
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner6));
    }

TEST(CoreTransmission, AsyncReadError)
    {
        // 读取错误：立即返回，不循环
        Net::io_context Loop;
        auto TransportOwner5 = std::make_shared<MockTransmission>(Loop.get_executor());
        auto& TransportObject = *TransportOwner5;
        TransportObject.SetReadError(std::make_error_code(std::errc::io_error));
        std::byte IoBuffer[8]{};
        Prism::Fault::Failure OperationFailure;
        std::size_t Done = 0;

        Net::co_spawn(
            Loop.get_executor(),
            [&]() -> Net::awaitable<void>
            {
                Done = ([&](Prism::IoResult Result) { OperationFailure = Result.Failure; return Result.Bytes; })(co_await TransportObject.ReadExact(IoBuffer));
            },
            Net::detached);
        Loop.run();

        EXPECT_EQ(Done, 0);
        EXPECT_TRUE(OperationFailure.Failed());
        EXPECT_EQ(OperationFailure.Native, std::make_error_code(std::errc::io_error));
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner5));
    }

TEST(CoreTransmission, AsyncWriteFull)
    {
        // 单轮写满
        Net::io_context Loop;
        auto TransportOwner4 = std::make_shared<MockTransmission>(Loop.get_executor());
        auto& TransportObject = *TransportOwner4;
        const std::byte IoBuffer[8]{};
        Prism::Fault::Failure OperationFailure;
        std::size_t Done = 0;

        Net::co_spawn(
            Loop.get_executor(),
            [&]() -> Net::awaitable<void>
            {
                Done = ([&](Prism::IoResult Result) { OperationFailure = Result.Failure; return Result.Bytes; })(co_await TransportObject.WriteExact(IoBuffer));
            },
            Net::detached);
        Loop.run();

        EXPECT_EQ(Done, 8);
        EXPECT_EQ(TransportObject.Written_, 8);
        EXPECT_TRUE(OperationFailure.Succeeded());
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner4));
    }

TEST(CoreTransmission, AsyncWriteChunked)
    {
        // 分块写入：多次 async_write_some 直至写满
        Net::io_context Loop;
        auto TransportOwner3 = std::make_shared<MockTransmission>(Loop.get_executor());
        auto& TransportObject = *TransportOwner3;
        TransportObject.SetWriteMax(3);
        const std::byte IoBuffer[8]{};
        Prism::Fault::Failure OperationFailure;
        std::size_t Done = 0;

        Net::co_spawn(
            Loop.get_executor(),
            [&]() -> Net::awaitable<void>
            {
                Done = ([&](Prism::IoResult Result) { OperationFailure = Result.Failure; return Result.Bytes; })(co_await TransportObject.WriteExact(IoBuffer));
            },
            Net::detached);
        Loop.run();

        EXPECT_EQ(Done, 8);
        EXPECT_EQ(TransportObject.Written_, 8);
        EXPECT_TRUE(OperationFailure.Succeeded());
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner3));
    }

TEST(CoreTransmission, AsyncWriteError)
    {
        // 写入错误：立即返回
        Net::io_context Loop;
        auto TransportOwner2 = std::make_shared<MockTransmission>(Loop.get_executor());
        auto& TransportObject = *TransportOwner2;
        TransportObject.SetWriteError(std::make_error_code(std::errc::io_error));
        const std::byte IoBuffer[8]{};
        Prism::Fault::Failure OperationFailure;
        std::size_t Done = 0;

        Net::co_spawn(
            Loop.get_executor(),
            [&]() -> Net::awaitable<void>
            {
                Done = ([&](Prism::IoResult Result) { OperationFailure = Result.Failure; return Result.Bytes; })(co_await TransportObject.WriteExact(IoBuffer));
            },
            Net::detached);
        Loop.run();

        EXPECT_EQ(Done, 0);
        EXPECT_TRUE(OperationFailure.Failed());
        EXPECT_EQ(OperationFailure.Native, std::make_error_code(std::errc::io_error));
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner2));
    }

TEST(CoreTransmission, AsyncWriteBrokenPipe)
    {
        // 对端关闭：写返回 0 → 映射为 broken_pipe
        Net::io_context Loop;
        auto TransportOwner1 = std::make_shared<MockTransmission>(Loop.get_executor());
        auto& TransportObject = *TransportOwner1;
        TransportObject.SetWriteZero(true);
        const std::byte IoBuffer[8]{};
        Prism::Fault::Failure OperationFailure;
        std::size_t Done = 0;

        Net::co_spawn(
            Loop.get_executor(),
            [&]() -> Net::awaitable<void>
            {
                Done = ([&](Prism::IoResult Result) { OperationFailure = Result.Failure; return Result.Bytes; })(co_await TransportObject.WriteExact(IoBuffer));
            },
            Net::detached);
        Loop.run();

        EXPECT_EQ(Done, 0);
        EXPECT_TRUE(OperationFailure.Failed());
        EXPECT_EQ(OperationFailure.Code, Prism::Fault::Code::WouldBlock);
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner1));
    }

/** @brief 对正式关闭失败保留同一预约，显式重试后核验真实退栈与弱 owner 释放。 */
auto VerifyCloseFailureRetirement(Prism::Fault::Failure Failure) -> void
    {
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        const auto PendingBefore = Storage->Pending();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        auto State = std::make_shared<NativeCloseRetryState>();
        State->CloseFailure = Failure;
        auto Carrier = std::make_shared<NativeCloseRetryTransmission>(Context->Io.get_executor(), State);
        std::weak_ptr<Prism::Transmission> WeakCarrier = Carrier;
        std::weak_ptr<Prism::Contract::CarrierActivity> WeakActivity = Carrier->Activity();
        State->WeakCarrier = WeakCarrier;
        State->WeakActivity = WeakActivity;

        const auto CloseResult = Carrier->Close();
        ASSERT_TRUE(CloseResult);
        Net::io_context DrainIo;
        auto ExecutorWork = Net::make_work_guard(Context->Io);
        std::thread ExecutorThread([&]
        {
            State->ExecutorThread = std::this_thread::get_id();
            Context->Io.run();
        });
        const auto FirstDrain = Prism::Testing::DriveDrain(DrainIo, std::move(Carrier));
        ASSERT_FALSE(FirstDrain);
        const auto NativeFailure = Failure.Native;
        EXPECT_EQ(FirstDrain.error().Code, Failure.Code);
        EXPECT_EQ(FirstDrain.error().Native, NativeFailure);
        State->PendingAtFailure = Storage->Pending();
        State->CarrierRetainedAtFailure = !WeakCarrier.expired();
        State->ActivityRetainedAtFailure = !WeakActivity.expired();
        EXPECT_EQ(State->PendingAtFailure, PendingBefore + 2U);
        EXPECT_TRUE(State->CarrierRetainedAtFailure);
        EXPECT_TRUE(State->ActivityRetainedAtFailure);
        EXPECT_EQ(State->CloseCalls.load(std::memory_order_acquire), 1U);
        EXPECT_TRUE(State->Open.load(std::memory_order_acquire));
        EXPECT_FALSE(State->WrongThread.load(std::memory_order_acquire));
        EXPECT_FALSE(Context->Fatal->HasFailure());
        auto RetainedCarrier = WeakCarrier.lock();
        EXPECT_TRUE(RetainedCarrier);

        Storage->Retry();
        State->RetryRequested.store(true, std::memory_order_release);
        EXPECT_TRUE(State->RetryRequested.load(std::memory_order_acquire));
        ExecutorWork.reset();
        ExecutorThread.join();
        EXPECT_TRUE(State->RecoveryCompleted.load(std::memory_order_acquire));
        EXPECT_EQ(State->CloseCalls.load(std::memory_order_acquire), 2U);
        EXPECT_FALSE(State->Open.load(std::memory_order_acquire));
        EXPECT_EQ(Storage->Pending(), PendingBefore);
        ASSERT_TRUE(RetainedCarrier);
        const auto RecoveredDrain = Prism::Testing::DriveDrain(DrainIo, std::move(RetainedCarrier));
        ASSERT_TRUE(RecoveredDrain);
        Storage->Collect();
        EXPECT_EQ(FirstDrain.error().Native, NativeFailure);
        EXPECT_FALSE(State->Open.load(std::memory_order_acquire));
        EXPECT_FALSE(State->WrongThread.load(std::memory_order_acquire));
        EXPECT_FALSE(Context->Fatal->HasFailure());
        EXPECT_EQ(Storage->Pending(), PendingBefore);

        EXPECT_TRUE(WeakCarrier.expired());
        EXPECT_TRUE(WeakActivity.expired());

    }


TEST(CoreTransmission, NativeCloseFailureRetiresAfterConfirmedRetry)
{
    VerifyCloseFailureRetirement(Prism::Fault::FromNative(std::make_error_code(std::errc::io_error)));
}

TEST(CoreTransmission, TypedCloseFailureWithoutNativeRetiresAfterConfirmedRetry)
{
    VerifyCloseFailureRetirement({Prism::Fault::Code::Blocked});
}

TEST(CoreTransmission, TypedCancelFailureRemainsOwnedAfterCloseUntilRetry)
{
    auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
    const auto PendingBefore = Storage->Pending();
    auto Context = Prism::Executor::ContextOwner::Create(Storage);
    auto State = std::make_shared<NativeCloseRetryState>();
    State->FailFirstClose = false;
    State->FailFirstCancel = true;
    State->CancelFailure = {Prism::Fault::Code::Blocked};
    auto Carrier = std::make_shared<NativeCloseRetryTransmission>(Context->Io.get_executor(), State);
    std::weak_ptr<Prism::Transmission> WeakCarrier = Carrier;
    std::weak_ptr<Prism::Contract::CarrierActivity> WeakActivity = Carrier->Activity();
    State->WeakCarrier = WeakCarrier;
    State->WeakActivity = WeakActivity;
    auto CloseReturned = State->FirstCloseReturned.get_future();

    ASSERT_TRUE(Carrier->Cancel());
    ASSERT_TRUE(Carrier->Close());
    auto ExecutorWork = Net::make_work_guard(Context->Io);
    std::thread ExecutorThread([&]
    {
        State->ExecutorThread = std::this_thread::get_id();
        Context->Io.run();
    });
    const auto CloseStatus = CloseReturned.wait_for(std::chrono::seconds(1));
    if (CloseStatus != std::future_status::ready)
    {
        ExecutorWork.reset();
        ExecutorThread.join();
        FAIL() << "关闭处理器未在所属执行器返回";
        return;
    }

    Net::io_context DrainIo;
    const auto FirstDrain = Prism::Testing::DriveDrain(DrainIo, std::move(Carrier));
    if (FirstDrain)
    {
        ADD_FAILURE() << "取消失败回执仍待显式重试时 Drain 不得退休";
    }
    else
    {
        EXPECT_EQ(FirstDrain.error().Code, Prism::Fault::Code::Blocked);
        EXPECT_FALSE(FirstDrain.error().Native);
    }
    EXPECT_EQ(State->CancelCalls.load(std::memory_order_acquire), 1U);
    EXPECT_EQ(State->CloseCalls.load(std::memory_order_acquire), 1U);
    EXPECT_FALSE(State->Open.load(std::memory_order_acquire));
    EXPECT_FALSE(WeakCarrier.expired());
    EXPECT_FALSE(WeakActivity.expired());
    EXPECT_EQ(Storage->Pending(), PendingBefore + 2U);

    auto RetainedCarrier = WeakCarrier.lock();
    EXPECT_TRUE(RetainedCarrier);
    Storage->Retry();
    ExecutorWork.reset();
    ExecutorThread.join();
    EXPECT_EQ(State->CancelCalls.load(std::memory_order_acquire), 2U);
    EXPECT_EQ(State->CloseCalls.load(std::memory_order_acquire), 1U);
    EXPECT_FALSE(State->WrongThread.load(std::memory_order_acquire));
    EXPECT_FALSE(Context->Fatal->HasFailure());
    EXPECT_EQ(Storage->Pending(), PendingBefore);

    if (!RetainedCarrier) return;
    const auto RecoveredDrain = Prism::Testing::DriveDrain(DrainIo, std::move(RetainedCarrier));
    ASSERT_TRUE(RecoveredDrain);
    Storage->Collect();
    EXPECT_TRUE(WeakCarrier.expired());
    EXPECT_TRUE(WeakActivity.expired());
    EXPECT_EQ(Storage->Pending(), PendingBefore);
}

TEST(CoreTransmission, RejectedControlDeliveryRemainsOwnedBeforeExecutorRuns)
{
    auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
    const auto PendingBefore = Storage->Pending();
    auto Context = Prism::Executor::ContextOwner::Create(Storage);
    auto State = std::make_shared<NativeCloseRetryState>();
    auto Carrier = std::make_shared<NativeCloseRetryTransmission>(Context->Io.get_executor(), State);
    std::weak_ptr<Prism::Transmission> WeakCarrier = Carrier;
    std::weak_ptr<Prism::Contract::CarrierActivity> WeakActivity = Carrier->Activity();
    Context->Io.stop();

    const auto CloseResult = Carrier->Close();
    ASSERT_FALSE(CloseResult);
    EXPECT_EQ(CloseResult.error().Code, Prism::Fault::Code::Blocked);
    EXPECT_EQ(State->CloseCalls.load(std::memory_order_acquire), 0U);
    EXPECT_EQ(Storage->Pending(), PendingBefore + 2U);

    Net::io_context DrainIo;
    const auto Drain = Prism::Testing::DriveDrain(DrainIo, std::move(Carrier));
    ASSERT_FALSE(Drain);
    EXPECT_EQ(Drain.error().Code, Prism::Fault::Code::Blocked);
    EXPECT_EQ(State->CloseCalls.load(std::memory_order_acquire), 0U);
    EXPECT_FALSE(WeakCarrier.expired());
    EXPECT_FALSE(WeakActivity.expired());

    Context->Io.restart();
    Storage->Retry();
    EXPECT_EQ(State->CloseCalls.load(std::memory_order_acquire), 0U);
    EXPECT_EQ(Storage->Pending(), PendingBefore + 2U);
    EXPECT_FALSE(WeakCarrier.expired());
    EXPECT_FALSE(WeakActivity.expired());
    Context->Io.stop();
}

TEST(CoreTransmission, KnownCloseRetryKeepsEarlierReceiptAfterActivityFailure)
{
    auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
    const auto PendingBefore = Storage->Pending();
    auto Context = Prism::Executor::ContextOwner::Create(Storage);
    auto State = std::make_shared<NativeCloseRetryState>();
    State->CloseFailure = {Prism::Fault::Code::Blocked};
    State->FailFirstCancel = true;
    State->FailRetryCancel = true;
    State->BlockActivityOnSecondCancel = true;
    auto Carrier = std::make_shared<NativeCloseRetryTransmission>(Context->Io.get_executor(), State);
    std::weak_ptr<Prism::Transmission> WeakCarrier = Carrier;
    std::weak_ptr<Prism::Contract::CarrierActivity> WeakActivity = Carrier->Activity();
    State->WeakCarrier = WeakCarrier;
    State->WeakActivity = WeakActivity;
    auto FirstCloseReceipt = State->FirstCloseReturned.get_future();
    auto RetryCloseReceipt = State->RetryCloseReturned.get_future();

    ASSERT_TRUE(Carrier->Cancel());
    ASSERT_TRUE(Carrier->Cancel());
    ASSERT_TRUE(Carrier->Close());
    while (State->CancelCalls.load(std::memory_order_acquire) != 2U ||
           State->CloseCalls.load(std::memory_order_acquire) != 1U ||
           FirstCloseReceipt.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
    {
        if (Context->Io.run_one() == 0) break;
    }
    Context->Io.stop();
    EXPECT_EQ(FirstCloseReceipt.wait_for(std::chrono::milliseconds(0)), std::future_status::ready);

    EXPECT_EQ(State->CancelCalls.load(std::memory_order_acquire), 2U);
    EXPECT_EQ(State->CloseCalls.load(std::memory_order_acquire), 1U);
    EXPECT_TRUE(State->ActivityBlocked.load(std::memory_order_acquire));
    EXPECT_FALSE(WeakCarrier.expired());
    EXPECT_FALSE(WeakActivity.expired());

    Net::io_context DrainIo;
    auto FirstDrain = Prism::Testing::DriveDrain(DrainIo, std::move(Carrier));
    ASSERT_FALSE(FirstDrain);
    EXPECT_EQ(FirstDrain.error().Code, Prism::Fault::Code::Blocked);
    EXPECT_FALSE(FirstDrain.error().Native);

    Context->Io.restart();
    State->ObserveRetryCloseReturned.store(true, std::memory_order_release);
    Storage->Retry();
    while (State->CancelCalls.load(std::memory_order_acquire) != 3U ||
           State->CloseCalls.load(std::memory_order_acquire) != 2U ||
           RetryCloseReceipt.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
    {
        if (Context->Io.run_one() == 0) break;
    }
    Context->Io.stop();
    EXPECT_EQ(RetryCloseReceipt.wait_for(std::chrono::milliseconds(0)), std::future_status::ready);
    Storage->Collect();

    EXPECT_EQ(State->CancelCalls.load(std::memory_order_acquire), 3U);
    EXPECT_EQ(State->CloseCalls.load(std::memory_order_acquire), 2U);
    EXPECT_FALSE(State->Open.load(std::memory_order_acquire));
    EXPECT_FALSE(State->WrongThread.load(std::memory_order_acquire));
    EXPECT_FALSE(WeakCarrier.expired());
    EXPECT_FALSE(WeakActivity.expired());
    EXPECT_EQ(Storage->Pending(), PendingBefore + 2U);

    auto RetainedCarrier = WeakCarrier.lock();
    ASSERT_TRUE(RetainedCarrier);
    const auto RetainedDrain = Prism::Testing::DriveDrain(DrainIo, std::move(RetainedCarrier));
    ASSERT_FALSE(RetainedDrain);
    EXPECT_EQ(RetainedDrain.error().Code, Prism::Fault::Code::Blocked);
}

/** @brief 停止时未交付的关闭只在原执行域重启并真实执行后释放实物。 */
TEST(CoreTransmission, StoppedExecutorCloseRetiresOnlyAfterConfirmedDelivery)
{
    auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
    const auto PendingBefore = Storage->Pending();
    auto Context = Prism::Executor::ContextOwner::Create(Storage);
    auto State = std::make_shared<NativeCloseRetryState>();
    State->FailFirstClose = false;
    auto Carrier = std::make_shared<NativeCloseRetryTransmission>(Context->Io.get_executor(), State);
    std::weak_ptr<Prism::Transmission> WeakCarrier = Carrier;
    std::weak_ptr<Prism::Contract::CarrierActivity> WeakActivity = Carrier->Activity();
    Context->Io.stop();
    const auto Closed = Carrier->Close();
    ASSERT_FALSE(Closed);
    EXPECT_EQ(Closed.error().Code, Prism::Fault::Code::Blocked);
    EXPECT_FALSE(Closed.error().Native);
    EXPECT_EQ(State->CloseCalls.load(std::memory_order_acquire), 0U);
    EXPECT_EQ(Storage->Pending(), PendingBefore + 2U);
    Carrier.reset();
    EXPECT_FALSE(WeakCarrier.expired());
    EXPECT_FALSE(WeakActivity.expired());

    Context->Io.restart();
    Storage->Retry();
    EXPECT_EQ(State->CloseCalls.load(std::memory_order_acquire), 0U);
    EXPECT_EQ(Storage->Pending(), PendingBefore + 2U);
    Context->Io.run();
    Storage->Collect();
    EXPECT_EQ(State->CloseCalls.load(std::memory_order_acquire), 1U);
    EXPECT_FALSE(State->Open.load(std::memory_order_acquire));
    EXPECT_FALSE(State->WrongThread.load(std::memory_order_acquire));
    EXPECT_FALSE(Context->Fatal->HasFailure());
    EXPECT_EQ(Storage->Pending(), PendingBefore);
    EXPECT_TRUE(WeakCarrier.expired());
    EXPECT_TRUE(WeakActivity.expired());
}
