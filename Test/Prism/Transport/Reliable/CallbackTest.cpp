/**
 * @file CallbackTest.cpp
 * @brief Reliable completion-handler 传输测试。
 */

#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <exception>
#include <memory>
#include <thread>

#include <Prism/Transport/Reliable.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;

    enum class CallbackReadCase
    {
        Payload,
        Timeout,
        Cancel
    };

    using WorkGuard = Net::executor_work_guard<Net::io_context::executor_type>;

    struct CallbackReadState final
    {
        explicit CallbackReadState(const CallbackReadCase Value)
            : Scenario(Value),
              SocketWork(Net::make_work_guard(SocketIo)),
              HandlerWork(Net::make_work_guard(HandlerIo)),
              Acceptor(SocketIo, {Net::ip::make_address("127.0.0.1"), 0}),
              Client(SocketIo),
              CancelTimer(SocketIo),
              Watchdog(SocketIo, std::chrono::seconds{2})
        {
            Client.connect(Acceptor.local_endpoint());
            Transport = std::make_shared<Prism::Transport::Reliable>(Acceptor.accept());
            Acceptor.close();
            Transport->SetTimeout(Scenario == CallbackReadCase::Cancel
                                      ? std::chrono::milliseconds{1000}
                                      : std::chrono::milliseconds{30});
            if (Scenario == CallbackReadCase::Payload)
            {
                const std::array<std::byte, 3> Literal{
                    std::byte{0x70}, std::byte{0x00}, std::byte{0xff}};
                Net::write(Client, Net::buffer(Literal));
            }
        }

        CallbackReadCase Scenario;
        Net::io_context SocketIo;
        Net::io_context HandlerIo;
        WorkGuard SocketWork;
        WorkGuard HandlerWork;
        std::atomic<bool> ThreadStartupComplete{false};
        std::atomic<bool> CleanupPending{false};
        Net::ip::tcp::acceptor Acceptor;
        Net::ip::tcp::socket Client;
        std::shared_ptr<Prism::Transport::Reliable> Transport;
        std::array<std::byte, 8> Buffer{};
        Prism::Fault::Failure ReadFailure;
        std::size_t ReadBytes{0};
        std::atomic_size_t Calls{0};
        std::thread::id SocketThread;
        std::thread::id HandlerThread;
        std::thread::id CompletionThread;
        bool TimedOut{false};
        std::exception_ptr Failure;
        Net::cancellation_signal Cancellation;
        Net::steady_timer CancelTimer;
        Net::steady_timer Watchdog;
    };

    /**
     * @brief 由 SocketIo owner 串行关闭 callback 场景并释放两个 work guard。
     * @details HandlerWork 的唯一 reset owner 是 SocketIo。若线程启动尚未
     *          完成，只延迟 SocketWork 的释放，使部分线程创建失败仍可由
     *          SocketRunner 执行 rollback。
     */
    struct CallbackReadCleanup final
    {
        std::shared_ptr<CallbackReadState> State;

        auto operator()() const -> void
        {
            State->Watchdog.cancel();
            State->CancelTimer.cancel();
            State->Transport->Cancel();
            State->Transport->Close();
            State->Client.close();
            State->HandlerWork.reset();
            if (State->ThreadStartupComplete.load(std::memory_order_acquire))
            {
                State->SocketWork.reset();
            }
            else
            {
                State->CleanupPending.store(true, std::memory_order_release);
            }
        }
    };

    /**
     * @brief 在线程启动完成后收口已提前发生的 socket cleanup。
     */
    struct CallbackReadStartupFinalize final
    {
        std::shared_ptr<CallbackReadState> State;

        auto operator()() const -> void
        {
            if (State->CleanupPending.exchange(false, std::memory_order_acq_rel))
            {
                State->SocketWork.reset();
            }
        }
    };

    /**
     * @brief 完成 callback 读并把底层资源清理投递回 socket executor。
     */
    struct CallbackReadCompletion final
    {
        std::shared_ptr<CallbackReadState> State;

        auto operator()(Prism::IoResult Result) const -> void
        {
            const auto PreviousCalls = State->Calls.fetch_add(1, std::memory_order_acq_rel);
            if (PreviousCalls == 0)
            {
                State->ReadFailure = Result.Failure;
                State->ReadBytes = Result.Bytes;
                State->CompletionThread = std::this_thread::get_id();
            }
            Net::post(State->SocketIo, CallbackReadCleanup{State});
        }
    };

    /**
     * @brief watchdog 到期时记录失败并释放两个 executor 的 work guard。
     */
    struct CallbackReadWatchdog final
    {
        std::shared_ptr<CallbackReadState> State;

        auto operator()(boost::system::error_code Error) const -> void
        {
            if (Error)
            {
                return;
            }
            State->TimedOut = true;
            CallbackReadCleanup{State}();
        }
    };

    /**
     * @brief 按取消场景发出 Reliable cancellation signal。
     */
    struct CallbackReadCancel final
    {
        std::shared_ptr<CallbackReadState> State;

        auto operator()(boost::system::error_code Error) const -> void
        {
            if (!Error)
            {
                State->Cancellation.emit(Net::cancellation_type::all);
            }
        }
    };

    /**
     * @brief 保存启动 coroutine 的首个异常，不提前停止任何 executor。
     */
    struct CallbackReadStartCompletion final
    {
        std::shared_ptr<CallbackReadState> State;

        auto operator()(std::exception_ptr Error) const -> void
        {
            if (Error && !State->Failure)
            {
                State->Failure = Error;
                CallbackReadCleanup{State}();
            }
        }
    };

    /**
     * @brief 启动 completion-handler 读和场景对应的取消计时器。
     */
    auto StartCallbackRead(const std::shared_ptr<CallbackReadState> &State)
        -> Net::awaitable<void>
    {
        State->Watchdog.async_wait(CallbackReadWatchdog{State});
        State->Transport->ReadSome(
            State->Buffer,
            Net::bind_cancellation_slot(
                State->Cancellation.slot(),
                Net::bind_executor(State->HandlerIo.get_executor(),
                                   CallbackReadCompletion{State})));
        if (State->Scenario == CallbackReadCase::Cancel)
        {
            State->CancelTimer.expires_after(std::chrono::milliseconds{10});
            State->CancelTimer.async_wait(CallbackReadCancel{State});
        }
        co_return;
    }

    /**
     * @brief 回滚部分创建的 callback runner，并等待 socket owner 收口资源。
     * @details 正常路径仍由 SocketIo 串行释放 HandlerWork；若投递 cleanup
     *          本身失败，则先停止并 join 两个已创建的 runner，再复用同一
     *          cleanup 入口，避免可连接线程析构触发 terminate。
     */
    auto RollbackCallbackReadThreads(
        const std::shared_ptr<CallbackReadState> &State,
        std::thread &SocketRunner,
        std::thread &HandlerRunner) -> void
    {
        State->ThreadStartupComplete.store(true, std::memory_order_release);
        bool CleanupPosted = false;
        try
        {
            Net::post(State->SocketIo, CallbackReadCleanup{State});
            CleanupPosted = true;
        }
        catch (...)
        {
            State->SocketIo.stop();
            if (HandlerRunner.joinable())
            {
                State->HandlerIo.stop();
            }
        }

        if (SocketRunner.joinable())
        {
            SocketRunner.join();
        }
        if (HandlerRunner.joinable())
        {
            HandlerRunner.join();
        }
        if (!CleanupPosted)
        {
            CallbackReadCleanup{State}();
        }
    }

    /**
     * @brief 驱动 callback read 场景并核对 executor、取消、超时和 payload 合同。
     */
    auto CheckCallbackReadExecutor(const CallbackReadCase Scenario) -> void
    {
        const auto State = std::make_shared<CallbackReadState>(Scenario);
        Net::co_spawn(State->SocketIo, StartCallbackRead(State),
                      CallbackReadStartCompletion{State});
        std::thread SocketRunner([State]
        {
            State->SocketThread = std::this_thread::get_id();
            State->SocketIo.run();
        });
        std::thread HandlerRunner;
        try
        {
            HandlerRunner = std::thread([State]
            {
                State->HandlerThread = std::this_thread::get_id();
                State->HandlerIo.run();
            });
        }
        catch (const std::exception &Error)
        {
            RollbackCallbackReadThreads(State, SocketRunner, HandlerRunner);
            FAIL() << "HandlerRunner creation failed: " << Error.what();
        }

        State->ThreadStartupComplete.store(true, std::memory_order_release);
        try
        {
            Net::post(State->SocketIo, CallbackReadStartupFinalize{State});
        }
        catch (const std::exception &Error)
        {
            RollbackCallbackReadThreads(State, SocketRunner, HandlerRunner);
            FAIL() << "callback thread startup finalization failed: " << Error.what();
        }
        SocketRunner.join();
        HandlerRunner.join();

        ASSERT_FALSE(State->Failure);
        ASSERT_FALSE(State->TimedOut);
        ASSERT_EQ(State->Calls.load(), 1U);
        EXPECT_EQ(State->CompletionThread, State->HandlerThread);
        EXPECT_NE(State->CompletionThread, State->SocketThread);
        if (Scenario == CallbackReadCase::Payload)
        {
            EXPECT_TRUE(State->ReadFailure.Succeeded());
            ASSERT_EQ(State->ReadBytes, 3U);
            EXPECT_EQ(State->Buffer[0], std::byte{0x70});
            EXPECT_EQ(State->Buffer[1], std::byte{0x00});
            EXPECT_EQ(State->Buffer[2], std::byte{0xff});
        }
        else
        {
            EXPECT_EQ(State->ReadBytes, 0U);
            EXPECT_EQ(State->ReadFailure.Code,
                      Scenario == CallbackReadCase::Cancel
                          ? Prism::Fault::Code::Canceled
                          : Prism::Fault::Code::Timeout);
        }
    }
} // namespace

TEST(Reliable, CallbackReadPreservesAssociatedExecutorAndLiteralPayload)
{
    CheckCallbackReadExecutor(CallbackReadCase::Payload);
}

TEST(Reliable, CallbackTimeoutPreservesAssociatedExecutor)
{
    CheckCallbackReadExecutor(CallbackReadCase::Timeout);
}

TEST(Reliable, CallbackCancellationReachesSocketBeforeDeadline)
{
    CheckCallbackReadExecutor(CallbackReadCase::Cancel);
}
