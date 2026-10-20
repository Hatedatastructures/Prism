/**
 * @file H2MuxStreamLifetimeTestSupport.hpp
 * @brief H2MuxStreamLifetimeTest.cpp 拆分后的模块共享测试夹具与构造辅助。
 */
#pragma once

/**
 * @file H2MuxStreamLifetimeTest.cpp
 * @brief sing-mux H2Mux 虚拟流生命周期契约测试
 * @details 生产崩溃证据：Prism 在 H2Mux 请求后以 0xC0000005 崩溃于
 *          `Prism::Mux::H2Mux::Http2Stream::Close()`。
 *          根因是 `co_spawn(State->Strand, CloseOnStrand(std::move(State), ...))`
 *          的实参求值顺序未指定：GCC 自右向左求值，先把 State 置空，
 *          再对空指针取 Strand。本文件锁定两条不变量：
 *          1) `Close()` 在任何状态下都不得崩溃，后续读按已封止的 I/O 准入返回 Canceled；
 *          2) 服务端关闭会话时必须唤醒已注册流的挂起读，以 EOF 收口。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/co_composed.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <expected>
#include <exception>
#include <functional>
#include <memory>
#include <system_error>
#include <vector>

#include <Prism/Protocols/Mux/H2Mux/Http2Server.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace
{

    namespace Net = boost::asio;
    using Prism::Mux::H2Mux::Http2State;
    using Prism::Mux::H2Mux::Http2Stream;

    /// 看门狗：仅解除挂死；正常收尾取消计时后不触发。
    struct Watchdog final
    {
        std::shared_ptr<Net::steady_timer> Timer;
        std::shared_ptr<bool> Timeouted{std::make_shared<bool>(false)};

        explicit Watchdog(Net::io_context &Io, std::chrono::milliseconds Budget)
            : Timer(std::make_shared<Net::steady_timer>(Io.get_executor()))
        {
            auto TimeoutedFlag = Timeouted;
            auto TimerValue = Timer;
            auto *IoPtr = &Io;
            Timer->expires_after(Budget);
            Timer->async_wait(
                [TimeoutedFlag, TimerValue, IoPtr](const boost::system::error_code &Error)
                {
                    if (Error == Net::error::operation_aborted)
                    {
                        return;
                    }
                    *TimeoutedFlag = true;
                    IoPtr->stop();
                });
        }

        auto Cancel() const -> void
        {
            Timer->cancel();
        }
    };

    /** @brief 关闭 H2 服务端并等待 Run 内部完成唯一根、子流及 carrier 排空。 */
    auto DrainHttp2Server(
        const std::shared_ptr<Prism::Mux::H2Mux::Http2Server> &Server)
        -> Net::awaitable<void>
    {
        Server->Close();
        const auto Drained = co_await Server->Drain();
        EXPECT_TRUE(Drained);
    }

    struct ServerRunObservation final
    {
        bool Completed{false};
        bool Succeeded{false};
        bool Threw{false};
        bool Retired{false};
        Prism::Fault::Failure Failure{};
        std::function<void()> OnCompleted;
    };

    struct ServerRunCompletion final
    {
        std::shared_ptr<ServerRunObservation> Observation;
        std::weak_ptr<Prism::Mux::H2Mux::Http2Server> Server;

        auto operator()(
            std::exception_ptr Exception,
            std::expected<void, Prism::Fault::Failure> Outcome) const -> void
        {
            if (const auto Value = Server.lock()) Observation->Retired = Value->IsRetired();
            Observation->Completed = true;
            Observation->Threw = static_cast<bool>(Exception);
            if (Exception) Observation->Failure = {Prism::Fault::Code::IoError};
            else if (!Outcome) Observation->Failure = Outcome.error();
            else Observation->Succeeded = true;
            if (Observation->OnCompleted) Observation->OnCompleted();
        }
    };

    auto StartServerRun(
        Net::any_io_executor Executor,
        std::shared_ptr<Prism::Mux::H2Mux::Http2Server> Server,
        std::shared_ptr<ServerRunObservation> Observation) -> void
    {
        const auto WeakServer = std::weak_ptr<Prism::Mux::H2Mux::Http2Server>(Server);
        Net::co_spawn(Executor, Server->Run(), ServerRunCompletion{Observation, WeakServer});
    }

    struct WriteProbe final
    {
        std::atomic<int> Active{0};
        std::atomic<int> Maximum{0};
    };

    class DelayedWriteTransmission final : public Prism::Transmission
    {
    public:
        DelayedWriteTransmission(Prism::SharedTransmission InnerValue,
                                 std::shared_ptr<WriteProbe> ProbeValue)
            : Prism::Transmission(InnerValue->Executor()),
              Inner_(std::move(InnerValue)), Probe_(std::move(ProbeValue))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        { return Inner_->Executor(); }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        { Inner_->ReadSome(Buffer, std::move(Handler)); }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<WriteWork>(
                WriteInput{std::static_pointer_cast<DelayedWriteTransmission>(
                               Prism::Transmission::shared_from_this()),
                           Buffer},
                std::move(Handler));
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        { Inner_->WriteShutdown(std::move(Handler)); }

        [[nodiscard]] auto OnClose() -> ControlResult override
        { return Inner_->Close(); }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        { return Inner_->Cancel(); }

        [[nodiscard]] auto IsOpen() const -> bool override { return Inner_->IsOpen(); }

    private:
        struct WriteInput final
        {
            std::shared_ptr<DelayedWriteTransmission> Owner;
            std::span<const std::byte> Buffer;
        };
        struct WriteWork final
        {
            template<class State>
            auto operator()(State Operation, WriteInput Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                const auto Result = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->WritePartial(Input.Buffer), Net::deferred);
                co_return std::tuple{Result};
            }
        };
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(Work{}, Executor()),
                Handler, std::move(Value));
        }
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            const auto Current = Probe_->Active.fetch_add(1, std::memory_order_acq_rel) + 1;
            auto Maximum = Probe_->Maximum.load(std::memory_order_acquire);
            while (Maximum < Current &&
                   !Probe_->Maximum.compare_exchange_weak(
                       Maximum, Current, std::memory_order_acq_rel, std::memory_order_acquire))
            {
            }
            Net::steady_timer Delay(Executor());
            Delay.expires_after(std::chrono::milliseconds(10));
            co_await Delay.async_wait(Net::use_awaitable);
            const auto Result = co_await Inner_->WriteSome(Buffer);
            Probe_->Active.fetch_sub(1, std::memory_order_acq_rel);
            co_return Result;
        }

        Prism::SharedTransmission Inner_;
        std::shared_ptr<WriteProbe> Probe_;
    };

    class ScriptedWriteTransmission final : public Prism::Transmission
    {
    public:
        explicit ScriptedWriteTransmission(Prism::SharedTransmission InnerValue)
            : Prism::Transmission(InnerValue->Executor()), Inner_(std::move(InnerValue))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override { return Inner_->Executor(); }
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        { Inner_->ReadSome(Buffer, std::move(Handler)); }
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<WriteWork>(
                WriteInput{std::static_pointer_cast<ScriptedWriteTransmission>(
                               Prism::Transmission::shared_from_this()),
                           Buffer},
                std::move(Handler));
        }
        auto StartWriteShutdown(Completion Handler) -> void override
        { Inner_->WriteShutdown(std::move(Handler)); }
        [[nodiscard]] auto OnClose() -> ControlResult override { return Inner_->Close(); }
        [[nodiscard]] auto OnCancel() -> ControlResult override { return Inner_->Cancel(); }
        [[nodiscard]] auto IsOpen() const -> bool override { return Inner_->IsOpen(); }
        [[nodiscard]] auto Writes() const noexcept -> std::size_t { return Writes_; }

    private:
        struct WriteInput final
        {
            std::shared_ptr<ScriptedWriteTransmission> Owner;
            std::span<const std::byte> Buffer;
        };
        struct WriteWork final
        {
            template<class State>
            auto operator()(State Operation, WriteInput Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                const auto Result = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->WritePartial(Input.Buffer), Net::deferred);
                co_return std::tuple{Result};
            }
        };
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(Work{}, Executor()),
                Handler, std::move(Value));
        }
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            ++Writes_;
            if (Writes_ <= 2U)
            {
                co_return co_await Inner_->WriteSome(Buffer);
            }
            const auto Count = (std::min)(Buffer.size(), std::size_t{1});
            const auto InnerResult = co_await Inner_->WriteSome(Buffer.first(Count));
            co_return Prism::IoResult{
                InnerResult.Bytes,
                Prism::Fault::FromNative(std::make_error_code(std::errc::io_error))};
        }

        Prism::SharedTransmission Inner_;
        std::size_t Writes_{0};
    };

    struct WriteFailureScenario final
    {
        explicit WriteFailureScenario(Net::io_context &Io)
            : ServerDone(Io.get_executor(), 1), ReadDone(Io.get_executor(), 1),
              Guard(Io, std::chrono::seconds(5))
        {
        }

        std::shared_ptr<Prism::Mux::H2Mux::Http2Server> Server;
        Prism::SharedTransmission Client;
        std::shared_ptr<Prism::Mux::H2Mux::Http2Stream> Stream;
        std::shared_ptr<ScriptedWriteTransmission> Transport;
        Net::experimental::channel<void(boost::system::error_code)> ServerDone, ReadDone;
        Watchdog Guard;
        std::exception_ptr Failure;
        Prism::Fault::Failure RunFailure{};
        bool RunCompleted{false};
        bool RunThrew{false};
        std::error_code WriteError, ReadError;
        std::size_t Written{999}, ReadBytes{999};
        bool ReadCompleted{false};
    };

    auto ReadPending(std::shared_ptr<WriteFailureScenario> State) -> Net::awaitable<void>
    {
        std::array<std::byte, 16> Buffer{};
        const auto Result = co_await State->Stream->ReadSome(Buffer);
        State->ReadBytes = Result.Bytes;
        State->ReadError = Prism::Fault::ToNative(Result.Failure);
        State->ReadCompleted = true;
        (void)State->ReadDone.try_send(boost::system::error_code{});
    }

    auto CloseWriteFailureServer(std::shared_ptr<WriteFailureScenario> State)
        -> Net::awaitable<void>
    {
        State->Server->Close();
        co_await State->ServerDone.async_receive(Net::use_awaitable);
        const auto Drained = co_await State->Server->Drain();
        EXPECT_TRUE(Drained);
    }

    auto RunWriteFailureScenario(std::shared_ptr<WriteFailureScenario> State) -> Net::awaitable<void>
    {
        Net::co_spawn(State->Server->Executor(), State->Server->Run(),
            [State](
                std::exception_ptr Exception,
                std::expected<void, Prism::Fault::Failure> Outcome)
            {
                State->RunCompleted = true;
                State->RunThrew = static_cast<bool>(Exception);
                if (Exception) State->RunFailure = {Prism::Fault::Code::IoError};
                else if (!Outcome) State->RunFailure = Outcome.error();
                (void)State->ServerDone.try_send(boost::system::error_code{});
            });
        auto ClientSession = std::make_shared<Prism::Http2::Session>(State->Client->Executor(), false);
        ClientSession->SendSettings();
        const auto Opened = ClientSession->OpenStream(
            Prism::Http2::HeaderList{{":method", "CONNECT"}, {":authority", "example.test:443"}}, false);
        if (!Opened)
        {
            co_await CloseWriteFailureServer(State);
            State->Guard.Cancel();
            co_return;
        }
        std::vector<std::byte> Wire;
        if (!ClientSession->Collect(Wire))
        {
            co_await CloseWriteFailureServer(State);
            State->Guard.Cancel();
            co_return;
        }
        const auto WriteResult = co_await State->Client->WriteExact(Wire);
        if (WriteResult.Failure.Failed())
        {
            co_await CloseWriteFailureServer(State);
            State->Guard.Cancel();
            co_return;
        }
        State->Stream = co_await State->Server->AcceptStream();
        if (!State->Stream)
        {
            co_await CloseWriteFailureServer(State);
            State->Guard.Cancel();
            co_return;
        }
        Net::co_spawn(State->Stream->Executor(), ReadPending(State), Net::detached);
        for (int Index = 0; Index < 4; ++Index)
        {
            co_await Net::post(State->Stream->Executor(), Net::use_awaitable);
        }
        const std::array<std::byte, 8> Payload{
            std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4},
            std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}};
        const auto Result = co_await State->Stream->WriteSome(Payload);
        State->Written = Result.Bytes;
        State->WriteError = Prism::Fault::ToNative(Result.Failure);
        EXPECT_TRUE(State->Stream->Close());
        State->Server->Close();
        co_await State->ServerDone.async_receive(Net::use_awaitable);
        co_await State->ReadDone.async_receive(Net::use_awaitable);
        const auto ActivityDrain = co_await State->Stream->Activity()->Drain();
        EXPECT_TRUE(ActivityDrain);
        const auto TerminationDrain = co_await State->Stream->DrainTerminations();
        EXPECT_TRUE(TerminationDrain);
        State->Guard.Cancel();
    }

    /// 构造仅含内存传输与 HTTP/2 会话的 H2 服务端状态
    auto MakeState(Net::io_context &Io) -> std::shared_ptr<Http2State>
    {
        auto [ServerRaw, ClientRaw] = Prism::MakeMemoryPair(Io.get_executor());
        auto State = std::make_shared<Http2State>(
            std::make_shared<Prism::MemoryStream>(std::move(ServerRaw)), 4U);
        State->Session =
            std::make_shared<Prism::Http2::Session>(State->Strand, true);
        return State;
    }

    auto CloseAndDrain(Net::io_context &Io, Prism::SharedTransmission Carrier) -> bool
    {
        bool CloseAccepted = false;
        bool Drained = false;
        Io.restart();
        Net::co_spawn(Io,
            [Carrier = std::move(Carrier), &CloseAccepted, &Drained]() -> Net::awaitable<void>
            {
                CloseAccepted = static_cast<bool>(Carrier->Close());
                const auto Result = co_await Carrier->Activity()->Drain();
                Drained = static_cast<bool>(Result);
            },
            Net::detached);
        Io.run();
        return CloseAccepted && Drained;
    }









} // namespace


