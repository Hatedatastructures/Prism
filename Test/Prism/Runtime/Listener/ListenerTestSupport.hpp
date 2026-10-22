/**
 * @file ListenerTestSupport.hpp
 * @brief TcpListener 测试共用的 worker、身份和 admission 辅助。
 * @details 供 ListenerAdmissionTest.cpp 与 ListenerLifecycleTest.cpp 共用，
 *          保持测试 fixture 的所有权和异步收尾逻辑集中在 Runtime 模块。
 */
#pragma once

#include <gtest/gtest.h>
#include <TestSupport/Fixtures/StreamFactory.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Runtime/Listener.hpp>
#include <Test/Prism/Runtime/Session/SessionAdmissionSupport.hpp>
#include <Prism/Runtime/Process.hpp>
#include <Prism/Runtime/Session.hpp>
#include <Prism/Runtime/WorkerGroup.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

#include <utility>

namespace
{

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;
    using ListenerTestEvents =
        Net::experimental::concurrent_channel<void(boost::system::error_code)>;

    struct ListenerOperationCompletion final
    {
        explicit ListenerOperationCompletion(Net::any_io_executor Executor)
            : Completed(std::move(Executor), 1)
        {
        }

        ListenerTestEvents Completed;
        std::optional<std::expected<void, Prism::Fault::Failure>> Result;
    };

    struct ListenerOperationOutcome final
    {
        bool TimedOut{false};
        std::expected<void, Prism::Fault::Failure> Result;
    };

    /** @brief 发布关闭或排空操作的真实结果并通知等待方。 */
    auto CompleteListenerOperation(
        const std::shared_ptr<ListenerOperationCompletion> &Completion,
        std::exception_ptr Exception,
        std::expected<void, Prism::Fault::Failure> Result) -> void
    {
        if (Exception)
        {
            Completion->Result.emplace(std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::GenericError}));
        }
        else
        {
            Completion->Result.emplace(std::move(Result));
        }
        (void)Completion->Completed.try_send(boost::system::error_code{});
    }

    struct ListenerTransmissionCloseAttempt final
    {
        Prism::Transmission::ControlResult Request;
        std::shared_ptr<ListenerOperationCompletion> Completion;
    };

    /** @brief 将 channel 的异步接收转换成可用于测试 deadline race 的有值结果。 */
    auto ReceiveListenerTestEvent(ListenerTestEvents &Events) -> Net::awaitable<bool>
    {
        boost::system::error_code Error;
        co_await Events.async_receive(Net::redirect_error(Net::use_awaitable, Error));
        co_return !Error;
    }

    /** @brief 将 timer 完成转换成有值结果，使两侧 watchdog race 保持 typed。 */
    auto ExpireListenerTestWatchdog(Net::steady_timer &Watchdog) -> Net::awaitable<bool>
    {
        co_await Watchdog.async_wait(Net::use_awaitable);
        co_return true;
    }

    /** @brief 在独立协程中运行关闭或 drain，保留真实结果到完成事件。 */
    [[nodiscard]] auto StartListenerOperation(
        Net::io_context &IoContext,
        Net::awaitable<std::expected<void, Prism::Fault::Failure>> Operation)
        -> std::shared_ptr<ListenerOperationCompletion>
    {
        const auto Completion = std::make_shared<ListenerOperationCompletion>(
            IoContext.get_executor());
        Net::co_spawn(IoContext.get_executor(), std::move(Operation),
            [Completion](std::exception_ptr Exception,
                         std::expected<void, Prism::Fault::Failure> Result)
            {
                CompleteListenerOperation(
                    Completion, std::move(Exception), std::move(Result));
            });
        return Completion;
    }

    /** @brief 有界观察 listener 测试中的独立关闭／回执操作。 */
    auto WaitForListenerOperationGuarded(
        Net::io_context &IoContext,
        const std::shared_ptr<ListenerOperationCompletion> &Completion,
        std::chrono::steady_clock::duration Timeout)
        -> Net::awaitable<ListenerOperationOutcome>
    {
        if (Completion->Result)
        {
            co_return ListenerOperationOutcome{false, *Completion->Result};
        }
        using Net::experimental::awaitable_operators::operator||;
        Net::steady_timer Watchdog(IoContext);
        Watchdog.expires_after(Timeout);
        const auto Wait = co_await (
            ReceiveListenerTestEvent(Completion->Completed) ||
            ExpireListenerTestWatchdog(Watchdog));
        if (Wait.index() != 0U || !std::get<0>(Wait))
        {
            co_return ListenerOperationOutcome{
                true, std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Timeout})};
        }
        co_return ListenerOperationOutcome{false, *Completion->Result};
    }

    /** @brief 请求传输关闭并立即开始等待其独立物理关闭回执。 */
    [[nodiscard]] auto StartListenerTransmissionClose(
        Net::io_context &IoContext,
        const Prism::SharedTransmission &Client) -> ListenerTransmissionCloseAttempt
    {
        if (!Client)
        {
            return {std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument}),
                    {}};
        }
        auto Request = Client->Close();
        auto Activity = Client->Activity();
        return {std::move(Request), StartListenerOperation(IoContext, Activity->Drain())};
    }

    /** @brief 有界等待传输关闭命令及其载体回执都完成。 */
    auto WaitForListenerTransmissionCloseGuarded(
        Net::io_context &IoContext,
        const ListenerTransmissionCloseAttempt &Attempt,
        std::chrono::steady_clock::duration Timeout)
        -> Net::awaitable<bool>
    {
        if (!Attempt.Completion)
        {
            co_return false;
        }
        const auto Outcome = co_await WaitForListenerOperationGuarded(
            IoContext, Attempt.Completion, Timeout);
        co_return static_cast<bool>(Attempt.Request) &&
            !Outcome.TimedOut && static_cast<bool>(Outcome.Result);
    }

    // 公共样板（RunCoro/echo 上游见 <TestSupport/Fixtures/RuntimeTestHelpers.hpp>）
    using Prism::Testing::TcpEchoServer;
    using Prism::Testing::RunCoro;

    [[nodiscard]] auto RequireWorkerBytePool(
        Prism::Runtime::WorkerGroup *Workers,
        const std::size_t WorkerIndex)
        -> std::shared_ptr<Prism::Memory::BytePool>
    {
        if (!Workers)
        {
            throw std::logic_error("listener test has no worker group for its Session");
        }
        const auto Id = Prism::WorkerId{static_cast<std::uint64_t>(WorkerIndex) + 1U};
        auto *Worker = Workers->Find(Id);
        if (!Worker || !Worker->Resources().Bytes)
        {
            throw std::logic_error("listener Session requires the selected worker's real byte pool");
        }
        return Worker->Resources().Bytes;
    }

    [[nodiscard]] auto MakeListenerWorkerSessionOptions(
        Prism::Runtime::WorkerGroup *Workers,
        const std::size_t WorkerIndex) -> Prism::Runtime::SessionOptions
    {
        Prism::Runtime::SessionOptions Options;
        Options.Services->Bytes = RequireWorkerBytePool(Workers, WorkerIndex);
        return Options;
    }

    class WorkerGroupRunner final
    {
    public:
        explicit WorkerGroupRunner(Prism::Runtime::WorkerGroup &GroupValue)
            : Group_(&GroupValue)
        {
            Threads_.reserve(Group_->Size());
            for (std::size_t Index = 0; Index < Group_->Size(); ++Index)
            {
                auto *WorkerValue = Group_->Find(Prism::WorkerId{
                    static_cast<std::uint64_t>(Index + 1)});
                if (WorkerValue)
                {
                    Threads_.emplace_back([WorkerValue] { WorkerValue->Run(); });
                }
            }
        }

        ~WorkerGroupRunner() noexcept
        {
            Group_->Stop();
            for (auto &Thread : Threads_)
            {
                if (Thread.joinable())
                {
                    Thread.join();
                }
            }
        }

        WorkerGroupRunner(const WorkerGroupRunner &) = delete;
        auto operator=(const WorkerGroupRunner &) -> WorkerGroupRunner & = delete;

    private:
        Prism::Runtime::WorkerGroup *Group_;
        std::vector<std::thread> Threads_;
    };

    /// 构造可识别首包（socks5 Greeting）
    auto Socks5Greeting() -> std::string
    {
        return std::string("\x05\x01\x00", 3);
    }

    using SessionIdentityEvents =
        Net::experimental::concurrent_channel<void(boost::system::error_code)>;

    struct SessionIdentityCapture final
    {
        std::array<std::atomic<std::uint64_t>, 2> Values{};
        std::array<std::atomic<bool>, 2> PeerIpCaptured{};
        std::array<std::string, 2> PeerIps{};
    };

    struct SessionIdentityProbeResult final
    {
        Prism::Fault::Code FirstStart{Prism::Fault::Code::GenericError};
        Prism::Fault::Code SecondStart{Prism::Fault::Code::GenericError};
        bool FirstConnected{false};
        bool SecondConnected{false};
        bool GreetingsWritten{false};
        std::size_t EventsReceived{0};
    };

    struct SessionIdentityProbeRequest final
    {
        Net::any_io_executor Executor;
        std::shared_ptr<Prism::Runtime::TcpListener> First;
        std::shared_ptr<Prism::Runtime::TcpListener> Second;
        std::shared_ptr<SessionIdentityEvents> Events;
        std::shared_ptr<SessionIdentityProbeResult> Result;
    };

    struct SessionIdentityAcceptRequest final
    {
        std::shared_ptr<SessionIdentityEvents> Events;
        std::shared_ptr<SessionIdentityCapture> Captured;
        std::size_t ListenerIndex{0};
        Prism::SharedTransmission Inbound;
        Prism::Contract::RequestMetadata Metadata;
    };

    auto AcceptSessionIdentity(SessionIdentityAcceptRequest Request)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        Prism::Contract::ProtocolDataPlane Plane;
        Plane.Root = Prism::Contract::StreamDataPlane{std::move(Request.Inbound)};
        Request.Captured->PeerIps[Request.ListenerIndex] = Request.Metadata.SourceIp;
        Request.Captured->PeerIpCaptured[Request.ListenerIndex].store(true, std::memory_order_release);
        Request.Captured->Values[Request.ListenerIndex].store(
            Request.Metadata.TaskIdentity.SessionId.Value(), std::memory_order_release);
        (void)Request.Events->try_send(boost::system::error_code{});
        co_return std::unexpected(Prism::Contract::FailureFromProtocolError(Prism::Error::ProtocolError));
    }

    struct SessionIdentityFactory final
    {
        std::shared_ptr<SessionIdentityEvents> Events;
        std::shared_ptr<SessionIdentityCapture> Captured;
        std::size_t ListenerIndex{0};
        Prism::Runtime::WorkerGroup *Workers{nullptr};

        auto operator()(Prism::Runtime::SessionAdmission Admission) const
            -> Prism::Runtime::SessionAdmissionResult
        {
            if (!Admission.Worker || !Admission.Generation)
            {
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            Prism::Runtime::SessionOptions Options;
            Options.SourceIp = std::move(Admission.SourceIp);
            Options.Services->Generation = Admission.Generation;
            Options.Services->Bytes = RequireWorkerBytePool(
                Workers, static_cast<std::size_t>(Admission.Worker.Value() - 1U));
            Options.Services->AcceptProtocol = std::make_shared<Prism::Testing::StreamFactory>(
                [Events = Events, Captured = Captured, ListenerIndex = ListenerIndex](
                    Prism::Contract::StreamAcceptInput Input)
                {
                    return AcceptSessionIdentity(
                        SessionIdentityAcceptRequest{Events, Captured, ListenerIndex,
                                                     std::move(Input.Inbound),
                                                     std::move(Input.Metadata)});
                });
            return std::make_shared<Prism::Runtime::Session>(std::move(Options));
        }
    };

    auto RunSessionIdentityProbe(SessionIdentityProbeRequest Request) -> Net::awaitable<void>
    {
        auto &Result = *Request.Result;
        Result.FirstStart = co_await Request.First->Start(Tcp::endpoint(Tcp::v4(), 0));
        if (Result.FirstStart != Prism::Fault::Code::Success)
        {
            co_return;
        }
        Result.SecondStart = co_await Request.Second->Start(Tcp::endpoint(Tcp::v4(), 0));
        if (Result.SecondStart != Prism::Fault::Code::Success)
        {
            co_await Request.First->Shutdown();
            co_return;
        }

        Prism::Network::Dialer::Dialer Dialer(Request.Executor);
        std::error_code FirstError;
        auto FirstDialed = co_await Dialer.Connect({*Prism::Network::ParseHost("127.0.0.1"), Request.First->LocalEndpoint().port()});
        Prism::SharedTransmission FirstClient;
        if (FirstDialed)
        {
            FirstClient = std::move(*FirstDialed);
            FirstError.clear();
        }
        else
        {
            FirstError = Prism::Fault::ToNative(FirstDialed.error());
        }
        Result.FirstConnected = !FirstError && static_cast<bool>(FirstClient);
        if (!Result.FirstConnected)
        {
            co_await Request.First->Shutdown();
            co_await Request.Second->Shutdown();
            co_return;
        }

        std::error_code SecondError;
        auto SecondDialed = co_await Dialer.Connect({*Prism::Network::ParseHost("127.0.0.1"), Request.Second->LocalEndpoint().port()});
        Prism::SharedTransmission SecondClient;
        if (SecondDialed)
        {
            SecondClient = std::move(*SecondDialed);
            SecondError.clear();
        }
        else
        {
            SecondError = Prism::Fault::ToNative(SecondDialed.error());
        }
        Result.SecondConnected = !SecondError && static_cast<bool>(SecondClient);
        if (!Result.SecondConnected)
        {
            (void)FirstClient->Close();
            co_await Request.First->Shutdown();
            co_await Request.Second->Shutdown();
            co_return;
        }

        const auto Greeting = Socks5Greeting();
        const auto Bytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Greeting.data()), Greeting.size());
        std::error_code FirstWriteError;
        const auto FirstWrite = co_await FirstClient->WriteSome(Bytes);
        FirstWriteError = Prism::Fault::ToNative(FirstWrite.Failure);
        const auto FirstWritten = FirstWrite.Bytes;
        std::error_code SecondWriteError;
        const auto SecondWrite = co_await SecondClient->WriteSome(Bytes);
        SecondWriteError = Prism::Fault::ToNative(SecondWrite.Failure);
        const auto SecondWritten = SecondWrite.Bytes;
        Result.GreetingsWritten = !FirstWriteError && !SecondWriteError &&
                                  FirstWritten == Greeting.size() &&
                                  SecondWritten == Greeting.size();
        if (!Result.GreetingsWritten)
        {
            (void)FirstClient->Close();
            (void)SecondClient->Close();
            co_await Request.First->Shutdown();
            co_await Request.Second->Shutdown();
            co_return;
        }

        co_await Request.Events->async_receive(Net::use_awaitable);
        ++Result.EventsReceived;
        co_await Request.Events->async_receive(Net::use_awaitable);
        ++Result.EventsReceived;
        (void)FirstClient->Close();
        (void)SecondClient->Close();
        co_await Request.First->Shutdown();
        co_await Request.Second->Shutdown();
    }





    auto AwaitHeldAdmission(Prism::SharedTransmission Inbound,
        std::shared_ptr<Net::experimental::concurrent_channel<void(boost::system::error_code)>> Entered)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        (void)Entered->try_send(boost::system::error_code{});
        std::array<std::byte, 1> Byte{};
        std::error_code Error;
        const auto Read = co_await Inbound->ReadExact(Byte);
        Error = Prism::Fault::ToNative(Read.Failure);
        (void)Inbound->Close();
        co_return std::unexpected(Prism::Contract::FailureFromProtocolError(Prism::Error::Canceled));
    }










} // namespace


