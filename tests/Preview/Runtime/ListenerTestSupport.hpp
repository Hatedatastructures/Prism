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

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Runtime/Listener.hpp>
#include <Preview/Runtime/SessionAdmissionTestSupport.hpp>
#include <Preview/Runtime/Process.hpp>
#include <Preview/Runtime/Session.hpp>
#include <Preview/Runtime/WorkerGroup.hpp>
#include <Preview/Transport/Transmission.hpp>
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
        std::optional<std::expected<void, Preview::Fault::Failure>> Result;
    };

    struct ListenerOperationOutcome final
    {
        bool TimedOut{false};
        std::expected<void, Preview::Fault::Failure> Result;
    };

    struct ListenerTransmissionCloseAttempt final
    {
        Preview::Transmission::ControlResult Request;
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
        Net::awaitable<std::expected<void, Preview::Fault::Failure>> Operation)
        -> std::shared_ptr<ListenerOperationCompletion>
    {
        const auto Completion = std::make_shared<ListenerOperationCompletion>(
            IoContext.get_executor());
        Net::co_spawn(IoContext.get_executor(), std::move(Operation),
            [Completion](std::exception_ptr Exception,
                         std::expected<void, Preview::Fault::Failure> Result)
            {
                if (Exception)
                {
                    Completion->Result.emplace(std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::GenericError}));
                }
                else
                {
                    Completion->Result.emplace(std::move(Result));
                }
                (void)Completion->Completed.try_send(boost::system::error_code{});
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
                true, std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Timeout})};
        }
        co_return ListenerOperationOutcome{false, *Completion->Result};
    }

    /** @brief 请求传输关闭并立即开始等待其独立物理关闭回执。 */
    [[nodiscard]] auto StartListenerTransmissionClose(
        Net::io_context &IoContext,
        const Preview::SharedTransmission &Client) -> ListenerTransmissionCloseAttempt
    {
        if (!Client)
        {
            return {std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument}),
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
    using Preview::Testing::TcpEchoServer;
    using Preview::Testing::RunCoro;

    [[nodiscard]] auto RequireWorkerBytePool(
        Preview::Runtime::WorkerGroup *Workers,
        const std::size_t WorkerIndex)
        -> std::shared_ptr<Preview::Memory::BytePool>
    {
        if (!Workers)
        {
            throw std::logic_error("listener test has no worker group for its Session");
        }
        const auto Id = Preview::WorkerId{static_cast<std::uint64_t>(WorkerIndex) + 1U};
        auto *Worker = Workers->Find(Id);
        if (!Worker || !Worker->Resources().Bytes)
        {
            throw std::logic_error("listener Session requires the selected worker's real byte pool");
        }
        return Worker->Resources().Bytes;
    }

    [[nodiscard]] auto MakeListenerWorkerSessionOptions(
        Preview::Runtime::WorkerGroup *Workers,
        const std::size_t WorkerIndex) -> Preview::Runtime::SessionOptions
    {
        Preview::Runtime::SessionOptions Options;
        Options.Services->Bytes = RequireWorkerBytePool(Workers, WorkerIndex);
        return Options;
    }

    class WorkerGroupRunner final
    {
    public:
        explicit WorkerGroupRunner(Preview::Runtime::WorkerGroup &GroupValue)
            : Group_(&GroupValue)
        {
            Threads_.reserve(Group_->Size());
            for (std::size_t Index = 0; Index < Group_->Size(); ++Index)
            {
                auto *WorkerValue = Group_->Find(Preview::WorkerId{
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
        Preview::Runtime::WorkerGroup *Group_;
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
        Preview::Fault::Code FirstStart{Preview::Fault::Code::GenericError};
        Preview::Fault::Code SecondStart{Preview::Fault::Code::GenericError};
        bool FirstConnected{false};
        bool SecondConnected{false};
        bool GreetingsWritten{false};
        std::size_t EventsReceived{0};
    };

    struct SessionIdentityProbeRequest final
    {
        Net::any_io_executor Executor;
        std::shared_ptr<Preview::Runtime::TcpListener> First;
        std::shared_ptr<Preview::Runtime::TcpListener> Second;
        std::shared_ptr<SessionIdentityEvents> Events;
        std::shared_ptr<SessionIdentityProbeResult> Result;
    };

    struct SessionIdentityAcceptRequest final
    {
        std::shared_ptr<SessionIdentityEvents> Events;
        std::shared_ptr<SessionIdentityCapture> Captured;
        std::size_t ListenerIndex{0};
        Preview::SharedTransmission Inbound;
        Preview::Contract::RequestMetadata Metadata;
    };

    auto AcceptSessionIdentity(SessionIdentityAcceptRequest Request)
        -> Net::awaitable<Preview::Contract::AcceptOutcome>
    {
        Preview::Contract::ProtocolDataPlane Plane;
        Plane.Root = Preview::Contract::StreamDataPlane{std::move(Request.Inbound)};
        Request.Captured->PeerIps[Request.ListenerIndex] = Request.Metadata.SourceIp;
        Request.Captured->PeerIpCaptured[Request.ListenerIndex].store(true, std::memory_order_release);
        Request.Captured->Values[Request.ListenerIndex].store(
            Request.Metadata.TaskIdentity.SessionId.Value(), std::memory_order_release);
        (void)Request.Events->try_send(boost::system::error_code{});
        co_return std::unexpected(Preview::Contract::FailureFromProtocolError(Preview::Error::ProtocolError));
    }

    struct SessionIdentityFactory final
    {
        std::shared_ptr<SessionIdentityEvents> Events;
        std::shared_ptr<SessionIdentityCapture> Captured;
        std::size_t ListenerIndex{0};
        Preview::Runtime::WorkerGroup *Workers{nullptr};

        auto operator()(Preview::Runtime::SessionAdmission Admission) const
            -> Preview::Runtime::SessionAdmissionResult
        {
            if (!Admission.Worker || !Admission.Generation)
            {
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            Preview::Runtime::SessionOptions Options;
            Options.SourceIp = std::move(Admission.SourceIp);
            Options.Services->Generation = Admission.Generation;
            Options.Services->Bytes = RequireWorkerBytePool(
                Workers, static_cast<std::size_t>(Admission.Worker.Value() - 1U));
            Options.Services->AcceptProtocol = std::make_shared<Preview::Testing::StreamFactory>(
                [Events = Events, Captured = Captured, ListenerIndex = ListenerIndex](
                    Preview::Contract::StreamAcceptInput Input)
                {
                    return AcceptSessionIdentity(
                        SessionIdentityAcceptRequest{Events, Captured, ListenerIndex,
                                                     std::move(Input.Inbound),
                                                     std::move(Input.Metadata)});
                });
            return std::make_shared<Preview::Runtime::Session>(std::move(Options));
        }
    };

    auto RunSessionIdentityProbe(SessionIdentityProbeRequest Request) -> Net::awaitable<void>
    {
        auto &Result = *Request.Result;
        Result.FirstStart = co_await Request.First->Start(Tcp::endpoint(Tcp::v4(), 0));
        if (Result.FirstStart != Preview::Fault::Code::Success)
        {
            co_return;
        }
        Result.SecondStart = co_await Request.Second->Start(Tcp::endpoint(Tcp::v4(), 0));
        if (Result.SecondStart != Preview::Fault::Code::Success)
        {
            co_await Request.First->Shutdown();
            co_return;
        }

        Preview::Network::Dialer::Dialer Dialer(Request.Executor);
        std::error_code FirstError;
        auto FirstDialed = co_await Dialer.Connect({*Preview::Network::ParseHost("127.0.0.1"), Request.First->LocalEndpoint().port()});
        Preview::SharedTransmission FirstClient;
        if (FirstDialed)
        {
            FirstClient = std::move(*FirstDialed);
            FirstError.clear();
        }
        else
        {
            FirstError = Preview::Fault::ToNative(FirstDialed.error());
        }
        Result.FirstConnected = !FirstError && static_cast<bool>(FirstClient);
        if (!Result.FirstConnected)
        {
            co_await Request.First->Shutdown();
            co_await Request.Second->Shutdown();
            co_return;
        }

        std::error_code SecondError;
        auto SecondDialed = co_await Dialer.Connect({*Preview::Network::ParseHost("127.0.0.1"), Request.Second->LocalEndpoint().port()});
        Preview::SharedTransmission SecondClient;
        if (SecondDialed)
        {
            SecondClient = std::move(*SecondDialed);
            SecondError.clear();
        }
        else
        {
            SecondError = Preview::Fault::ToNative(SecondDialed.error());
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
        FirstWriteError = Preview::Fault::ToNative(FirstWrite.Failure);
        const auto FirstWritten = FirstWrite.Bytes;
        std::error_code SecondWriteError;
        const auto SecondWrite = co_await SecondClient->WriteSome(Bytes);
        SecondWriteError = Preview::Fault::ToNative(SecondWrite.Failure);
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





    auto AwaitHeldAdmission(Preview::SharedTransmission Inbound,
        std::shared_ptr<Net::experimental::concurrent_channel<void(boost::system::error_code)>> Entered)
        -> Net::awaitable<Preview::Contract::AcceptOutcome>
    {
        (void)Entered->try_send(boost::system::error_code{});
        std::array<std::byte, 1> Byte{};
        std::error_code Error;
        const auto Read = co_await Inbound->ReadExact(Byte);
        Error = Preview::Fault::ToNative(Read.Failure);
        (void)Inbound->Close();
        co_return std::unexpected(Preview::Contract::FailureFromProtocolError(Preview::Error::Canceled));
    }










} // namespace


