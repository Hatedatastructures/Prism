/**
 * @file NativeHttp3Session.cpp
 * @brief 原生 HTTP/3 与 QUIC provider 会话契约回归
 */

#include <Preview/Protocols/Http3/NativeServer.hpp>
#include <Preview/Protocols/Http3/NativeClient.hpp>
#include <Preview/Protocols/Quic/ConnectionLifecycle.hpp>
#include <TestSupport/Preview/QuicStreamProviderActivity.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <stdexcept>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

namespace
{

    namespace Net = boost::asio;
    using TestSignal = std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>>;
    using ProviderResult = std::expected<Preview::Quic::SharedStreamProvider, Preview::Fault::Failure>;

    /** @brief 首次关闭返回正在交接，重试后完成本地关闭的 HTTP/3 stream provider。 */
    class PendingCloseProvider final : public Preview::Quic::StreamProvider
    {
    public:
        PendingCloseProvider(Net::any_io_executor Executor, const std::int64_t StreamId)
            : Executor_(std::move(Executor)), StreamId_(StreamId),
              Activity_(std::make_shared<Preview::Testing::Quic::StreamProviderActivity>(Executor_))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override { return Executor_; }
        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override { return Activity_; }
        [[nodiscard]] auto StreamId() const noexcept -> std::int64_t override { return StreamId_; }
        [[nodiscard]] auto IsClosed() const noexcept -> bool override { return Closed_; }
        [[nodiscard]] auto CloseCalls() const noexcept -> std::size_t { return CloseCalls_; }

        [[nodiscard]] auto Read(std::span<std::byte>, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t> override
        {
            const auto Operation = Activity_->BeginOperation();
            ErrorCode.clear();
            if (!Operation || Closed_)
            {
                ErrorCode = std::make_error_code(std::errc::operation_canceled);
            }
            co_return 0U;
        }

        [[nodiscard]] auto Write(std::span<const std::byte> Buffer, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t> override
        {
            const auto Operation = Activity_->BeginOperation();
            ErrorCode.clear();
            if (!Operation || Closed_)
            {
                ErrorCode = std::make_error_code(std::errc::operation_canceled);
                co_return 0U;
            }
            co_return Buffer.size();
        }

        [[nodiscard]] auto Close() -> Preview::Quic::StreamProvider::ControlResult override
        {
            ++CloseCalls_;
            if (CloseCalls_ == 1U)
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            Closed_ = true;
            Activity_->CompleteClose();
            return {};
        }

        [[nodiscard]] auto ShutdownWrite() -> Net::awaitable<ShutdownResult> override
        {
            const auto Operation = Activity_->BeginOperation();
            if (!Operation)
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            }
            co_return ShutdownResult{};
        }

        [[nodiscard]] auto WaitForWriteAcknowledgement() -> Net::awaitable<ShutdownResult> override
        {
            const auto Operation = Activity_->BeginOperation();
            if (!Operation)
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            }
            co_return ShutdownResult{};
        }

    private:
        Net::any_io_executor Executor_;
        std::int64_t StreamId_;
        std::shared_ptr<Preview::Testing::Quic::StreamProviderActivity> Activity_;
        std::size_t CloseCalls_{0U};
        bool Closed_{false};
    };

    struct PendingCloseScenario final
    {
        explicit PendingCloseScenario(Net::any_io_executor Executor)
            : AcceptUnidirectional(std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(Executor, 1U)),
              AcceptBidirectional(std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(Executor, 1U)),
              RunFinished(std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(Executor, 1U))
        {
        }

        TestSignal AcceptUnidirectional;
        TestSignal AcceptBidirectional;
        TestSignal RunFinished;
        std::vector<std::shared_ptr<PendingCloseProvider>> Providers;
        std::int64_t NextStreamId{3};
        std::optional<std::expected<void, Preview::Fault::Failure>> RunResult;
        std::exception_ptr RunException;
    };

    [[nodiscard]] auto WaitForSignal(TestSignal Signal) -> Net::awaitable<bool>
    {
        boost::system::error_code Error;
        co_await Signal->async_receive(Net::redirect_error(Net::use_awaitable, Error));
        co_return !Error;
    }

    [[nodiscard]] auto WaitForProtocolReady(
        const std::shared_ptr<Preview::Http3::NativeServerSession> &Session,
        Net::any_io_executor Executor) -> Net::awaitable<bool>
    {
        Net::steady_timer Timer(std::move(Executor));
        for (std::size_t Attempt = 0U; Attempt < 100U; ++Attempt)
        {
            if (Session->ProtocolReady()) co_return true;
            Timer.expires_after(std::chrono::milliseconds(10));
            boost::system::error_code Error;
            co_await Timer.async_wait(Net::redirect_error(Net::use_awaitable, Error));
            if (Error) co_return false;
        }
        co_return Session->ProtocolReady();
    }

    [[nodiscard]] auto WaitForCanceledAccept(TestSignal Signal) -> Net::awaitable<ProviderResult>
    {
        const auto Signaled = co_await WaitForSignal(std::move(Signal));
        if (!Signaled)
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::IoError});
        }
        co_return std::unexpected(
            Preview::Fault::Failure{Preview::Fault::Code::Canceled});
    }

    auto RecordRunCompletion(
        const std::shared_ptr<PendingCloseScenario> &Scenario,
        std::exception_ptr Exception,
        std::expected<void, Preview::Fault::Failure> Result) -> void
    {
        Scenario->RunException = std::move(Exception);
        Scenario->RunResult = std::move(Result);
        (void)Scenario->RunFinished->try_send(boost::system::error_code{});
    }

    struct PendingCloseResult final
    {
        bool Ready{false};
        bool RunFinished{false};
        bool RunSucceeded{false};
        bool Drained{false};
        bool Retired{false};
        Preview::Fault::Failure RunFailure{};
        Preview::Fault::Failure DrainFailure{};
        std::vector<std::size_t> CloseCalls;
    };

    /** @brief 在协议关闭钩子观察 QUIC native server 是否已先封闭。 */
    class CloseOrderLifecycle final : public Preview::Protocols::QuicConnectionLifecycle
    {
    public:
        explicit CloseOrderLifecycle(Preview::Protocols::QuicConnectionPreparation Input)
            : QuicConnectionLifecycle(std::move(Input))
        {
            Install(Options());
        }

        [[nodiscard]] auto NativeClosed() const noexcept -> bool
        {
            const auto Server = NativeServer();
            return !Server || Server->Health().Closed;
        }

        [[nodiscard]] auto NativeClosedBeforeProtocol() const noexcept -> bool
        {
            return NativeClosedBeforeProtocol_;
        }

    private:
        auto CloseProtocol() -> void override
        {
            NativeClosedBeforeProtocol_ = NativeClosed();
        }

        [[nodiscard]] auto DrainProtocol()
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        bool NativeClosedBeforeProtocol_{false};
    };

    [[nodiscard]] auto RunPendingCloseScenario() -> Net::awaitable<PendingCloseResult>
    {
        const auto Executor = co_await Net::this_coro::executor;
        const auto Scenario = std::make_shared<PendingCloseScenario>(Executor);
        Preview::Http3::NativeServerSessionOptions Options;
        Options.Executor = Executor;
        Options.OpenUnidirectional = [Scenario, Executor]() -> Net::awaitable<ProviderResult> {
            auto Provider = std::make_shared<PendingCloseProvider>(Executor, Scenario->NextStreamId);
            Scenario->NextStreamId += 4;
            Scenario->Providers.push_back(Provider);
            co_return Preview::Quic::SharedStreamProvider{std::move(Provider)};
        };
        Options.AcceptUnidirectional = [Scenario] {
            return WaitForCanceledAccept(Scenario->AcceptUnidirectional);
        };
        Options.AcceptBidirectional = [Scenario] {
            return WaitForCanceledAccept(Scenario->AcceptBidirectional);
        };
        auto Session = std::make_shared<Preview::Http3::NativeServerSession>(std::move(Options));
        Net::co_spawn(Executor, Session->Run(), [Scenario](
            std::exception_ptr Exception,
            std::expected<void, Preview::Fault::Failure> Result)
        {
            RecordRunCompletion(Scenario, std::move(Exception), std::move(Result));
        });

        PendingCloseResult Result;
        Result.Ready = co_await WaitForProtocolReady(Session, Executor);
        const auto Closed = Session->Close();
        if (Closed)
        {
            (void)Scenario->AcceptUnidirectional->try_send(boost::system::error_code{});
            (void)Scenario->AcceptBidirectional->try_send(boost::system::error_code{});
        }
        Result.RunFinished = co_await WaitForSignal(Scenario->RunFinished);
        Result.RunSucceeded = Result.RunFinished && !Scenario->RunException &&
                              Scenario->RunResult && *Scenario->RunResult;
        if (Result.RunFinished && Scenario->RunResult && !*Scenario->RunResult)
        {
            Result.RunFailure = Scenario->RunResult->error();
        }
        const auto Drained = co_await Session->Drain();
        Result.Drained = static_cast<bool>(Drained);
        if (!Drained) Result.DrainFailure = Drained.error();
        Result.Retired = Session->IsRetired();
        for (const auto &Provider : Scenario->Providers)
        {
            Result.CloseCalls.push_back(Provider->CloseCalls());
        }
        co_return Result;
    }

    static_assert(!std::is_copy_constructible_v<Preview::Http3::HeaderBlock>);
    static_assert(std::is_move_constructible_v<Preview::Http3::HeaderBlock>);
    static_assert(!std::is_copy_constructible_v<Preview::Http3::RequestHead>);
    static_assert(std::is_move_constructible_v<Preview::Http3::RequestEvent>);
    static_assert(!std::is_copy_constructible_v<Preview::Http3::DataEvent>);
    static_assert(std::is_move_constructible_v<Preview::Http3::DataEvent>);
    static_assert(std::is_move_constructible_v<Preview::Http3::NativeServerSessionOptions>);
    static_assert(requires(Preview::Http3::NativeServerSession &Session)
                  {
                      Session.Run();
                      Session.Close();
                      Session.ProtocolReady();
                  });
    static_assert(std::is_move_constructible_v<Preview::Http3::NativeClientSessionOptions>);
    static_assert(requires(Preview::Http3::NativeClientSession &Session,
                           Preview::Http3::RequestHead Request)
                  {
                      Session.SendRequest(std::move(Request));
                      Session.OpenBidirectionalStream();
                      Session.Close();
                  });

    TEST(NativeHttp3Session, ExposesAsyncProviderContract)
    {
        Preview::Http3::NativeServerSessionOptions Options;
        EXPECT_FALSE(Options.OpenUnidirectional);
        EXPECT_FALSE(Options.AcceptUnidirectional);
        EXPECT_FALSE(Options.AcceptBidirectional);
        EXPECT_FALSE(Options.OnEvent);
    }

    TEST(NativeHttp3Session, PreservesCloseRejectionAfterProviderRetires)
    {
        Net::io_context Io;
        std::optional<PendingCloseResult> Result;
        std::exception_ptr Exception;
        Net::co_spawn(Io, RunPendingCloseScenario(), [&](
            std::exception_ptr Error, PendingCloseResult Value)
        {
            Exception = std::move(Error);
            Result = std::move(Value);
        });
        Io.run();

        ASSERT_FALSE(Exception);
        ASSERT_TRUE(Result);
        EXPECT_TRUE(Result->Ready);
        EXPECT_TRUE(Result->RunFinished);
        EXPECT_FALSE(Result->RunSucceeded);
        EXPECT_FALSE(Result->Drained);
        EXPECT_TRUE(Result->Retired);
        EXPECT_EQ(Result->RunFailure.Code, Preview::Fault::Code::Blocked);
        EXPECT_EQ(Result->DrainFailure.Code, Preview::Fault::Code::Blocked);
        ASSERT_EQ(Result->CloseCalls.size(), 3U);
        for (const auto Calls : Result->CloseCalls)
        {
            EXPECT_GE(Calls, 2U);
        }
    }

    TEST(NativeHttp3Session, ClosesProtocolBeforeNativeQuicLoops)
    {
        Net::io_context Io;
        auto Socket = std::make_shared<Net::ip::udp::socket>(
            Io, Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 0U));
        auto Tls = std::make_shared<Net::ssl::context>(Net::ssl::context::tlsv13_server);
        Preview::Protocols::QuicConnectionPreparation Preparation;
        Preparation.Listener.Executor = Io.get_executor();
        Preparation.Listener.Socket = std::move(Socket);
        Preparation.Listener.Tls = std::move(Tls);
        auto Lifecycle = std::make_shared<CloseOrderLifecycle>(std::move(Preparation));

        ASSERT_FALSE(Lifecycle->NativeClosed());
        ASSERT_TRUE(Lifecycle->RequestClose());
        std::optional<std::expected<void, Preview::Fault::Failure>> DrainResult;
        std::exception_ptr Exception;
        Net::co_spawn(Io, Lifecycle->Drain(), [&](
            std::exception_ptr Error,
            std::expected<void, Preview::Fault::Failure> Result)
        {
            Exception = std::move(Error);
            DrainResult = std::move(Result);
        });
        Io.run();

        ASSERT_FALSE(Exception);
        ASSERT_TRUE(DrainResult);
        ASSERT_TRUE(*DrainResult);
        EXPECT_FALSE(Lifecycle->NativeClosedBeforeProtocol());
        EXPECT_TRUE(Lifecycle->NativeClosed());
    }

    TEST(NativeHttp3Session, ClientDefaultsToUnready)
    {
        boost::asio::io_context Io;
        Preview::Http3::NativeClientSessionOptions Options;
        Options.Executor = Io.get_executor();
        auto Session = std::make_shared<Preview::Http3::NativeClientSession>(std::move(Options));
        EXPECT_FALSE(Session->HandshakeReady());
        EXPECT_FALSE(Session->ProtocolReady());
        Session->Close();
    }

    TEST(NativeHttp3Session, EventHeadersAndDataMoveWithoutBorrowedPayload)
    {
        EXPECT_THROW(
            Preview::Http3::HeaderBlock(nullptr),
            std::invalid_argument);
        auto MemoryOwner = std::make_shared<Preview::Memory::SessionResource<>>();
        Preview::Http3::HeaderBlock Headers(MemoryOwner);
        Headers.Fields.push_back({":method", "GET"});
        Headers.Fields.push_back({":path", "/generic"});

        Preview::Http3::RequestEvent Request{
            0, Preview::Http3::RequestHead{std::move(Headers), true}};
        Preview::Http3::ServerEvent Event{std::move(Request)};
        ASSERT_TRUE(std::holds_alternative<Preview::Http3::RequestEvent>(Event));
        const auto &RequestValue = std::get<Preview::Http3::RequestEvent>(Event);
        ASSERT_EQ(RequestValue.Head.Headers.Fields.size(), 2U);
        EXPECT_EQ(RequestValue.Head.Headers.Fields[0].Name, ":method");
        EXPECT_EQ(RequestValue.Head.Headers.Fields[0].value, "GET");
        EXPECT_EQ(RequestValue.Head.Headers.Fields[1].Name, ":path");
        EXPECT_EQ(RequestValue.Head.Headers.Fields[1].value, "/generic");
        EXPECT_TRUE(RequestValue.Head.Fin);
        EXPECT_EQ(RequestValue.Head.Headers.Owner, MemoryOwner);

        Preview::Http3::DataEvent Data{
            0, std::vector<std::byte>{std::byte{0x41}, std::byte{0x42}}, true};
        Preview::Http3::ServerEvent DataValue{std::move(Data)};
        ASSERT_TRUE(std::holds_alternative<Preview::Http3::DataEvent>(DataValue));
        const auto &Payload = std::get<Preview::Http3::DataEvent>(DataValue);
        ASSERT_EQ(Payload.Data.size(), 2U);
        EXPECT_EQ(Payload.Data[0], std::byte{0x41});
        EXPECT_EQ(Payload.Data[1], std::byte{0x42});
        EXPECT_TRUE(Payload.Fin);
    }

    TEST(NativeHttp3Session, GenericResponseAllowsArbitraryStatusAndFields)
    {
        auto MemoryOwner = std::make_shared<Preview::Memory::SessionResource<>>();
        Preview::Http3::HeaderBlock Headers(MemoryOwner);
        Headers.Fields.push_back({"content-type", "application/octet-stream"});
        Headers.Fields.push_back({"x-h3-test", "value"});
        Preview::Http3::ResponseHead Response{7, 418, std::move(Headers), true};

        EXPECT_EQ(Response.StreamId, 7);
        EXPECT_EQ(Response.Status, 418);
        ASSERT_EQ(Response.Headers.Fields.size(), 2U);
        EXPECT_EQ(Response.Headers.Fields[0].Name, "content-type");
        EXPECT_EQ(Response.Headers.Fields[1].Name, "x-h3-test");
        EXPECT_TRUE(Response.Fin);
    }

    TEST(NativeHttp3Session, RequestFinIsAGenericWireChoice)
    {
        auto ClosedOwner = std::make_shared<Preview::Memory::SessionResource<>>();
        Preview::Http3::RequestHead ClosedRequest{
            Preview::Http3::HeaderBlock(ClosedOwner), true};
        EXPECT_TRUE(ClosedRequest.Fin);

        auto OpenOwner = std::make_shared<Preview::Memory::SessionResource<>>();
        Preview::Http3::RequestHead OpenRequest{
            Preview::Http3::HeaderBlock(OpenOwner), false};
        EXPECT_FALSE(OpenRequest.Fin);
    }

} // namespace
