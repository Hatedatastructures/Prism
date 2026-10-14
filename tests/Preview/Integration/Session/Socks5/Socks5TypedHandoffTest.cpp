#include <TestSupport/Preview/ProviderBindings.hpp>
/**
 * @file Socks5TypedHandoffTest.cpp
 * @brief SOCKS5 typed data-plane handoff 的红灯回归测试
 * @details 锁定正式 SOCKS5 binding 到 ProtocolDataPlane、Context 的唯一
 *          move owner，以及真实 UserPass/CONNECT 握手的关闭和账户租约边界。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Account/Account.hpp>
#include <Preview/Protocols/Anytls/IngressFactory.hpp>
#include <Preview/Protocols/Vless/IngressFactory.hpp>
#include <Preview/Protocols/Trojan/IngressFactory.hpp>
#include <Preview/Protocols/Vmess/IngressFactory.hpp>
#include <Preview/Contract/Ingress/StreamFactory.hpp>
#include <Preview/Account/Authenticator.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Protocols/Socks5/Socks5.hpp>
#include <Preview/Contract/Ingress/DataPlane.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Fault = Preview::Fault;
    namespace Middleware = Preview::Middleware;
    namespace Runtime = Preview::Runtime;
    namespace Socks5 = Preview::Socks5;

    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using Preview::SharedTransmission;
    using Preview::Testing::RunCoro;

    using CompletionChannel =
        Net::experimental::channel<void(boost::system::error_code, bool)>;
    using MemoryPair =
        std::pair<std::shared_ptr<MemoryStream>, std::shared_ptr<MemoryStream>>;

    struct HandshakeWatchdogState final
    {
        std::shared_ptr<MemoryStream> Client;
        std::shared_ptr<MemoryStream> Server;
        std::shared_ptr<Net::steady_timer> Timer;
        std::shared_ptr<CompletionChannel> AcceptWake;
        std::shared_ptr<CompletionChannel> ServerExited;
        std::shared_ptr<CompletionChannel> WatchdogExited;
        bool ServerFinished{false};
        bool ServerFailed{false};
        bool ServerExitObserved{false};
        bool WatchdogExitObserved{false};
        bool TimedOut{false};
        bool Finished{false};
    };

    auto MakeHandshakeWatchdogState(Net::io_context &Io, const MemoryPair &Endpoints)
        -> std::shared_ptr<HandshakeWatchdogState>
    {
        auto State = std::make_shared<HandshakeWatchdogState>();
        State->Client = Endpoints.first;
        State->Server = Endpoints.second;
        State->Timer = std::make_shared<Net::steady_timer>(Io);
        State->AcceptWake = std::make_shared<CompletionChannel>(Io.get_executor(), 1);
        State->ServerExited = std::make_shared<CompletionChannel>(Io.get_executor(), 1);
        State->WatchdogExited = std::make_shared<CompletionChannel>(Io.get_executor(), 1);
        return State;
    }

    auto RunHandshakeWatchdog(
        const std::shared_ptr<HandshakeWatchdogState> &State)
        -> Net::awaitable<void>
    {
        boost::system::error_code ErrorCode;
        co_await State->Timer->async_wait(
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        if (!ErrorCode && !State->Finished)
        {
            State->TimedOut = true;
            (void)State->Client->Close();
            (void)State->Server->Close();
            if (!State->ServerFinished)
            {
                (void)State->AcceptWake->try_send(
                    boost::system::error_code{}, false);
            }
        }
        (void)State->WatchdogExited->try_send(
            boost::system::error_code{}, true);
    }

    auto StartHandshakeWatchdog(
        const std::shared_ptr<HandshakeWatchdogState> &State,
        std::chrono::milliseconds Timeout) -> void
    {
        State->Timer->expires_after(Timeout);
        Net::co_spawn(
            State->Timer->get_executor(),
            RunHandshakeWatchdog(State),
            [](const std::exception_ptr &) {});
    }

    auto WaitForServerExit(const std::shared_ptr<HandshakeWatchdogState> &State)
        -> Net::awaitable<void>
    {
        if (!State->ServerExitObserved)
        {
            (void)co_await State->ServerExited->async_receive(Net::use_awaitable);
            State->ServerExitObserved = true;
        }
    }

    auto FinishHandshake(const std::shared_ptr<HandshakeWatchdogState> &State)
        -> Net::awaitable<void>
    {
        State->Finished = true;
        State->Timer->cancel();
        if (!State->WatchdogExitObserved)
        {
            (void)co_await State->WatchdogExited->async_receive(Net::use_awaitable);
            State->WatchdogExitObserved = true;
        }
    }

    auto AbortHandshake(const std::shared_ptr<HandshakeWatchdogState> &State)
        -> Net::awaitable<void>
    {
        State->Finished = true;
        (void)State->Client->Close();
        (void)State->Server->Close();
        State->Timer->cancel();
        co_await WaitForServerExit(State);
        if (!State->WatchdogExitObserved)
        {
            (void)co_await State->WatchdogExited->async_receive(Net::use_awaitable);
            State->WatchdogExitObserved = true;
        }
    }

    auto MakeMemoryPairShared(Net::io_context &Io)
        -> MemoryPair
    {
        auto [A, B] = MakeMemoryPair(Io.get_executor());
        return {std::make_shared<MemoryStream>(std::move(A)),
                std::make_shared<MemoryStream>(std::move(B))};
    }

    auto MakeAccountRecord(Preview::AccountId AccountId, std::string_view Password)
        -> std::shared_ptr<Preview::Testing::ProviderAccounts>
    {
        return Preview::Testing::ProviderAccount(
            Preview::Account::Credential::Password(Password), AccountId,
            {.MaxConnections = 1});
    }

    auto AsWire(const std::vector<std::uint8_t> &Value) -> std::span<const std::byte>
    {
        return std::as_bytes(std::span<const std::uint8_t>(Value));
    }

    auto WriteWire(SharedTransmission Connection, std::span<const std::byte> Wire)
        -> Net::awaitable<bool>
    {
        std::error_code ErrorCode;
        const auto Written = co_await Connection->WriteExact(Wire);
        ErrorCode = Preview::Fault::ToNative(Written.Failure);
        co_return !ErrorCode && Written.Bytes == Wire.size();
    }

    auto ReadWire(SharedTransmission Connection, std::span<std::byte> Wire)
        -> Net::awaitable<bool>
    {
        std::error_code ErrorCode;
        const auto Read = co_await Connection->ReadExact(Wire);
        ErrorCode = Preview::Fault::ToNative(Read.Failure);
        co_return !ErrorCode && Read.Bytes == Wire.size();
    }

    auto MakeUserPass(std::string_view User, std::string_view Password)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Wire{0x01, static_cast<std::uint8_t>(User.size())};
        Wire.insert(Wire.end(), User.begin(), User.end());
        Wire.push_back(static_cast<std::uint8_t>(Password.size()));
        Wire.insert(Wire.end(), Password.begin(), Password.end());
        return Wire;
    }

    auto MakeConnectRequest(std::string_view Host, std::uint16_t Port)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Wire{
            0x05,
            0x01,
            0x00,
            0x03,
            static_cast<std::uint8_t>(Host.size())};
        Wire.insert(Wire.end(), Host.begin(), Host.end());
        Wire.push_back(static_cast<std::uint8_t>(Port >> 8));
        Wire.push_back(static_cast<std::uint8_t>(Port & 0xff));
        return Wire;
    }

    class StubHandler final : public Preview::Contract::StreamFactory
    {
    public:
        explicit StubHandler(Preview::Contract::ProtocolDataPlane Result)
            : Result_(std::move(Result))
        {
        }

        auto Accept(SharedTransmission, Preview::Contract::RequestMetadata)
            -> Net::awaitable<Preview::Contract::AcceptOutcome> override
        {
            co_return std::move(Result_);
        }

        [[nodiscard]] auto Name() const -> std::string_view override
        {
            return "socks5-typed-handoff-stub";
        }

    private:
        Preview::Contract::ProtocolDataPlane Result_;
    };

    auto MakeStubAccept(Preview::Contract::ProtocolDataPlane Result)
        -> std::shared_ptr<Preview::Contract::StreamFactory>
    {
        return std::make_shared<StubHandler>(std::move(Result));
    }

    struct Socks5TypedContextFlow final
    {
        std::shared_ptr<Preview::Contract::StreamFactory> Accept;
        SharedTransmission &Inbound;
        Middleware::Context &Context;
    };

    /** @brief 验证 typed DataPlane 转移后 PostDial 仍由唯一 Context 持有。 */
    auto RunSocks5TypedContextFlow(Socks5TypedContextFlow Flow)
        -> Net::awaitable<void>
    {
        auto Accepted = co_await Flow.Accept->Accept(Flow.Inbound, {});
        const auto Code = Accepted ? Preview::Fault::Code::Success
                                   : Accepted.error().Code;
        if (Accepted)
        {
            Flow.Context.SetDataPlane(std::move(*Accepted));
            Flow.Inbound = Flow.Context.Inbound();
        }
        EXPECT_EQ(Code, Fault::Code::Success);
        EXPECT_TRUE(Flow.Context.PostDial())
            << "typed context must retain DataPlane PostDial when legacy PostDial is empty";
        EXPECT_EQ(&Flow.Context.PostDial(), &Flow.Context.DataPlane.PostDial);
        if (Flow.Context.PostDial())
        {
            co_await Flow.Context.PostDial()(Fault::Code::Success);
        }
    }

    struct Socks5AcceptTask final
    {
        std::shared_ptr<Preview::Contract::StreamFactory> Accept;
        SharedTransmission &Inbound;
        Middleware::Context &Context;
        Fault::Code &Code;
        std::shared_ptr<HandshakeWatchdogState> Watchdog;
    };

    /** @brief 运行真实 SOCKS5 accept task 并唯一发布完成/退出通知。 */
    auto RunSocks5AcceptTask(Socks5AcceptTask Flow) -> Net::awaitable<void>
    {
        try
        {
            auto Accepted = co_await Flow.Accept->Accept(Flow.Inbound, {});
            Flow.Code = Accepted ? Preview::Fault::Code::Success
                                 : Accepted.error().Code;
            if (Accepted)
            {
                Flow.Context.SetDataPlane(std::move(*Accepted));
                Flow.Inbound = Flow.Context.Inbound();
            }
        }
        catch (...)
        {
            Flow.Watchdog->ServerFailed = true;
        }
        Flow.Watchdog->ServerFinished = true;
        (void)Flow.Watchdog->AcceptWake->try_send(
            boost::system::error_code{}, true);
        (void)Flow.Watchdog->ServerExited->try_send(
            boost::system::error_code{}, true);
    }

    TEST(Socks5TypedHandoff, MovingPlaneTransfersTransportLeaseAndPostDial)
    {
        Net::io_context Io;
        auto [Transport, Peer] = MakeMemoryPairShared(Io);
        auto Directory = MakeAccountRecord(Preview::AccountId{7301}, "typed-password");
        const auto Record = Directory->Store->FindById(Preview::AccountId{7301});
        ASSERT_TRUE(Record);
        auto Authenticator = Directory->Authenticator;
        auto AuthResult = Authenticator->Authenticate(Preview::AuthenticationRequest{
            .AccountId = {},
            .Identity = {},
            .Credential = Preview::Account::CredentialView::Password("typed-password"),
            .Rate = {}});
        ASSERT_TRUE(AuthResult);
        ASSERT_TRUE(*AuthResult);

        Preview::Contract::ProtocolDataPlane Result;
        Result.ProtocolAuthenticated = true;
        Result.AccountId = AuthResult->AccountId();
        Result.AccountLease = std::move(*AuthResult);
        Result.Root = Preview::Contract::StreamDataPlane{Transport};
        const auto CallbackCalled = std::make_shared<bool>(false);
        Result.PostDial = [CallbackCalled](Fault::Code) -> Net::awaitable<Fault::Code>
        {
            *CallbackCalled = true;
            co_return Fault::Code::Success;
        };

        auto Accepted = std::move(Result);

        ASSERT_TRUE(Accepted.HasTransport());
        EXPECT_EQ(Accepted.Transport().get(), Transport.get());
        EXPECT_FALSE(Result.Transport())
            << "typed materialization must consume the legacy transport owner";
        EXPECT_FALSE(Result.PostDial)
            << "typed materialization must consume the legacy PostDial owner";
        ASSERT_TRUE(Accepted.AccountLease);
        EXPECT_TRUE(static_cast<bool>(Accepted.AccountLease));
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 1U);
        ASSERT_TRUE(Accepted.PostDial);

        RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                co_await Accepted.PostDial(Fault::Code::Success);
            });
        EXPECT_TRUE(*CallbackCalled);

        Accepted.AccountLease.Release();
        EXPECT_FALSE(static_cast<bool>(Accepted.AccountLease));
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U);
        Transport->Close();
        Peer->Close();
    }

    TEST(Socks5TypedHandoff, TypedAcceptKeepsDataPlanePostDialAsSingleContextOwner)
    {
        Net::io_context Io;
        auto [Transport, Peer] = MakeMemoryPairShared(Io);
        Preview::Contract::ProtocolDataPlane Result;
        Result.Root = Preview::Contract::StreamDataPlane{Transport};
        auto Accepted = std::move(Result);
        ASSERT_TRUE(Accepted.HasTransport());

        const auto CallbackCalled = std::make_shared<bool>(false);
        Accepted.PostDial = [CallbackCalled](Fault::Code) -> Net::awaitable<Fault::Code>
        {
            *CallbackCalled = true;
            co_return Fault::Code::Success;
        };
        auto Accept = MakeStubAccept(std::move(Accepted));
        Middleware::Context Context;
        SharedTransmission Inbound = Peer;

        RunCoro(Io, RunSocks5TypedContextFlow(
            Socks5TypedContextFlow{Accept, Inbound, Context}));

        EXPECT_TRUE(*CallbackCalled);
        const auto ContextTransport = Context.DataPlane.Transport();
        ASSERT_TRUE(ContextTransport);
        if (Context.Inbound()) Context.Inbound()->Close();
            Context.SetDataPlane({});
        EXPECT_FALSE(ContextTransport->IsOpen());
        Peer->Close();
    }


    struct Socks5TypedHandoffScenario final
    {
        Net::io_context &Io;
        std::shared_ptr<MemoryStream> Client;
        SharedTransmission &Inbound;
        Middleware::Context &Context;
        Fault::Code &Code;
        std::shared_ptr<HandshakeWatchdogState> Watchdog;
    };

    auto RunSocks5TypedHandoffScenario(Socks5TypedHandoffScenario &Scenario)
        -> Net::awaitable<void>
    {
                const std::vector<std::uint8_t> Greeting{0x05, 0x01, 0x02};
                if (!co_await WriteWire(Scenario.Client, AsWire(Greeting)))
                {
                    ADD_FAILURE() << "SOCKS5 greeting write failed";
                    co_await AbortHandshake(Scenario.Watchdog);
                    co_return;
                }
                std::array<std::byte, 2> Method{};
                if (!co_await ReadWire(Scenario.Client, Method))
                {
                    ADD_FAILURE() << "SOCKS5 method reply read failed";
                    co_await AbortHandshake(Scenario.Watchdog);
                    co_return;
                }
                EXPECT_EQ(std::to_integer<std::uint8_t>(Method[0]), 0x05);
                EXPECT_EQ(std::to_integer<std::uint8_t>(Method[1]), 0x02);

                const auto Credentials = MakeUserPass("account", "socks5-password");
                if (!co_await WriteWire(Scenario.Client, AsWire(Credentials)))
                {
                    ADD_FAILURE() << "SOCKS5 UserPass write failed";
                    co_await AbortHandshake(Scenario.Watchdog);
                    co_return;
                }
                std::array<std::byte, 2> AuthenticationReply{};
                if (!co_await ReadWire(Scenario.Client, AuthenticationReply))
                {
                    ADD_FAILURE() << "SOCKS5 UserPass reply read failed";
                    co_await AbortHandshake(Scenario.Watchdog);
                    co_return;
                }
                EXPECT_EQ(std::to_integer<std::uint8_t>(AuthenticationReply[1]), 0x00);

                const auto Request = MakeConnectRequest("example.com", 443);
                if (!co_await WriteWire(Scenario.Client, AsWire(Request)))
                {
                    ADD_FAILURE() << "SOCKS5 CONNECT write failed";
                    co_await AbortHandshake(Scenario.Watchdog);
                    co_return;
                }
                (void)co_await Scenario.Watchdog->AcceptWake->async_receive(Net::use_awaitable);
                co_await WaitForServerExit(Scenario.Watchdog);
                if (Scenario.Watchdog->TimedOut || Scenario.Watchdog->ServerFailed)
                {
                    ADD_FAILURE() << (Scenario.Watchdog->TimedOut
                                          ? "SOCKS5 UserPass/CONNECT handshake timed out"
                                          : "SOCKS5 accept coroutine failed");
                    co_await AbortHandshake(Scenario.Watchdog);
                    co_return;
                }
                EXPECT_EQ(Scenario.Code, Fault::Code::Success);
                EXPECT_TRUE(Scenario.Context.PostDial());
                EXPECT_EQ(&Scenario.Context.PostDial(), &Scenario.Context.DataPlane.PostDial);
                if (!Scenario.Context.PostDial())
                {
                    co_await AbortHandshake(Scenario.Watchdog);
                    co_return;
                }
                co_await Scenario.Context.PostDial()(Fault::Code::Success);

                std::array<std::byte, 10> Reply{};
                const auto ReplyRead = co_await ReadWire(Scenario.Client, Reply);
                EXPECT_TRUE(ReplyRead);
                if (!ReplyRead)
                {
                    co_await AbortHandshake(Scenario.Watchdog);
                    co_return;
                }
                if (Scenario.Watchdog->TimedOut)
                {
                    ADD_FAILURE() << "SOCKS5 deferred CONNECT reply timed out";
                    co_await AbortHandshake(Scenario.Watchdog);
                    co_return;
                }
                EXPECT_EQ(std::to_integer<std::uint8_t>(Reply[0]), 0x05);
                EXPECT_EQ(std::to_integer<std::uint8_t>(Reply[1]), 0x00);
                Scenario.Client->Close();
                co_await FinishHandshake(Scenario.Watchdog);

    }
    TEST(Socks5TypedHandoff, RealUserPassConnectTransfersLeaseAndReplyCallback)
    {
        Net::io_context Io;
        auto [Client, Server] = MakeMemoryPairShared(Io);
        const auto AccountId = Preview::AccountId{7302};
        auto Directory = MakeAccountRecord(AccountId, "socks5-password");
        const auto Record = Directory->Store->FindById(AccountId);
        ASSERT_TRUE(Record);

        Socks5::ServerConfig Config;
        Config.EnableTcp = true;
        Config.EnableUdp = false;
        Config.EnableAuth = true;
        Config.DeferConnectReply = true;
        Config.Authenticator = Directory->Authenticator;
        auto Accept = Preview::Testing::MakeSocks5Binding(std::move(Config));
        Middleware::Context Context;
        SharedTransmission Inbound = Server;
        Fault::Code Code = Fault::Code::IoError;
        const auto Watchdog =
            MakeHandshakeWatchdogState(Io, MemoryPair{Client, Server});
        StartHandshakeWatchdog(Watchdog, std::chrono::seconds{3});

        Net::co_spawn(
            Io.get_executor(),
            RunSocks5AcceptTask(Socks5AcceptTask{
                Accept, Inbound, Context, Code, Watchdog}),
            [Watchdog](const std::exception_ptr &ErrorValue)
            {
                if (ErrorValue)
                {
                    Watchdog->ServerFailed = true;
                }
            });

        Socks5TypedHandoffScenario Scenario{Io, Client, Inbound, Context, Code, Watchdog};
        RunCoro(Io, RunSocks5TypedHandoffScenario(Scenario));

        EXPECT_FALSE(Watchdog->TimedOut)
            << "watchdog must terminate stalled SOCKS5 success handshakes";
        if (Watchdog->TimedOut)
        {
            if (Context.Inbound()) Context.Inbound()->Close();
            Context.SetDataPlane({});
            return;
        }
        EXPECT_EQ(Code, Fault::Code::Success);
        if (Code != Fault::Code::Success || Watchdog->ServerFailed)
        {
            if (Context.Inbound()) Context.Inbound()->Close();
            Context.SetDataPlane({});
            return;
        }
        EXPECT_EQ(Context.AccountId(), AccountId);
        ASSERT_TRUE(Context.AccountLease());
        ASSERT_TRUE(static_cast<bool>(Context.DataPlane.AccountLease));
        EXPECT_TRUE(static_cast<bool>(Context.DataPlane.AccountLease));
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 1U);
        const auto Transport = Context.DataPlane.Transport();
        ASSERT_TRUE(Transport);
        EXPECT_TRUE(Transport->IsOpen());

        Context.AccountLease().Release();
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U);
        Io.restart();
        RunCoro(Io, [&Context, Transport]() -> Net::awaitable<void>
        {
            if (Context.Inbound()) Context.Inbound()->Close();
            Context.SetDataPlane({});
            co_await Net::post(Transport->Executor(), Net::use_awaitable);
            EXPECT_FALSE(Transport->IsOpen());
        }());
        Server->Close();
    }

    struct Socks5InvalidUserPassFlow final
    {
        std::shared_ptr<MemoryStream> Client;
        std::shared_ptr<HandshakeWatchdogState> Watchdog;
    };

    /** @brief 驱动无效 UserPass 握手并等待服务端真实退出。 */
    auto RunSocks5InvalidUserPassFlow(Socks5InvalidUserPassFlow Flow)
        -> Net::awaitable<void>
    {
        const std::vector<std::uint8_t> Greeting{0x05, 0x01, 0x02};
        const auto Credentials = MakeUserPass("account", "wrong-password");
        if (!co_await WriteWire(Flow.Client, AsWire(Greeting)))
        {
            ADD_FAILURE() << "SOCKS5 greeting write failed";
            co_await AbortHandshake(Flow.Watchdog);
            co_return;
        }
        std::array<std::byte, 2> Method{};
        if (!co_await ReadWire(Flow.Client, Method))
        {
            ADD_FAILURE() << "SOCKS5 method reply read failed";
            co_await AbortHandshake(Flow.Watchdog);
            co_return;
        }
        if (!co_await WriteWire(Flow.Client, AsWire(Credentials)))
        {
            ADD_FAILURE() << "SOCKS5 invalid UserPass write failed";
            co_await AbortHandshake(Flow.Watchdog);
            co_return;
        }
        std::array<std::byte, 2> AuthenticationReply{};
        const auto ReplyRead = co_await ReadWire(Flow.Client, AuthenticationReply);
        EXPECT_TRUE(ReplyRead);
        if (!ReplyRead)
        {
            co_await AbortHandshake(Flow.Watchdog);
            co_return;
        }
        EXPECT_EQ(std::to_integer<std::uint8_t>(AuthenticationReply[0]), 0x01);
        EXPECT_EQ(std::to_integer<std::uint8_t>(AuthenticationReply[1]), 0x01);
        co_await WaitForServerExit(Flow.Watchdog);
        if (Flow.Watchdog->TimedOut || Flow.Watchdog->ServerFailed)
        {
            ADD_FAILURE() << (Flow.Watchdog->TimedOut
                                  ? "SOCKS5 invalid UserPass handshake timed out"
                                  : "SOCKS5 accept coroutine failed");
            co_await AbortHandshake(Flow.Watchdog);
            co_return;
        }
        Flow.Client->Close();
        co_await FinishHandshake(Flow.Watchdog);
    }

    TEST(Socks5TypedHandoff, RealInvalidUserPassClosesAndReleasesLease)
    {
        Net::io_context Io;
        auto [Client, Server] = MakeMemoryPairShared(Io);
        auto Directory = MakeAccountRecord(Preview::AccountId{7303}, "valid-password");
        const auto Record = Directory->Store->FindById(Preview::AccountId{7303});
        ASSERT_TRUE(Record);

        Socks5::ServerConfig Config;
        Config.EnableTcp = true;
        Config.EnableUdp = false;
        Config.EnableAuth = true;
        Config.Authenticator = Directory->Authenticator;
        auto Accept = Preview::Testing::MakeSocks5Binding(std::move(Config));
        Middleware::Context Context;
        SharedTransmission Inbound = Server;
        Fault::Code Code = Fault::Code::IoError;
        const auto Watchdog =
            MakeHandshakeWatchdogState(Io, MemoryPair{Client, Server});
        StartHandshakeWatchdog(Watchdog, std::chrono::seconds{3});

        Net::co_spawn(
            Io.get_executor(),
            RunSocks5AcceptTask(Socks5AcceptTask{
                Accept, Inbound, Context, Code, Watchdog}),
            [Watchdog](const std::exception_ptr &ErrorValue)
            {
                if (ErrorValue)
                {
                    Watchdog->ServerFailed = true;
                }
            });

        RunCoro(Io, RunSocks5InvalidUserPassFlow(
            Socks5InvalidUserPassFlow{Client, Watchdog}));

        EXPECT_FALSE(Watchdog->TimedOut)
            << "watchdog must terminate stalled SOCKS5 auth failures";
        if (Watchdog->TimedOut)
        {
            if (Context.Inbound()) Context.Inbound()->Close();
            Context.SetDataPlane({});
            return;
        }
        EXPECT_EQ(Code, Fault::Code::AuthFailed);
        EXPECT_FALSE(Context.DataPlane.HasTransport());
        EXPECT_FALSE(Context.PostDial());
        EXPECT_FALSE(Context.AccountLease());
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U);
        EXPECT_FALSE(Server->IsOpen());
        Client->Close();
    }
} // namespace
