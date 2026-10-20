#include <TestSupport/Prism/ProviderBindings.hpp>
/**
 * @file Socks5TypedHandoffTest.cpp
 * @brief SOCKS5 typed data-plane handoff 的红灯回归测试
 * @details 锁定正式 SOCKS5 binding 到 ProtocolDataPlane、Context 的唯一
 *          move owner，以及真实 UserPass/CONNECT 握手的关闭和账户租约边界。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Account/Account.hpp>
#include <Prism/Contract/Ingress/StreamFactory.hpp>
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Protocols/Socks5/Socks5.hpp>
#include <Prism/Contract/Ingress/DataPlane.hpp>
#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/TransportResources.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Fault = Prism::Fault;
    namespace Middleware = Prism::Middleware;
    namespace Socks5 = Prism::Socks5;

    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;
    using Prism::SharedTransmission;
    using Prism::Testing::RunCoro;

    auto MakeSocks5AcceptInput(SharedTransmission Inbound)
        -> Prism::Contract::StreamAcceptInput
    {
        return {
            std::move(Inbound), {},
            std::make_shared<Prism::Memory::BytePool>(
                Prism::Memory::BytePoolOptions{.BlockCount = 8}),
            {}};
    }

    auto FinalizeSocks5Transport(Net::io_context &Io, SharedTransmission Transport) -> void
    {
        if (!Transport)
        {
            return;
        }
        if (Transport->IsOpen())
        {
            Prism::Testing::ExpectFixtureCloseReceipt(
                Prism::Testing::DriveClose(Io, std::move(Transport)));
            return;
        }
        EXPECT_TRUE(Prism::Testing::DriveDrain(Io, std::move(Transport)));
    }

    auto MakeSocks5BindingForDirectory(Net::io_context &Io,
        const std::shared_ptr<Prism::Testing::ProviderAccounts> &Directory,
        Socks5::ServerConfig Config) -> std::shared_ptr<Socks5::Binding>
    {
        auto Prepared = Socks5::Prepare(
            {"fixture", Directory->Generation, std::move(Config)},
            {Io.get_executor(),
                {Directory->Generation, Directory->Credentials, Directory->Authenticator}, {}});
        if (!Prepared)
        {
            throw std::runtime_error("SOCKS5 typed handoff fixture prepare failed");
        }
        auto Bound = Socks5::Bind(std::move(*Prepared), {});
        if (!Bound)
        {
            throw std::runtime_error("SOCKS5 typed handoff fixture bind failed");
        }
        return *Bound;
    }

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
        bool AcceptStarted{false};
        bool WatchdogStarted{false};
        bool WatchdogFailed{false};
        bool ServerExitObserved{false};
        bool WatchdogExitObserved{false};
        bool TimedOut{false};
        bool Finished{false};
        bool ClientCloseStarted{false};
        bool ServerCloseStarted{false};
    };

    auto CloseSocks5Transport(SharedTransmission Transport) -> Net::awaitable<void>
    {
        const auto Receipt = co_await Prism::Testing::CloseFixture(std::move(Transport));
        Prism::Testing::ExpectFixtureCloseReceipt(Receipt);
    }

    auto CloseHandshakeTransports(
        const std::shared_ptr<HandshakeWatchdogState> &State) -> Net::awaitable<void>
    {
        if (!State->ClientCloseStarted)
        {
            State->ClientCloseStarted = true;
            co_await CloseSocks5Transport(State->Client);
        }
        if (!State->ServerCloseStarted)
        {
            State->ServerCloseStarted = true;
            co_await CloseSocks5Transport(State->Server);
        }
    }

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
            co_await CloseHandshakeTransports(State);
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
            [State](const std::exception_ptr &ErrorValue)
            {
                if (ErrorValue)
                {
                    State->WatchdogFailed = true;
                    (void)State->WatchdogExited->try_send(
                        boost::system::error_code{}, true);
                }
            });
        State->WatchdogStarted = true;
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
        if (State->WatchdogStarted && !State->WatchdogExitObserved)
        {
            (void)co_await State->WatchdogExited->async_receive(Net::use_awaitable);
            State->WatchdogExitObserved = true;
        }
    }

    auto AbortHandshake(const std::shared_ptr<HandshakeWatchdogState> &State)
        -> Net::awaitable<void>
    {
        State->Finished = true;
        co_await CloseHandshakeTransports(State);
        State->Timer->cancel();
        if (State->AcceptStarted)
        {
            co_await WaitForServerExit(State);
        }
        if (State->WatchdogStarted && !State->WatchdogExitObserved)
        {
            (void)co_await State->WatchdogExited->async_receive(Net::use_awaitable);
            State->WatchdogExitObserved = true;
        }
    }

    auto AwaitSocks5BindingDrain(std::shared_ptr<Socks5::Binding> Binding,
        std::expected<void, Fault::Failure> &Receipt, bool &Completed)
        -> Net::awaitable<void>
    {
        Receipt = co_await Binding->Drain();
        Completed = true;
    }

    auto FinalizeSocks5Binding(Net::io_context &Io,
        const std::shared_ptr<Socks5::Binding> &Binding) noexcept -> void
    {
        if (!Binding) return;
        Binding->Close();
        std::expected<void, Fault::Failure> Receipt;
        bool Completed = false;
        try
        {
            Io.restart();
            RunCoro(Io, AwaitSocks5BindingDrain(Binding, Receipt, Completed));
        }
        catch (...) { ADD_FAILURE() << "SOCKS5 binding drain threw"; return; }
        EXPECT_TRUE(Completed) << "SOCKS5 binding drain did not complete";
        if (!Completed) return;
        if (!Receipt) ADD_FAILURE() << "SOCKS5 binding drain failed: code="
                                    << static_cast<unsigned>(Receipt.error().Code);
        EXPECT_TRUE(Binding->IsRetired());
    }

    struct Socks5ScenarioCleanupState final
    {
        Net::io_context &Io;
        std::shared_ptr<Socks5::Binding> Binding;
        Middleware::Context &Context;
        SharedTransmission Server;
        SharedTransmission Client;
        std::shared_ptr<HandshakeWatchdogState> Watchdog;
    };

    class Socks5ScenarioCleanup final
    {
    public:
        explicit Socks5ScenarioCleanup(Socks5ScenarioCleanupState State)
            : State_(std::move(State))
        {
        }

        ~Socks5ScenarioCleanup()
        {
            Finalize();
        }

        auto Finalize() noexcept -> void
        {
            if (Finalized_)
            {
                return;
            }
            Finalized_ = true;
            if (!State_.Watchdog->Finished)
            {
                try
                {
                    State_.Io.restart();
                    RunCoro(State_.Io, AbortHandshake(State_.Watchdog));
                }
                catch (...) { ADD_FAILURE() << "SOCKS5 handshake abort cleanup failed"; }
            }
            EXPECT_FALSE(State_.Watchdog->WatchdogFailed);
            const auto Finalize = [this](SharedTransmission Transport)
            {
                try { FinalizeSocks5Transport(State_.Io, std::move(Transport)); }
                catch (...) { ADD_FAILURE() << "SOCKS5 transport finalization failed"; }
            };
            Finalize(State_.Context.DataPlane.Transport());
            State_.Context.SetDataPlane({});
            Finalize(State_.Server);
            Finalize(State_.Client);
            FinalizeSocks5Binding(State_.Io, State_.Binding);
        }

    private:
        Socks5ScenarioCleanupState State_;
        bool Finalized_{false};
    };

    auto MakeMemoryPairShared(Net::io_context &Io)
        -> MemoryPair
    {
        auto [A, B] = MakeMemoryPair(Io.get_executor());
        return {std::make_shared<MemoryStream>(std::move(A)),
                std::make_shared<MemoryStream>(std::move(B))};
    }

    auto MakeAccountRecord(Prism::AccountId AccountId, std::string_view Password)
        -> std::shared_ptr<Prism::Testing::ProviderAccounts>
    {
        return Prism::Testing::ProviderAccount(
            Prism::Account::Credential::Password(Password), AccountId,
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
        ErrorCode = Prism::Fault::ToNative(Written.Failure);
        co_return !ErrorCode && Written.Bytes == Wire.size();
    }

    auto ReadWire(SharedTransmission Connection, std::span<std::byte> Wire)
        -> Net::awaitable<bool>
    {
        std::error_code ErrorCode;
        const auto Read = co_await Connection->ReadExact(Wire);
        ErrorCode = Prism::Fault::ToNative(Read.Failure);
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

    class StubHandler final : public Prism::Contract::StreamFactory
    {
    public:
        explicit StubHandler(Prism::Contract::ProtocolDataPlane Result)
            : Result_(std::move(Result))
        {
        }

        auto Accept(Prism::Contract::StreamAcceptInput Input)
            -> Net::awaitable<Prism::Contract::AcceptOutcome> override
        {
            (void)Input;
            co_return std::move(Result_);
        }

        [[nodiscard]] auto Name() const -> std::string_view override
        {
            return "socks5-typed-handoff-stub";
        }

    private:
        Prism::Contract::ProtocolDataPlane Result_;
    };

    auto MakeStubAccept(Prism::Contract::ProtocolDataPlane Result)
        -> std::shared_ptr<Prism::Contract::StreamFactory>
    {
        return std::make_shared<StubHandler>(std::move(Result));
    }

    struct Socks5TypedContextFlow final
    {
        std::shared_ptr<Prism::Contract::StreamFactory> Accept;
        SharedTransmission &Inbound;
        Middleware::Context &Context;
    };

    /** @brief 验证 typed DataPlane 转移后 PostDial 仍由唯一 Context 持有。 */
    auto RunSocks5TypedContextFlow(Socks5TypedContextFlow Flow)
        -> Net::awaitable<void>
    {
        auto Accepted = co_await Flow.Accept->Accept(
            MakeSocks5AcceptInput(std::move(Flow.Inbound)));
        const auto Code = Accepted ? Prism::Fault::Code::Success
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
            const auto PostDialFailure = co_await Flow.Context.PostDial()(Fault::Failure{});
            EXPECT_TRUE(PostDialFailure.Succeeded());
        }
    }

    struct Socks5AcceptTask final
    {
        std::shared_ptr<Prism::Contract::StreamFactory> Accept;
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
            auto Accepted = co_await Flow.Accept->Accept(
                MakeSocks5AcceptInput(std::move(Flow.Inbound)));
            Flow.Code = Accepted ? Prism::Fault::Code::Success
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

    TEST(Socks5TypedHandoff, TypedAcceptKeepsDataPlanePostDialAsSingleContextOwner)
    {
        Net::io_context Io;
        auto [Transport, Peer] = MakeMemoryPairShared(Io);
        Prism::Contract::ProtocolDataPlane Result;
        Result.Root = Prism::Contract::StreamDataPlane{Transport};
        auto Accepted = std::move(Result);
        ASSERT_TRUE(Accepted.HasTransport());

        const auto CallbackCalled = std::make_shared<bool>(false);
        Accepted.PostDial = [CallbackCalled](Fault::Failure) -> Net::awaitable<Fault::Failure>
        {
            *CallbackCalled = true;
            co_return Fault::Failure{};
        };
        auto Accept = MakeStubAccept(std::move(Accepted));
        Middleware::Context Context;
        SharedTransmission Inbound = Peer;

        RunCoro(Io, RunSocks5TypedContextFlow(
            Socks5TypedContextFlow{Accept, Inbound, Context}));

        EXPECT_TRUE(*CallbackCalled);
        const auto ContextTransport = Context.DataPlane.Transport();
        ASSERT_TRUE(ContextTransport);
        FinalizeSocks5Transport(Io, ContextTransport);
        Context.SetDataPlane({});
        EXPECT_FALSE(ContextTransport->IsOpen());
        FinalizeSocks5Transport(Io, Peer);
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

                const auto Credentials = MakeUserPass("provider-fixture", "socks5-password");
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
                const auto PostDialFailure = co_await Scenario.Context.PostDial()(Fault::Failure{});
                EXPECT_TRUE(PostDialFailure.Succeeded());

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
                co_await FinishHandshake(Scenario.Watchdog);

    }
    TEST(Socks5TypedHandoff, RealUserPassConnectTransfersLeaseAndReplyCallback)
    {
        Net::io_context Io;
        auto [Client, Server] = MakeMemoryPairShared(Io);
        const auto AccountId = Prism::AccountId{7302};
        auto Directory = MakeAccountRecord(AccountId, "socks5-password");
        const auto Record = Directory->Store->FindById(AccountId);
        ASSERT_TRUE(Record);

        Socks5::ServerConfig Config;
        Config.EnableTcp = true;
        Config.EnableUdp = false;
        Config.EnableAuth = true;
        Config.DeferConnectReply = true;
        Config.Authenticator = Directory->Authenticator;
        auto Accept = MakeSocks5BindingForDirectory(Io, Directory, std::move(Config));
        Middleware::Context Context;
        SharedTransmission Inbound = Server;
        Fault::Code Code = Fault::Code::IoError;
        const auto Watchdog =
            MakeHandshakeWatchdogState(Io, MemoryPair{Client, Server});
        Socks5ScenarioCleanup Cleanup({Io, Accept, Context, Server, Client, Watchdog});
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
        Watchdog->AcceptStarted = true;

        Socks5TypedHandoffScenario Scenario{Io, Client, Inbound, Context, Code, Watchdog};
        RunCoro(Io, RunSocks5TypedHandoffScenario(Scenario));

        EXPECT_FALSE(Watchdog->TimedOut)
            << "watchdog must terminate stalled SOCKS5 success handshakes";
        if (Watchdog->TimedOut)
        {
            Cleanup.Finalize();
            return;
        }
        EXPECT_EQ(Code, Fault::Code::Success);
        if (Code != Fault::Code::Success || Watchdog->ServerFailed)
        {
            Cleanup.Finalize();
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
        Cleanup.Finalize();
        EXPECT_FALSE(Transport->IsOpen());
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
        const auto Credentials = MakeUserPass("provider-fixture", "wrong-password");
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
        co_await FinishHandshake(Flow.Watchdog);
    }

    TEST(Socks5TypedHandoff, RealInvalidUserPassClosesAndReleasesLease)
    {
        Net::io_context Io;
        auto [Client, Server] = MakeMemoryPairShared(Io);
        auto Directory = MakeAccountRecord(Prism::AccountId{7303}, "valid-password");
        const auto Record = Directory->Store->FindById(Prism::AccountId{7303});
        ASSERT_TRUE(Record);

        Socks5::ServerConfig Config;
        Config.EnableTcp = true;
        Config.EnableUdp = false;
        Config.EnableAuth = true;
        Config.Authenticator = Directory->Authenticator;
        auto Accept = MakeSocks5BindingForDirectory(Io, Directory, std::move(Config));
        Middleware::Context Context;
        SharedTransmission Inbound = Server;
        Fault::Code Code = Fault::Code::IoError;
        const auto Watchdog =
            MakeHandshakeWatchdogState(Io, MemoryPair{Client, Server});
        Socks5ScenarioCleanup Cleanup({Io, Accept, Context, Server, Client, Watchdog});
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
        Watchdog->AcceptStarted = true;

        RunCoro(Io, RunSocks5InvalidUserPassFlow(
            Socks5InvalidUserPassFlow{Client, Watchdog}));

        EXPECT_FALSE(Watchdog->TimedOut)
            << "watchdog must terminate stalled SOCKS5 auth failures";
        if (Watchdog->TimedOut)
        {
            Cleanup.Finalize();
            return;
        }
        EXPECT_EQ(Code, Fault::Code::AuthFailed);
        EXPECT_FALSE(Context.DataPlane.HasTransport());
        EXPECT_FALSE(Context.PostDial());
        EXPECT_FALSE(Context.AccountLease());
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U);
        EXPECT_FALSE(Server->IsOpen())
            << "SOCKS5 admission must close inbound after authentication failure";
        Cleanup.Finalize();
    }
} // namespace
