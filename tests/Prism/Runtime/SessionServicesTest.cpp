/**
 * @file SessionServicesTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "SessionLifecycleTestSupport.hpp"

#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>

#include <exception>
#include <expected>
#include <memory>
#include <system_error>
#include <utility>

namespace
{
    auto MakeSessionOptions(Net::any_io_executor Executor)
        -> Prism::Runtime::SessionOptions
    {
        Prism::Runtime::SessionOptions Options;
        Options.Services->Bytes = std::make_shared<Prism::Memory::BytePool>();
        Options.Control = std::make_shared<Prism::Runtime::SessionControl>(
            std::move(Executor));
        return Options;
    }

    struct MuxRunGate final
    {
        std::shared_ptr<ByteChannel> Started;
        std::shared_ptr<ByteChannel> Release;
        bool WorkCompleted{false};
    };

    struct MuxActivityScenario final
    {
        Net::io_context &Io;
        std::shared_ptr<Prism::Testing::MuxSession> Mux;
        std::shared_ptr<MuxRunGate> Gate;
        std::shared_ptr<ByteChannel> RunFinished;
        std::shared_ptr<ByteChannel> DrainFinished;
        std::expected<void, Prism::Fault::Failure> RunResult{
            std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::GenericError})};
        std::expected<void, Prism::Fault::Failure> DrainResult{
            std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::GenericError})};
        std::exception_ptr RunFailure;
        std::exception_ptr DrainFailure;
        bool RunReturned{false};
        bool DrainReturned{false};
        bool DrainPendingBeforeRelease{false};
    };

    struct DatagramRunGate final
    {
        std::shared_ptr<ByteChannel> Started;
        std::shared_ptr<ByteChannel> Release;
        bool WorkCompleted{false};
    };

    struct DatagramActivityScenario final
    {
        Net::io_context &Io;
        std::shared_ptr<Prism::Testing::DatagramSession> Datagram;
        std::shared_ptr<Prism::MemoryStream> Transport;
        std::shared_ptr<DatagramRunGate> Gate;
        std::shared_ptr<ByteChannel> RunFinished;
        std::shared_ptr<ByteChannel> DrainFinished;
        std::expected<void, Prism::Fault::Failure> RunResult{
            std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::GenericError})};
        std::expected<void, Prism::Fault::Failure> DrainResult{
            std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::GenericError})};
        std::exception_ptr RunFailure;
        std::exception_ptr DrainFailure;
        bool RunReturned{false};
        bool DrainReturned{false};
        bool DrainPendingBeforeRelease{false};
    };

    auto WaitForDatagramRelease(std::shared_ptr<DatagramRunGate> Gate)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        (void)Gate->Started->try_send(boost::system::error_code{});
        boost::system::error_code Error;
        co_await Gate->Release->async_receive(Net::redirect_error(Net::use_awaitable, Error));
        Gate->WorkCompleted = !Error;

        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto RunDatagramActivityScenario(std::shared_ptr<DatagramActivityScenario> Scenario)
        -> Net::awaitable<void>
    {
        Net::co_spawn(Scenario->Io, Scenario->Datagram->Run(),
            [&Scenario](std::exception_ptr Failure, std::expected<void, Prism::Fault::Failure> Result)
            {
                Scenario->RunFailure = std::move(Failure);
                Scenario->RunResult = std::move(Result);
                Scenario->RunReturned = true;
                (void)Scenario->RunFinished->try_send(boost::system::error_code{});
            });
        co_await Scenario->Gate->Started->async_receive(Net::use_awaitable);
        Scenario->Datagram->Close();
        Net::co_spawn(Scenario->Io, Scenario->Datagram->Activity()->Drain(),
            [&Scenario](std::exception_ptr Failure,
                std::expected<void, Prism::Fault::Failure> Result)
            {
                Scenario->DrainFailure = std::move(Failure);
                Scenario->DrainResult = std::move(Result);
                Scenario->DrainReturned = true;
                (void)Scenario->DrainFinished->try_send(boost::system::error_code{});
            });
        co_await Net::post(Scenario->Io, Net::use_awaitable);
        Scenario->DrainPendingBeforeRelease = !Scenario->DrainReturned;
        (void)Scenario->Gate->Release->try_send(boost::system::error_code{});
        co_await Scenario->RunFinished->async_receive(Net::use_awaitable);
        co_await Scenario->DrainFinished->async_receive(Net::use_awaitable);
    }

    auto WaitForMuxRelease(std::shared_ptr<MuxRunGate> Gate)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        (void)Gate->Started->try_send(boost::system::error_code{});
        boost::system::error_code Error;
        co_await Gate->Release->async_receive(Net::redirect_error(Net::use_awaitable, Error));
        Gate->WorkCompleted = !Error;
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto RunMuxActivityScenario(std::shared_ptr<MuxActivityScenario> Scenario)
        -> Net::awaitable<void>
    {
        Net::co_spawn(Scenario->Io, Scenario->Mux->Run({}),
            [&Scenario](std::exception_ptr Failure,
                std::expected<void, Prism::Fault::Failure> Result)
            {
                Scenario->RunFailure = std::move(Failure);
                Scenario->RunResult = std::move(Result);
                Scenario->RunReturned = true;
                (void)Scenario->RunFinished->try_send(boost::system::error_code{});
            });
        co_await Scenario->Gate->Started->async_receive(Net::use_awaitable);
        Scenario->Mux->Close();
        Net::co_spawn(Scenario->Io, Scenario->Mux->Drain(),
            [&Scenario](std::exception_ptr Failure,
                std::expected<void, Prism::Fault::Failure> Result)
            {
                Scenario->DrainFailure = std::move(Failure);
                Scenario->DrainResult = std::move(Result);
                Scenario->DrainReturned = true;
                (void)Scenario->DrainFinished->try_send(boost::system::error_code{});
            });
        co_await Net::post(Scenario->Io, Net::use_awaitable);
        Scenario->DrainPendingBeforeRelease = !Scenario->DrainReturned;
        (void)Scenario->Gate->Release->try_send(boost::system::error_code{});
        co_await Scenario->RunFinished->async_receive(Net::use_awaitable);
        co_await Scenario->DrainFinished->async_receive(Net::use_awaitable);
    }

    auto AcceptTypedDatagram(
        std::shared_ptr<bool> ServiceCalled,
        Prism::SharedTransmission Inbound)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        Prism::Contract::DatagramDataPlane Datagram;
        Datagram.Transport = Inbound;
        Datagram.Session = std::make_shared<Prism::Testing::DatagramSession>(
            Inbound,
            [ServiceCalled]() -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
            {
                *ServiceCalled = true;
                co_return std::expected<void, Prism::Fault::Failure>{};
            });
        Prism::Contract::ProtocolDataPlane Plane;
        Plane.Root = std::move(Datagram);
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(std::move(Inbound));
        if (!Prepared)
        {
            co_return std::unexpected(Prepared.error());
        }
        co_return co_await Prepared->Admit(std::move(Plane));
    }

    struct TypedDatagramFactory final
    {
        std::shared_ptr<bool> ServiceCalled;

        auto operator()(Prism::Contract::StreamAcceptInput Input) const
            -> Net::awaitable<Prism::Contract::AcceptOutcome>
        {
            return AcceptTypedDatagram(ServiceCalled, std::move(Input.Inbound));
        }
    };

    struct TypedDatagramRequest final
    {
        std::shared_ptr<Prism::Runtime::Session> Session;
        std::shared_ptr<Prism::MemoryStream> Client;
        std::shared_ptr<Prism::MemoryStream> Server;
    };

    auto RunTypedDatagram(TypedDatagramRequest Request) -> Net::awaitable<void>
    {
        const std::string Greeting("\x05\x01\x00", 3);
        std::error_code ErrorCode;
        const auto Write = co_await Request.Client->WriteSome(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Greeting.data()), Greeting.size()));
        ErrorCode = Prism::Fault::ToNative(Write.Failure);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ((co_await Request.Session->Run(Request.Server)).Code,
                  Prism::Fault::Code::Success);
    }

    struct TypedMuxRootRequest final
    {
        std::shared_ptr<bool> MuxCalled;
        std::shared_ptr<Prism::Fault::Failure> RunFailure;
        Prism::Contract::MuxRootRequest Root;
    };

    auto RunTypedMuxRoot(TypedMuxRootRequest Request)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        if (!Request.Root.GenerationUseState)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        auto Lease = Request.Root.GenerationUseState->Acquire();
        if (!Lease)
        {
            co_return std::unexpected(Lease.error());
        }
        *Request.MuxCalled = true;
        if (Request.RunFailure && Request.RunFailure->Failed())
        {
            co_return std::unexpected(*Request.RunFailure);
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto AcceptTypedMux(
        std::shared_ptr<bool> MuxCalled,
        std::shared_ptr<Prism::Fault::Failure> RunFailure,
        Prism::SharedTransmission Inbound)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Inbound);
        if (!Prepared)
        {
            co_return std::unexpected(Prepared.error());
        }
        auto Admission = std::move(*Prepared);
        std::array<std::byte, 1> Probe{};
        const auto Read = co_await Inbound->ReadExact(Probe);
        if (Read.Failure.Failed())
        {
            co_return co_await Admission.Reject(Read.Failure);
        }
        Prism::Contract::ProtocolDataPlane Plane;
        Plane.Root = Prism::Contract::MuxRootDataPlane{
            Inbound,
            std::make_shared<Prism::Testing::MuxSession>(
                Inbound,
                [MuxCalled, RunFailure](Prism::Contract::MuxRootRequest Request)
                { return RunTypedMuxRoot(TypedMuxRootRequest{
                    MuxCalled, RunFailure, std::move(Request)}); })};
        co_return co_await Admission.Admit(std::move(Plane));
    }

    struct TypedMuxFactory final
    {
        std::shared_ptr<bool> MuxCalled;
        std::shared_ptr<Prism::Fault::Failure> RunFailure;

        auto operator()(Prism::Contract::StreamAcceptInput Input) const
            -> Net::awaitable<Prism::Contract::AcceptOutcome>
        {
            return AcceptTypedMux(MuxCalled, RunFailure, std::move(Input.Inbound));
        }
    };

    struct TypedMuxSessionRequest final
    {
        Prism::Runtime::SessionOptions Options;
        Prism::SharedTransmission Inbound;
        std::shared_ptr<ByteChannel> Done;
        std::shared_ptr<Prism::Fault::Failure> Result;
    };

    auto RunTypedMuxSession(TypedMuxSessionRequest Request) -> Net::awaitable<void>
    {
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
        if (Request.Options.Services)
        {
            UseState = Request.Options.Services->GenerationUseState;
        }
        if (!UseState)
        {
            *Request.Result = Prism::Fault::Failure{Prism::Fault::Code::Blocked};
            (void)Request.Done->try_send(boost::system::error_code{});
            co_return;
        }
        auto Lease = UseState->Acquire();
        if (!Lease)
        {
            *Request.Result = Lease.error();
            (void)Request.Done->try_send(boost::system::error_code{});
            co_return;
        }
        {
            Prism::Runtime::Session Session(std::move(Request.Options));
            if (!Session.SetGenerationUseLease(std::move(*Lease)))
            {
                *Request.Result = Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument};
            }
            else
            {
                *Request.Result = co_await Session.Run(Request.Inbound);
            }
        }
        (void)Request.Done->try_send(boost::system::error_code{});
    }

    struct TypedMuxRequest final
    {
        Net::any_io_executor Executor;
        std::shared_ptr<Prism::MemoryStream> Client;
        Prism::SharedTransmission Inbound;
        std::shared_ptr<ByteChannel> Done;
        std::shared_ptr<Prism::Fault::Failure> Result;
        Prism::Runtime::SessionOptions Options;
    };

    auto RunTypedMux(TypedMuxRequest Request) -> Net::awaitable<void>
    {
        Net::co_spawn(
            Request.Executor,
            RunTypedMuxSession(TypedMuxSessionRequest{
                std::move(Request.Options), Request.Inbound, Request.Done, Request.Result}),
            Net::detached);

        const std::string RequestText =
            "GET http://example.com:80/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        std::error_code WriteError;
        const auto Bytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(RequestText.data()), RequestText.size());
        const auto Written = co_await Request.Client->WriteSome(Bytes);
        WriteError = Prism::Fault::ToNative(Written.Failure);
        EXPECT_FALSE(WriteError);
        boost::system::error_code DoneError;
        co_await Request.Done->async_receive(
            Net::redirect_error(Net::use_awaitable, DoneError));
    }

    auto HoldSessionChildUntilReleased(
        std::shared_ptr<ByteChannel> Started,
        std::shared_ptr<ByteChannel> Release,
        std::shared_ptr<bool> Completed) -> Net::awaitable<void>
    {
        (void)Started->try_send(boost::system::error_code{});
        co_await WaitForRelease(Release);
        *Completed = true;
    }

    struct SessionGenerationRunState final
    {
        bool Completed{false};
        std::exception_ptr Exception;
        Prism::Fault::Failure Result;
    };

    struct SessionGenerationDrainRequest final
    {
        Net::io_context &Io;
        std::shared_ptr<Prism::Runtime::Session> Session;
        std::shared_ptr<Prism::MemoryStream> Inbound;
        std::shared_ptr<ByteChannel> ChildStarted;
        std::shared_ptr<ByteChannel> ChildRelease;
        std::shared_ptr<bool> ChildCompleted;
        std::shared_ptr<ByteChannel> RunDone;
        std::shared_ptr<SessionGenerationRunState> RunState;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
    };

    auto AwaitSessionGenerationControlDrain(SessionGenerationDrainRequest Request)
        -> Net::awaitable<void>
    {
        Net::co_spawn(Request.Io, Request.Session->Run(Request.Inbound),
            [RunState = Request.RunState, RunDone = Request.RunDone](
                std::exception_ptr Error, Prism::Fault::Failure Result)
            {
                RunState->Exception = std::move(Error);
                RunState->Result = Result;
                RunState->Completed = true;
                (void)RunDone->try_send(boost::system::error_code{});
            });
        boost::system::error_code Error;
        co_await Request.ChildStarted->async_receive(
            Net::redirect_error(Net::use_awaitable, Error));
        EXPECT_FALSE(Error);
        Net::steady_timer ReleaseDelay(Request.Io);
        ReleaseDelay.expires_after(std::chrono::milliseconds(30));
        co_await ReleaseDelay.async_wait(Net::use_awaitable);
        EXPECT_FALSE(Request.RunState->Completed);
        EXPECT_FALSE(*Request.ChildCompleted);
        EXPECT_EQ(Request.UseState->Outstanding(), 1U);
        (void)Request.ChildRelease->try_send(boost::system::error_code{});
        const auto RunFinished = co_await WaitForSignalOrTimeout(Request.RunDone, Request.Io);
        EXPECT_TRUE(RunFinished);
    }

    auto AcceptTypedAccountDatagram(
        std::shared_ptr<Prism::Account::AccountLease> LeaseOwner,
        Prism::SharedTransmission Inbound)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Inbound);
        if (!Prepared)
        {
            co_return std::unexpected(Prepared.error());
        }
        Prism::Contract::DatagramDataPlane Datagram;
        Datagram.Transport = Inbound;
        Datagram.Session = std::make_shared<Prism::Testing::DatagramSession>(
            Inbound,
            []() -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
            {
                co_return std::expected<void, Prism::Fault::Failure>{};
            });
        Prism::Contract::ProtocolDataPlane Plane;
        Plane.Root = std::move(Datagram);
        Plane.AccountId = Prism::AccountId{88};
        Plane.AccountLease = std::move(*LeaseOwner);
        co_return co_await Prepared->Admit(std::move(Plane));
    }

    struct TypedAccountDatagramFactory final
    {
        std::shared_ptr<Prism::Account::AccountLease> LeaseOwner;

        auto operator()(Prism::Contract::StreamAcceptInput Input) const
            -> Net::awaitable<Prism::Contract::AcceptOutcome>
        {
            return AcceptTypedAccountDatagram(LeaseOwner, std::move(Input.Inbound));
        }
    };

    struct TypedAccountDatagramRequest final
    {
        std::shared_ptr<Prism::Runtime::Session> Session;
        std::shared_ptr<Prism::MemoryStream> Client;
        std::shared_ptr<Prism::MemoryStream> Server;
    };

    auto RunTypedAccountDatagram(TypedAccountDatagramRequest Request)
        -> Net::awaitable<void>
    {
        const std::string Greeting("\x05\x01\x00", 3);
        std::error_code ErrorCode;
        const auto Write = co_await Request.Client->WriteSome(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Greeting.data()), Greeting.size()));
        ErrorCode = Prism::Fault::ToNative(Write.Failure);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ((co_await Request.Session->Run(Request.Server)).Code,
                  Prism::Fault::Code::Success);
    }
}

TEST(SessionServicesLifecycle, CompletedSessionReleasesControlOwner)
    {
        Net::io_context Io;
        auto [Raw, Peer] = Prism::MakeMemoryPair(Io.get_executor());
        auto Inbound = std::make_shared<Prism::MemoryStream>(std::move(Raw));
        auto Control = std::make_shared<Prism::Runtime::SessionControl>(Io.get_executor());
        const std::weak_ptr<Prism::Runtime::SessionControl> WeakControl = Control;
        Prism::Runtime::SessionOptions Options;
        Options.Services->Bytes = std::make_shared<Prism::Memory::BytePool>();
        Options.Control = Control;
        Options.Services->AcceptProtocol = std::make_shared<Prism::Testing::StreamFactory>(
            [](Prism::Contract::StreamAcceptInput)
                -> Net::awaitable<Prism::Contract::AcceptOutcome>
            { co_return std::unexpected(
                Prism::Contract::FailureFromProtocolError(Prism::Error::BadAuth)); });
        auto Session = std::make_shared<Prism::Runtime::Session>(std::move(Options));
        const std::weak_ptr<Prism::Runtime::Session> WeakSession = Session;
        // RunCoro 返回前完整等待，Session/Control 的借用不会跨出调用边界。
        RunCoro(Io, [&]() -> Net::awaitable<void>
        {
            EXPECT_EQ((co_await Session->Run(Inbound)).Code, Prism::Fault::Code::AuthFailed);
            EXPECT_FALSE(Inbound->IsOpen());
            Session.reset();
            Control.reset();
            co_await Net::post(Io, Net::use_awaitable);
            EXPECT_TRUE(WeakSession.expired());
            EXPECT_TRUE(WeakControl.expired());
        });
    }

TEST(SessionServicesLifecycle, TrafficOwnerOutlivesCallerForDetachedChildren)
    {
        auto Traffic = std::make_shared<OwnedTrafficSink>();
        const std::weak_ptr<OwnedTrafficSink> WeakTraffic = Traffic;
        Prism::Middleware::Context Context;
        Context.Traffic = Traffic;

        Traffic.reset();

        ASSERT_FALSE(WeakTraffic.expired());
        ASSERT_TRUE(Context.Traffic);
        EXPECT_FALSE(Context.Traffic == nullptr);

        Context.Traffic.reset();
        EXPECT_TRUE(WeakTraffic.expired());
    }

TEST(SessionDataPlane, ProtocolPlaneUsesTypedRootAndAccountIdentity)
    {
        Net::io_context Ioc;
        auto [Raw, Peer] = Prism::MakeMemoryPair(Ioc.get_executor());
        auto Transport = std::make_shared<Prism::MemoryStream>(std::move(Raw));

        Prism::Contract::ProtocolDataPlane Plane;
        Plane.AccountId = Prism::AccountId{42};
        Plane.Root = Prism::Contract::StreamDataPlane{Transport};

        EXPECT_TRUE(Plane.IsStream());
        EXPECT_FALSE(Plane.IsDatagram());
        ASSERT_TRUE(Plane.Stream());
        EXPECT_EQ(Plane.Stream()->Transport.get(), Transport.get());
        EXPECT_EQ(Plane.AccountId.Value(), 42U);

        Prism::Contract::DatagramDataPlane Datagram;
        Datagram.Transport = std::make_shared<Prism::MemoryStream>(std::move(Peer));
        Plane.Root = std::move(Datagram);

        EXPECT_FALSE(Plane.IsStream());
        EXPECT_TRUE(Plane.IsDatagram());
        ASSERT_TRUE(Plane.Datagram());
        EXPECT_TRUE(Plane.Datagram()->Transport);
    }

TEST(SessionDataPlane, SessionRunsTypedDatagramServiceWithoutLegacyFlag)
    {
        Net::io_context Ioc;
        auto [ClientRaw, ServerRaw] = Prism::MakeMemoryPair(Ioc.get_executor());
        auto Client = std::make_shared<Prism::MemoryStream>(std::move(ClientRaw));
        auto Server = std::make_shared<Prism::MemoryStream>(std::move(ServerRaw));
        auto ServiceCalled = std::make_shared<bool>(false);

        auto Options = MakeSessionOptions(Ioc.get_executor());
        Options.Services->AcceptProtocol = std::make_shared<Prism::Testing::StreamFactory>(
            TypedDatagramFactory{ServiceCalled});
        auto Session = std::make_shared<Prism::Runtime::Session>(std::move(Options));

        Prism::Testing::RunCoro(Ioc, RunTypedDatagram(
                                             TypedDatagramRequest{Session, Client, Server}));

        EXPECT_TRUE(*ServiceCalled);
    }

TEST(SessionDataPlane, SessionRunsTypedMuxServiceWithoutDial)
    {
        Net::io_context Ioc;
        auto [ClientRaw, ServerRaw] = Prism::MakeMemoryPair(Ioc.get_executor());
        auto Client = std::make_shared<Prism::MemoryStream>(std::move(ClientRaw));
        auto Inbound = std::make_shared<Prism::MemoryStream>(std::move(ServerRaw));
        auto Done = std::make_shared<ByteChannel>(Ioc.get_executor(), 1);
        auto MuxCalled = std::make_shared<bool>(false);
        auto Result = std::make_shared<Prism::Fault::Failure>(
            Prism::Fault::Code::IoError);

        auto Options = MakeSessionOptions(Ioc.get_executor());
        auto UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
        Options.Services->GenerationUseState = UseState;
        Options.Services->AcceptProtocol = std::make_shared<Prism::Testing::StreamFactory>(
            TypedMuxFactory{MuxCalled});

        RunCoro(Ioc, RunTypedMux(TypedMuxRequest{
                            Ioc.get_executor(), Client, Inbound, Done, Result,
                            std::move(Options)}));

        EXPECT_EQ(Result->Code, Prism::Fault::Code::Success);
        EXPECT_TRUE(*MuxCalled);
        EXPECT_EQ(UseState->Outstanding(), 0U);
    }

TEST(SessionDataPlane, MuxFailurePreservesNativeCauseThroughSessionCleanup)
    {
        Net::io_context Ioc;
        auto [ClientRaw, ServerRaw] = Prism::MakeMemoryPair(Ioc.get_executor());
        auto Client = std::make_shared<Prism::MemoryStream>(std::move(ClientRaw));
        auto Inbound = std::make_shared<Prism::MemoryStream>(std::move(ServerRaw));
        auto Done = std::make_shared<ByteChannel>(Ioc.get_executor(), 1);
        auto MuxCalled = std::make_shared<bool>(false);
        const auto Native = std::make_error_code(std::errc::connection_reset);
        auto MuxFailure = std::make_shared<Prism::Fault::Failure>(
            Prism::Fault::FromNative(Native));
        auto Result = std::make_shared<Prism::Fault::Failure>();

        auto Options = MakeSessionOptions(Ioc.get_executor());
        auto UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
        Options.Services->GenerationUseState = UseState;
        Options.Services->AcceptProtocol = std::make_shared<Prism::Testing::StreamFactory>(
            TypedMuxFactory{MuxCalled, MuxFailure});

        RunCoro(Ioc, RunTypedMux(TypedMuxRequest{
            Ioc.get_executor(), Client, Inbound, Done, Result, std::move(Options)}));

        EXPECT_TRUE(*MuxCalled);
        EXPECT_EQ(Result->Code, MuxFailure->Code);
        EXPECT_EQ(Result->Native, Native);
        EXPECT_EQ(UseState->Outstanding(), 0U);
    }

TEST(SessionDataPlane, MuxActivityTracksRunUntilCloseDrainReceipt)
    {
        Net::io_context Io;
        auto [Raw, Peer] = Prism::MakeMemoryPair(Io.get_executor());
        auto Transport = std::make_shared<Prism::MemoryStream>(std::move(Raw));
        auto Gate = std::make_shared<MuxRunGate>();
        Gate->Started = MakeReleaseChannel(Io.get_executor());
        Gate->Release = MakeReleaseChannel(Io.get_executor());
        auto Mux = std::make_shared<Prism::Testing::MuxSession>(Transport,
            [Gate](Prism::Contract::MuxRootRequest)
            { return WaitForMuxRelease(Gate); });
        auto Scenario = std::make_shared<MuxActivityScenario>(MuxActivityScenario{
            Io, Mux, Gate, MakeReleaseChannel(Io.get_executor()),
            MakeReleaseChannel(Io.get_executor())});

        RunCoro(Io, RunMuxActivityScenario(Scenario));

        EXPECT_FALSE(Scenario->RunFailure);
        EXPECT_FALSE(Scenario->DrainFailure);
        EXPECT_TRUE(Scenario->RunResult);
        EXPECT_TRUE(Scenario->DrainResult.has_value());
        EXPECT_TRUE(Scenario->RunReturned);
        EXPECT_TRUE(Scenario->DrainReturned);
        EXPECT_TRUE(Scenario->DrainPendingBeforeRelease);
        EXPECT_TRUE(Gate->WorkCompleted);
        (void)Peer;
    }

TEST(SessionDataPlane, DatagramActivityTracksRunUntilCloseDrainReceipt)
    {
        Net::io_context Io;
        auto [Raw, Peer] = Prism::MakeMemoryPair(Io.get_executor());
        auto Transport = std::make_shared<Prism::MemoryStream>(std::move(Raw));
        auto Gate = std::make_shared<DatagramRunGate>();
        Gate->Started = MakeReleaseChannel(Io.get_executor());
        Gate->Release = MakeReleaseChannel(Io.get_executor());
        auto Datagram = std::make_shared<Prism::Testing::DatagramSession>(
            Transport, [Gate] { return WaitForDatagramRelease(Gate); });
        auto Scenario = std::make_shared<DatagramActivityScenario>(DatagramActivityScenario{
            Io, Datagram, Transport, Gate, MakeReleaseChannel(Io.get_executor()),
            MakeReleaseChannel(Io.get_executor())});

        RunCoro(Io, RunDatagramActivityScenario(Scenario));

        EXPECT_FALSE(Scenario->RunFailure);
        EXPECT_FALSE(Scenario->DrainFailure);
        EXPECT_EQ(Scenario->RunResult.has_value(), true);
        EXPECT_TRUE(Scenario->DrainResult.has_value());
        EXPECT_TRUE(Scenario->RunReturned);
        EXPECT_TRUE(Scenario->DrainReturned);
        EXPECT_TRUE(Scenario->DrainPendingBeforeRelease);
        EXPECT_TRUE(Gate->WorkCompleted);
        EXPECT_FALSE(Transport->IsOpen());
        (void)Peer;
    }

TEST(SessionDataPlane, TypedAccountLeaseReleasesExactlyOnceAtSessionEnd)
    {
        Net::io_context Ioc;
        auto Directory = Prism::Testing::ProviderAccount(
            Prism::Account::Credential::Password("typed-lease"), Prism::AccountId{88});
        ASSERT_TRUE(Directory->Publication);
        auto Record = Directory->Store->FindById(Prism::AccountId{88});
        ASSERT_TRUE(Record);
        auto Acquired = Directory->Credentials.TryAcquire(
            Prism::Account::AcquireRequest{
                .Credential = Prism::Account::CredentialView::Password("typed-lease"),
                .Rate = Prism::Account::RateRequest{0, 1, 1}});
        ASSERT_TRUE(Acquired);
        auto LeaseOwner = std::make_shared<Prism::Account::AccountLease>(
            std::move(*Acquired));
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 1U);

        auto [ClientRaw, ServerRaw] = Prism::MakeMemoryPair(Ioc.get_executor());
        auto Client = std::make_shared<Prism::MemoryStream>(std::move(ClientRaw));
        auto Server = std::make_shared<Prism::MemoryStream>(std::move(ServerRaw));
        auto Options = MakeSessionOptions(Ioc.get_executor());
        Options.Services->AcceptProtocol = std::make_shared<Prism::Testing::StreamFactory>(
            TypedAccountDatagramFactory{LeaseOwner});
        auto Session = std::make_shared<Prism::Runtime::Session>(std::move(Options));

        Prism::Testing::RunCoro(Ioc, RunTypedAccountDatagram(
                                             TypedAccountDatagramRequest{Session, Client, Server}));

        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U);
        EXPECT_FALSE(*LeaseOwner);
    }


TEST(SessionServicesLifecycle, GenerationUseLeaseWaitsForControlTaskDrain)
{
    Net::io_context Io;
    auto UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
    auto Lease = UseState->Acquire();
    ASSERT_TRUE(Lease);

    auto [Raw, Peer] = Prism::MakeMemoryPair(Io.get_executor());
    auto Inbound = std::make_shared<Prism::MemoryStream>(std::move(Raw));
    auto Control = std::make_shared<Prism::Runtime::SessionControl>(Io.get_executor());
    Prism::Runtime::SessionOptions Options;
    Options.Services->Bytes = std::make_shared<Prism::Memory::BytePool>();
    Options.Control = Control;
    Options.Services->AcceptProtocol = std::make_shared<Prism::Testing::StreamFactory>(
        [](Prism::Contract::StreamAcceptInput)
            -> Net::awaitable<Prism::Contract::AcceptOutcome>
        { co_return std::unexpected(
                Prism::Contract::FailureFromProtocolError(Prism::Error::BadAuth)); });
    auto Session = std::make_shared<Prism::Runtime::Session>(std::move(Options));
    ASSERT_TRUE(Session->SetGenerationUseLease(std::move(*Lease)));
    EXPECT_EQ(UseState->Outstanding(), 1U);

    auto ChildStarted = MakeReleaseChannel(Io.get_executor());
    auto ChildRelease = MakeReleaseChannel(Io.get_executor());
    auto ChildCompleted = std::make_shared<bool>(false);
    Prism::Lifecycle::TaskRequest Request;
    const auto Child = Control->Start(
        std::move(Request),
        HoldSessionChildUntilReleased(ChildStarted, ChildRelease, ChildCompleted));
    ASSERT_TRUE(Child);

    auto RunDone = MakeReleaseChannel(Io.get_executor());
    auto RunState = std::make_shared<SessionGenerationRunState>();
    RunCoro(Io, AwaitSessionGenerationControlDrain(SessionGenerationDrainRequest{
        Io, Session, Inbound, ChildStarted, ChildRelease, ChildCompleted,
        RunDone, RunState, UseState}));

    EXPECT_FALSE(RunState->Exception);
    EXPECT_EQ(RunState->Result.Code, Prism::Fault::Code::AuthFailed);
    EXPECT_TRUE(*ChildCompleted);
    EXPECT_EQ(UseState->Outstanding(), 1U);
    Session.reset();
    EXPECT_EQ(UseState->Outstanding(), 0U);
    (void)Peer;
}
