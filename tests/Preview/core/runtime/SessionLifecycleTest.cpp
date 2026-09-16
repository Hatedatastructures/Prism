/**
 * @file SessionLifecycleTest.cpp
 * @brief Preview 会话所有权、取消与排空契约测试
 * @details 覆盖 owner-held 资源、取消竞态、异常收口、非合作操作和
 *          listener/controller 的两阶段停机边界。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <stdexcept>
#include <string>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Utility/TrafficSink.hpp>
#include <Preview/Account/Account.hpp>
#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Runtime/Contract/DataPlane.hpp>
#include <Preview/Runtime/Listener.hpp>
#include <Preview/Runtime/Session.hpp>
#include <Preview/Runtime/SessionControl.hpp>
#include <Preview/Runtime/SessionRegistry.hpp>
#include <Preview/Runtime/Recognition/Route.hpp>
#include <Preview/Runtime/Recognition/SchemeExecutor.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;
    using ByteChannel = Net::experimental::channel<void(boost::system::error_code)>;
    using Preview::Testing::RunCoro;

    auto MakeReleaseChannel(Net::any_io_executor Executor) -> std::shared_ptr<ByteChannel>
    {
        return std::make_shared<ByteChannel>(std::move(Executor), 1);
    }

    auto WaitForRelease(const std::shared_ptr<ByteChannel> &Release) -> Net::awaitable<void>
    {
        boost::system::error_code ErrorCode;
        co_await Release->async_receive(Net::redirect_error(Net::use_awaitable, ErrorCode));
    }

    auto WaitForReleaseAndMark(const std::shared_ptr<ByteChannel> &Release,
                               const std::shared_ptr<bool> &Completed) -> Net::awaitable<void>
    {
        co_await WaitForRelease(Release);
        *Completed = true;
    }

    auto MakeInfo(std::uint64_t Id) -> Preview::Runtime::SessionInfo
    {
        Preview::Runtime::SessionInfo Info;
        Info.Id = Id;
        Info.identity = "user-" + std::to_string(Id);
        Info.peer = "127.0.0.1";
        Info.Target = "example.test:443";
        Info.Protocol = 1;
        return Info;
    }

    auto CheckCurrentIdentity(const std::shared_ptr<Preview::Runtime::SessionControl> &Control,
                              Preview::Lifecycle::TaskIdentity Expected) -> Net::awaitable<void>
    {
        const auto Current = Control->CurrentIdentity();
        EXPECT_EQ(Current.SessionId, Expected.SessionId);
        EXPECT_EQ(Current.WorkerId, Expected.WorkerId);
        EXPECT_TRUE(static_cast<bool>(Current.TaskId));
        co_return;
    }

    class OwnedTrafficSink final : public Preview::Foundation::TrafficSink
    {
    public:
        void Report(std::string_view, std::size_t, std::size_t) override {}
    };

    TEST(SessionDataPlane, ProtocolPlaneUsesTypedRootAndAccountIdentity)
    {
        Net::io_context Ioc;
        auto [Raw, Peer] = Preview::MakeMemoryPair(Ioc.get_executor());
        auto Transport = std::make_shared<Preview::MemoryStream>(std::move(Raw));

        Preview::Runtime::ProtocolDataPlane Plane;
        Plane.AccountId = Preview::AccountId{42};
        Plane.Root = Preview::Runtime::StreamDataPlane{Transport};

        EXPECT_TRUE(Plane.IsStream());
        EXPECT_FALSE(Plane.IsDatagram());
        ASSERT_TRUE(Plane.Stream());
        EXPECT_EQ(Plane.Stream()->Transport.get(), Transport.get());
        EXPECT_EQ(Plane.AccountId.Value(), 42U);

        Preview::Runtime::DatagramDataPlane Datagram;
        Datagram.Transport = std::make_shared<Preview::MemoryStream>(std::move(Peer));
        Plane.Root = std::move(Datagram);

        EXPECT_FALSE(Plane.IsStream());
        EXPECT_TRUE(Plane.IsDatagram());
        ASSERT_TRUE(Plane.Datagram());
        EXPECT_TRUE(Plane.Datagram()->Transport);
    }

    TEST(SessionDataPlane, SessionRunsTypedDatagramServiceWithoutLegacyFlag)
    {
        Net::io_context Ioc;
        auto [ClientRaw, ServerRaw] = Preview::MakeMemoryPair(Ioc.get_executor());
        auto Client = std::make_shared<Preview::MemoryStream>(std::move(ClientRaw));
        auto Server = std::make_shared<Preview::MemoryStream>(std::move(ServerRaw));
        auto ServiceCalled = std::make_shared<bool>(false);

        Preview::Runtime::SessionOptions Options;
        Options.AcceptProtocol = [ServiceCalled](Preview::SharedTransmission &Inbound,
                                                  Preview::Middleware::Context &Context)
            -> Net::awaitable<Preview::Fault::Code>
        {
            Preview::Runtime::DatagramDataPlane Datagram;
            Datagram.Transport = Inbound;
            Datagram.Service = [ServiceCalled](Preview::Middleware::Context &)
                -> Net::awaitable<Preview::Fault::Code>
            {
                *ServiceCalled = true;
                co_return Preview::Fault::Code::Success;
            };
            Preview::Runtime::ProtocolDataPlane Plane;
            Plane.Root = std::move(Datagram);
            Plane.AccountId = Preview::AccountId{7};
            Context.SetDataPlane(std::move(Plane));
            co_return Preview::Fault::Code::Success;
        };
        auto Session = std::make_shared<Preview::Runtime::Session>(std::move(Options));

        Preview::Testing::RunCoro(
            Ioc,
            [&]() -> Net::awaitable<void>
            {
                const std::string Greeting("\x05\x01\x00", 3);
                std::error_code ErrorCode;
                co_await Client->async_write_some(
                    std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(Greeting.data()), Greeting.size()),
                    ErrorCode);
                EXPECT_FALSE(ErrorCode);
                EXPECT_EQ(co_await Session->Run(Server), Preview::Fault::Code::Success);
            });

        EXPECT_TRUE(*ServiceCalled);
    }

    TEST(SessionDataPlane, SessionRunsTypedMuxServiceWithoutDial)
    {
        Net::io_context Ioc;
        auto [ClientRaw, ServerRaw] = Preview::MakeMemoryPair(Ioc.get_executor());
        auto Client = std::make_shared<Preview::MemoryStream>(std::move(ClientRaw));
        auto Inbound = std::make_shared<Preview::MemoryStream>(std::move(ServerRaw));
        auto Done = std::make_shared<ByteChannel>(Ioc.get_executor(), 1);
        auto MuxCalled = std::make_shared<bool>(false);
        auto Result = std::make_shared<Preview::Fault::Code>(Preview::Fault::Code::IoError);

        Preview::Runtime::SessionOptions Options;
        Options.AcceptProtocol = [](Preview::SharedTransmission &InboundValue,
                                    Preview::Middleware::Context &Context)
            -> Net::awaitable<Preview::Fault::Code>
        {
            Preview::Runtime::ProtocolDataPlane Plane;
            Plane.Root = Preview::Runtime::MuxRootDataPlane{InboundValue, "auto"};
            Context.SetDataPlane(std::move(Plane));
            co_return Preview::Fault::Code::Success;
        };
        Options.mux = [MuxCalled](Preview::SharedTransmission &, Preview::Middleware::Context &)
            -> Net::awaitable<bool>
        {
            *MuxCalled = true;
            co_return true;
        };

        RunCoro(
            Ioc,
            [&]() -> Net::awaitable<void>
            {
                Net::co_spawn(
                    Ioc,
                    [Inbound, Done, Result, Options = std::move(Options)]() mutable
                        -> Net::awaitable<void>
                    {
                        Preview::Runtime::Session Session(std::move(Options));
                        *Result = co_await Session.Run(Inbound);
                        (void)Done->try_send(boost::system::error_code{});
                    },
                    Net::detached);

                const std::string Request =
                    "GET http://example.com:80/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
                std::error_code WriteError;
                const auto Bytes = std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(Request.data()), Request.size());
                co_await Client->async_write_some(Bytes, WriteError);
                EXPECT_FALSE(WriteError);
                boost::system::error_code DoneError;
                co_await Done->async_receive(Net::redirect_error(Net::use_awaitable, DoneError));
            });

        EXPECT_EQ(*Result, Preview::Fault::Code::Success);
        EXPECT_TRUE(*MuxCalled);
    }

    TEST(SessionDataPlane, TypedAccountLeaseReleasesExactlyOnceAtSessionEnd)
    {
        Net::io_context Ioc;
        Preview::Account::AccountDirectory Directory;
        auto Record = std::make_shared<Preview::Account::AccountRecord>(
            Preview::Account::AccountRecord::CreateRequest{
                .AccountId = Preview::AccountId{88},
                .CredentialValue = Preview::Account::Credential::Password("typed-lease")});
        ASSERT_TRUE(Directory.Upsert(Record));
        auto Acquired = Directory.TryAcquire(
            Preview::Account::AccountDirectory::AcquireRequest{
                Record->Credential(), Preview::Account::RateRequest{0, 1, 1}});
        ASSERT_TRUE(Acquired);
        auto LeaseOwner = std::make_shared<Preview::Account::AccountLease>(
            std::move(Acquired.Lease));
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 1U);

        auto [ClientRaw, ServerRaw] = Preview::MakeMemoryPair(Ioc.get_executor());
        auto Client = std::make_shared<Preview::MemoryStream>(std::move(ClientRaw));
        auto Server = std::make_shared<Preview::MemoryStream>(std::move(ServerRaw));
        Preview::Runtime::SessionOptions Options;
        Options.AcceptProtocol = [LeaseOwner](Preview::SharedTransmission &Inbound,
                                              Preview::Middleware::Context &Context)
            -> Net::awaitable<Preview::Fault::Code>
        {
            Preview::Runtime::DatagramDataPlane Datagram;
            Datagram.Transport = Inbound;
            Datagram.Service = [](Preview::Middleware::Context &)
                -> Net::awaitable<Preview::Fault::Code>
            { co_return Preview::Fault::Code::Success; };
            Preview::Runtime::ProtocolDataPlane Plane;
            Plane.Root = std::move(Datagram);
            Plane.AccountId = Preview::AccountId{88};
            Plane.AccountLease.emplace(std::move(*LeaseOwner));
            Context.SetDataPlane(std::move(Plane));
            co_return Preview::Fault::Code::Success;
        };
        auto Session = std::make_shared<Preview::Runtime::Session>(std::move(Options));

        Preview::Testing::RunCoro(
            Ioc,
            [&]() -> Net::awaitable<void>
            {
                const std::string Greeting("\x05\x01\x00", 3);
                std::error_code ErrorCode;
                co_await Client->async_write_some(
                    std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(Greeting.data()), Greeting.size()),
                    ErrorCode);
                EXPECT_FALSE(ErrorCode);
                EXPECT_EQ(co_await Session->Run(Server), Preview::Fault::Code::Success);
            });

        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U);
        EXPECT_FALSE(*LeaseOwner);
    }

    TEST(SessionControlLifecycle, ExposesSubmittedListenerTaskIdentity)
    {
        Net::io_context Ioc;
        auto Control = std::make_shared<Preview::Runtime::SessionControl>(Ioc.get_executor());
        Preview::Lifecycle::TaskIdentity Submitted;
        Submitted.SessionId = Preview::SessionId{101};
        Submitted.WorkerId = Preview::WorkerId{3};

        Preview::Testing::RunCoro(
            Ioc,
            [&]() -> Net::awaitable<void>
            {
                Preview::Lifecycle::TaskRequest Request;
                Request.Identity = Submitted;
                EXPECT_TRUE(Control->Start(
                    std::move(Request),
                    CheckCurrentIdentity(Control, Submitted)));
                co_await Control->Drain();
            });
    }

    TEST(SessionControlLifecycle, WorkerAdmissionIdentityStaysWithChildScope)
    {
        Net::io_context Ioc;
        Preview::Lifecycle::TaskRegistry WorkerRegistry(Ioc.get_executor());
        auto Control = std::make_shared<Preview::Runtime::SessionControl>();
        ASSERT_TRUE(Control->Bind(Ioc.get_executor(), WorkerRegistry));

        Preview::Lifecycle::TaskRequest Request;
        Request.Identity.SessionId = Preview::SessionId{301};
        Request.Identity.WorkerId = Preview::WorkerId{4};
        Request.Identity.Generation = Preview::GenerationId{17};

        Preview::Testing::RunCoro(
            Ioc,
            [Control, Request = std::move(Request)]() mutable -> Net::awaitable<void>
            {
                EXPECT_TRUE(Control->Start(
                    std::move(Request),
                    []() -> Net::awaitable<void> { co_return; }()));
                const auto Identity = Control->CurrentIdentity();
                EXPECT_EQ(Identity.SessionId, Preview::SessionId{301});
                EXPECT_EQ(Identity.WorkerId, Preview::WorkerId{4});
                EXPECT_EQ(Identity.Generation, Preview::GenerationId{17});
                EXPECT_TRUE(static_cast<bool>(Identity.TaskId));
                co_await Control->Drain();
            });

        EXPECT_FALSE(Control->IsCancelled());
        Control->Cancel();
        EXPECT_TRUE(Control->IsCancelled());
        const auto WorkerTask = WorkerRegistry.SpawnTracked(
            Preview::Lifecycle::TaskRequest{},
            []() -> Net::awaitable<void> { co_return; }());
        ASSERT_NE(WorkerTask, nullptr);
        Ioc.restart();
        Preview::Testing::RunCoro(Ioc, WorkerRegistry.Drain());
    }

    TEST(SessionControlLifecycle, DrainWaitsPastConfiguredGraceUntilLoserCompletes)
    {
        Net::io_context Ioc;
        auto Control = std::make_shared<Preview::Runtime::SessionControl>(Ioc.get_executor());
        auto Release = MakeReleaseChannel(Ioc.get_executor());
        auto DrainDone = MakeReleaseChannel(Ioc.get_executor());
        auto OperationCompleted = std::make_shared<bool>(false);
        auto DrainCompleted = std::make_shared<bool>(false);

        RunCoro(
            Ioc,
            [&]() -> Net::awaitable<void>
            {
                const auto Started = Control->Start(
                    WaitForReleaseAndMark(Release, OperationCompleted));
                EXPECT_TRUE(Started);

                Control->Cancel();
                Net::co_spawn(
                    Ioc, Control->Drain(),
                    [DrainDone, DrainCompleted](std::exception_ptr Failure)
                    {
                        if (Failure)
                        {
                            DrainDone->try_send(
                                boost::system::errc::make_error_code(boost::system::errc::io_error));
                            return;
                        }
                        *DrainCompleted = true;
                        DrainDone->try_send(boost::system::error_code{});
                    });

                Net::steady_timer Grace(Ioc);
                Grace.expires_after(std::chrono::milliseconds(150));
                co_await Grace.async_wait(Net::use_awaitable);
                EXPECT_FALSE(*DrainCompleted);

                Release->try_send(boost::system::error_code{});
                boost::system::error_code DrainError;
                co_await DrainDone->async_receive(
                    Net::redirect_error(Net::use_awaitable, DrainError));
                EXPECT_FALSE(DrainError);
                EXPECT_TRUE(*DrainCompleted);
                EXPECT_TRUE(*OperationCompleted);
            });
    }

    TEST(SessionControlLifecycle, ThrowingOperationReportsErrorAndDrains)
    {
        Net::io_context Ioc;
        auto Control = std::make_shared<Preview::Runtime::SessionControl>(Ioc.get_executor());
        std::size_t ErrorCalls = 0;
        Preview::Fault::Code ReportedCode = Preview::Fault::Code::Success;
        Control->SetErrorHook(
            [&ErrorCalls, &ReportedCode](Preview::Fault::Code Code, std::exception_ptr)
            {
                ++ErrorCalls;
                ReportedCode = Code;
            });

        RunCoro(
            Ioc,
            [&]() -> Net::awaitable<void>
            {
                const auto Started = Control->Start(
                    []() -> Net::awaitable<void>
                    {
                        throw std::runtime_error("preview operation failure");
                        co_return;
                    }());
                EXPECT_TRUE(Started);
                co_await Control->Drain();
            });

        EXPECT_EQ(ErrorCalls, 1U);
        EXPECT_EQ(ReportedCode, Preview::Fault::Code::IoError);
    }

    TEST(SessionControlLifecycle, NonCooperativeCancelIsSingleShotAndCloseIsExactlyOnce)
    {
        Net::io_context Ioc;
        auto Control = std::make_shared<Preview::Runtime::SessionControl>(Ioc.get_executor());
        auto Release = MakeReleaseChannel(Ioc.get_executor());
        std::size_t CancelCalls = 0;
        std::size_t CloseCalls = 0;

        RunCoro(
            Ioc,
            [&]() -> Net::awaitable<void>
            {
                const auto Started = Control->Start(
                    WaitForRelease(Release), [&CancelCalls] { ++CancelCalls; });
                EXPECT_TRUE(Started);

                Control->Cancel();
                Control->Cancel();
                Net::steady_timer Tick(Ioc);
                Tick.expires_after(std::chrono::milliseconds(1));
                co_await Tick.async_wait(Net::use_awaitable);
                EXPECT_EQ(CancelCalls, 1U);

                EXPECT_TRUE(Control->CloseOnce([&CloseCalls] { ++CloseCalls; }));
                EXPECT_FALSE(Control->CloseOnce([&CloseCalls] { ++CloseCalls; }));

                Net::co_spawn(
                    Ioc,
                    [Control]() -> Net::awaitable<void> { co_await Control->Drain(); },
                    Net::detached);
                Release->try_send(boost::system::error_code{});
                co_await Control->Drain();
            });

        EXPECT_EQ(CancelCalls, 1U);
        EXPECT_EQ(CloseCalls, 1U);
        EXPECT_EQ(Control->Metrics().CancelRequests, 1U);
        EXPECT_EQ(Control->Metrics().CloseCalls, 1U);
    }

    TEST(SessionRegistryLifecycle, ShutdownCancelsAndDrainsAllRegisteredSessions)
    {
        Net::io_context Ioc;
        auto Registry = std::make_shared<Preview::Runtime::SessionRegistry>();
        auto FirstControl = std::make_shared<Preview::Runtime::SessionControl>(Ioc.get_executor());
        auto SecondControl = std::make_shared<Preview::Runtime::SessionControl>(Ioc.get_executor());
        auto FirstRelease = MakeReleaseChannel(Ioc.get_executor());
        auto SecondRelease = MakeReleaseChannel(Ioc.get_executor());
        std::size_t FirstCancels = 0;
        std::size_t SecondCancels = 0;
        auto FirstRegistration = Registry->Register(MakeInfo(1), FirstControl);
        auto SecondRegistration = Registry->Register(MakeInfo(2), SecondControl);
        ASSERT_TRUE(FirstRegistration);
        ASSERT_TRUE(SecondRegistration);

        bool ShutdownCompleted = false;
        RunCoro(
            Ioc,
            [&]() -> Net::awaitable<void>
            {
                EXPECT_TRUE(FirstControl->Start(
                    WaitForRelease(FirstRelease), [&FirstCancels] { ++FirstCancels; }));
                EXPECT_TRUE(SecondControl->Start(
                    WaitForRelease(SecondRelease), [&SecondCancels] { ++SecondCancels; }));

                Net::co_spawn(
                    Ioc,
                    [Registry, &ShutdownCompleted]() -> Net::awaitable<void>
                    {
                        co_await Registry->Shutdown();
                        ShutdownCompleted = true;
                    },
                    Net::detached);

                Net::steady_timer Pending(Ioc);
                Pending.expires_after(std::chrono::milliseconds(20));
                co_await Pending.async_wait(Net::use_awaitable);
                EXPECT_FALSE(ShutdownCompleted);
                EXPECT_EQ(FirstCancels, 1U);
                EXPECT_EQ(SecondCancels, 1U);

                FirstRelease->try_send(boost::system::error_code{});
                SecondRelease->try_send(boost::system::error_code{});
                co_await Registry->Shutdown();
                EXPECT_TRUE(ShutdownCompleted);
            });

        EXPECT_EQ(FirstCancels, 1U);
        EXPECT_EQ(SecondCancels, 1U);
        EXPECT_EQ(Registry->Size(), 0U);
        FirstRegistration.Reset();
        SecondRegistration.Reset();
        EXPECT_EQ(Registry->Size(), 0U);
    }

    TEST(SessionRegistryLifecycle, ShutdownClearsLegacyPutRecords)
    {
        Net::io_context Ioc;
        auto Registry = std::make_shared<Preview::Runtime::SessionRegistry>();
        Registry->Put(MakeInfo(99));
        EXPECT_EQ(Registry->Size(), 1U);

        RunCoro(
            Ioc,
            [&]() -> Net::awaitable<void>
            {
                co_await Registry->Shutdown();
            });

        EXPECT_EQ(Registry->Size(), 0U);
    }

    TEST(SessionRegistryLifecycle, ReportsOperationFailureThroughExplicitHooks)
    {
        Net::io_context Ioc;
        auto Registry = std::make_shared<Preview::Runtime::SessionRegistry>();
        auto Control = std::make_shared<Preview::Runtime::SessionControl>(Ioc.get_executor());
        std::size_t ErrorCalls = 0;
        std::size_t MetricCalls = 0;
        Preview::Fault::Code ErrorCode = Preview::Fault::Code::Success;
        Registry->SetErrorHook(
            [&ErrorCalls, &ErrorCode](std::uint64_t, Preview::Fault::Code Code, std::exception_ptr)
            {
                ++ErrorCalls;
                ErrorCode = Code;
            });
        Registry->SetMetricsHook(
            [&MetricCalls](std::uint64_t, const Preview::Runtime::SessionMetrics &)
            { ++MetricCalls; });
        auto Registration = Registry->Register(MakeInfo(7), Control);
        ASSERT_TRUE(Registration);

        RunCoro(
            Ioc,
            [&]() -> Net::awaitable<void>
            {
                EXPECT_TRUE(Control->Start(
                    []() -> Net::awaitable<void>
                    {
                        throw std::runtime_error("tracked failure");
                        co_return;
                    }()));
                co_await Registry->Drain();
            });

        EXPECT_EQ(ErrorCalls, 1U);
        EXPECT_EQ(ErrorCode, Preview::Fault::Code::IoError);
        EXPECT_GT(MetricCalls, 0U);
        EXPECT_TRUE(Control->CloseOnce([] {}));
        EXPECT_FALSE(Control->CloseOnce([] {}));
        Registration.Reset();
    }

    TEST(SessionServicesLifecycle, SharedDependenciesOutliveCallerScope)
    {
        std::weak_ptr<Preview::Recognition::SniRouteTable> WeakRoutes;
        std::weak_ptr<Preview::Recognition::SchemeExecutor> WeakScheme;
        std::weak_ptr<Preview::Middleware::Context::PadConfig> WeakPad;
        std::weak_ptr<OwnedTrafficSink> WeakTraffic;
        auto Session = [&]
        {
            auto Services = std::make_shared<Preview::Runtime::SessionServices>();
            auto Routes = std::make_shared<Preview::Recognition::SniRouteTable>();
            auto Scheme = std::make_shared<Preview::Recognition::SchemeExecutor>();
            auto Pad = std::make_shared<Preview::Middleware::Context::PadConfig>();
            auto Traffic = std::make_shared<OwnedTrafficSink>();
            WeakRoutes = Routes;
            WeakScheme = Scheme;
            WeakPad = Pad;
            WeakTraffic = Traffic;
            Services->Routes = std::move(Routes);
            Services->Scheme = std::move(Scheme);
            Services->Pad = std::move(Pad);
            Services->Traffic = std::move(Traffic);

            Preview::Runtime::SessionOptions Options;
            Options.Services = std::move(Services);
            return std::make_unique<Preview::Runtime::Session>(std::move(Options));
        }();

        EXPECT_FALSE(WeakRoutes.expired());
        EXPECT_FALSE(WeakScheme.expired());
        EXPECT_FALSE(WeakPad.expired());
        EXPECT_FALSE(WeakTraffic.expired());
        Session.reset();
        EXPECT_TRUE(WeakRoutes.expired());
        EXPECT_TRUE(WeakScheme.expired());
        EXPECT_TRUE(WeakPad.expired());
        EXPECT_TRUE(WeakTraffic.expired());
    }

    TEST(TcpListenerLifecycle, StopOnlyStopsAcceptAndControllerShutdownDrainsSessions)
    {
        Net::io_context Ioc;
        auto Release = MakeReleaseChannel(Ioc.get_executor());
        Preview::Runtime::TcpListener Listener(
            Ioc.get_executor(),
            [Release](Preview::SharedTransmission, std::size_t)
                -> std::shared_ptr<Preview::Runtime::Session>
            {
                Preview::Runtime::SessionOptions Options;
                Options.AcceptProtocol = [Release](Preview::SharedTransmission &,
                                                   Preview::Middleware::Context &)
                    -> Net::awaitable<Preview::Fault::Code>
                {
                    co_await WaitForRelease(Release);
                    co_return Preview::Fault::Code::Success;
                };
                return std::make_shared<Preview::Runtime::Session>(std::move(Options));
            });

        std::shared_ptr<Preview::Transmission> Client;
        bool ShutdownCompleted = false;
        RunCoro(
            Ioc,
            [&]() -> Net::awaitable<void>
            {
                EXPECT_EQ(co_await Listener.Start(
                              Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0)),
                          Preview::Fault::Code::Success);
                const auto Port = Listener.LocalEndpoint().port();
                Preview::Network::Dialer::Dialer Dialer(Ioc.get_executor());
                std::error_code ErrorCode;
                Client = co_await Dialer.Connect("127.0.0.1", Port, ErrorCode);
                EXPECT_FALSE(ErrorCode);
                const bool ClientReady = Client != nullptr;
                EXPECT_TRUE(ClientReady);
                if (!ClientReady)
                {
                    Listener.Stop();
                    co_return;
                }

                const std::string Greeting("\x05\x01\x00", 3);
                co_await Client->async_write_some(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(Greeting.data()),
                                               Greeting.size()),
                    ErrorCode);
                Net::steady_timer Accepted(Ioc);
                Accepted.expires_after(std::chrono::milliseconds(20));
                co_await Accepted.async_wait(Net::use_awaitable);
                EXPECT_EQ(Listener.Registry().Size(), 1U);

                Listener.Stop();
                EXPECT_EQ(Listener.Registry().Size(), 1U);

                Net::co_spawn(
                    Ioc,
                    [&Listener, &ShutdownCompleted]() -> Net::awaitable<void>
                    {
                        co_await Listener.Shutdown();
                        ShutdownCompleted = true;
                    },
                    Net::detached);
                Net::steady_timer Pending(Ioc);
                Pending.expires_after(std::chrono::milliseconds(20));
                co_await Pending.async_wait(Net::use_awaitable);
                EXPECT_FALSE(ShutdownCompleted);

                Release->try_send(boost::system::error_code{});
                co_await Listener.Shutdown();
                EXPECT_TRUE(ShutdownCompleted);
                Client->Close();
            });
    }

    TEST(TcpListenerLifecycle, DestructorCancelsActiveSessionWithoutBlocking)
    {
        Net::io_context Ioc;
        auto Release = MakeReleaseChannel(Ioc.get_executor());
        auto ActiveControl = std::make_shared<std::shared_ptr<Preview::Runtime::SessionControl>>();
        auto Client = std::make_shared<Preview::SharedTransmission>();
        auto Listener = std::make_unique<Preview::Runtime::TcpListener>(
            Ioc.get_executor(),
            [Release, ActiveControl](Preview::SharedTransmission, std::size_t)
                -> std::shared_ptr<Preview::Runtime::Session>
            {
                auto Control = std::make_shared<Preview::Runtime::SessionControl>();
                *ActiveControl = Control;
                Preview::Runtime::SessionOptions Options;
                Options.Control = Control;
                Options.AcceptProtocol = [Release](Preview::SharedTransmission &,
                                                    Preview::Middleware::Context &)
                    -> Net::awaitable<Preview::Fault::Code>
                {
                    co_await WaitForRelease(Release);
                    co_return Preview::Fault::Code::Success;
                };
                return std::make_shared<Preview::Runtime::Session>(std::move(Options));
            });

        RunCoro(
            Ioc,
            [&]() -> Net::awaitable<void>
            {
                EXPECT_EQ(co_await Listener->Start(
                              Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0)),
                          Preview::Fault::Code::Success);
                Preview::Network::Dialer::Dialer Dialer(Ioc.get_executor());
                std::error_code ErrorCode;
                *Client = co_await Dialer.Connect("127.0.0.1", Listener->LocalEndpoint().port(),
                                                 ErrorCode);
                EXPECT_FALSE(ErrorCode);
                const bool ClientReady = *Client != nullptr;
                EXPECT_TRUE(ClientReady);
                if (!ClientReady)
                {
                    co_return;
                }
                const std::string Greeting("\x05\x01\x00", 3);
                co_await (*Client)->async_write_some(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(Greeting.data()),
                                               Greeting.size()),
                    ErrorCode);
                Net::steady_timer Accepted(Ioc);
                Accepted.expires_after(std::chrono::milliseconds(20));
                co_await Accepted.async_wait(Net::use_awaitable);
                EXPECT_NE(*ActiveControl, nullptr);
                if (*ActiveControl)
                {
                    EXPECT_EQ(Listener->Registry().Size(), 1U);
                }
            });

        ASSERT_NE(*ActiveControl, nullptr);
        auto Control = *ActiveControl;
        Listener.reset();
        EXPECT_TRUE(Control->IsCancelled());

        Release->try_send(boost::system::error_code{});
        if (*Client)
        {
            (*Client)->Close();
        }
        Ioc.restart();
        RunCoro(
            Ioc,
            [Control]() -> Net::awaitable<void>
            {
                co_await Control->Drain();
            });
        EXPECT_TRUE(Control->IsClosed());
    }

} // namespace
