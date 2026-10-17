/**
 * @file TuicAdmissionTest.cpp
 * @brief TUIC admission 认证、stream lease 与 datagram 行为测试。
 */
#include "TuicAdmissionSupport.hpp"
#include <cstdio>

namespace
{
    struct BidiReadProbe final
    {
        Net::any_io_executor Executor;
        std::weak_ptr<Preview::Tuic::ConnectionAdmission> Admission;
        std::function<void()> CaptureActiveStreams;
    };

    /** @brief 在测试 executor 上关闭仍存活的 admission owner。 */
    auto CloseAdmission(const std::weak_ptr<Preview::Tuic::ConnectionAdmission> &Admission) -> void
    {
        if (auto Owner = Admission.lock())
        {
            Owner->Close();
            Owner->OnClosed();
        }
    }

    /** @brief 记录握手时 stream lease 并在读取开始后请求连接关闭。 */
    auto OnBidiReadStarted(const std::shared_ptr<BidiReadProbe> &Probe) -> void
    {
        Probe->CaptureActiveStreams();
        Net::post(Probe->Executor, [Probe] { CloseAdmission(Probe->Admission); });
    }

    struct DatagramObservation final
    {
        std::size_t ExchangeCalls{0};
        std::size_t ReportCalls{0};
        std::uint64_t ByteUploaded{0};
        std::uint64_t ByteDownloaded{0};
        Preview::Tuic::DatagramSessionReport SessionReport{};
    };

    /** @brief 验证原 UDP 请求字节并返回原目标与响应负载。 */
    auto ExchangeObservedDatagram(
        const std::shared_ptr<DatagramObservation> &Observation,
        Preview::Tuic::DatagramRequest Request)
        -> Net::awaitable<Preview::Tuic::DatagramResult>
    {
        ++Observation->ExchangeCalls;
        EXPECT_EQ(Request.AccountId, Preview::AccountId{42});
        EXPECT_EQ(Request.Target.Host, "203.0.113.7");
        EXPECT_EQ(Request.Payload, (std::vector<std::uint8_t>{
            'r', 'e', 'q', 'u', 'e', 's', 't', '-', 'p', 'a', 'y', 'l', 'o', 'a', 'd'}));
        const auto UploadedBytes = static_cast<std::uint64_t>(Request.Payload.size());
        co_return Preview::Tuic::DatagramResult{
            Preview::Error::None,
            {Preview::Tuic::AddressType::Ipv4, "198.51.100.4", 53},
            {'o', 'k'}, UploadedBytes, 2U};
    }

    /** @brief 区分流量增量与 datagram session 终结报告。 */
    auto RecordDatagramObservation(
        const std::shared_ptr<DatagramObservation> &Observation,
        Preview::Tuic::DatagramSessionReport Report) -> void
    {
        if (Report.Kind == Preview::Foundation::TrafficEventKind::Bytes)
        {
            Observation->ByteUploaded += Report.UploadedBytes;
            Observation->ByteDownloaded += Report.DownloadedBytes;
            return;
        }
        ++Observation->ReportCalls;
        Observation->SessionReport = Report;
    }
}

TEST(TuicAdmission, ReadsBufferedAuthenticationAfterPeerFin)
{
    Net::io_context Io;
    AdmissionHarness Harness(Io);
    Harness.Install();
    auto AuthStream = MakeScriptedStream(Io.get_executor(), MakeAuthWire());
    AuthStream.Provider->MarkPeerFin();
    ASSERT_TRUE(AuthStream.Provider->IsClosed());

    Harness.SubmitUnidirectional(AuthStream.Provider);
    Harness.SubmitExporter(TestExporter);
    Io.run();

    EXPECT_EQ(Harness.Authenticator()->Calls(), 1U);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 1U);
    EXPECT_FALSE(AuthStream.Transmission->IsOpen());
    Io.restart();
    Harness.Admission()->OnClosed();
    Io.run();
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 0U);
    Harness.CloseAndDrain();
}

TEST(TuicAdmission, ReadsBufferedConnectAfterPeerFin)
{
    Net::io_context Io;
    AdmissionHarness Harness(Io);
    std::size_t DialCalls = 0;
    Preview::Tuic::AdmissionServices Services;
    Services.Dial = [&DialCalls, Executor = Io.get_executor()](Preview::Tuic::DialRequest)
        -> Net::awaitable<std::expected<Preview::SharedTransmission,
            Preview::Fault::Failure>>
    {
        ++DialCalls;
        co_return Preview::SharedTransmission{std::make_shared<ScriptedTransmission>(Executor)};
    };
    Harness.Install(std::move(Services));
    Harness.SubmitUnidirectional(
        MakeScriptedStream(Io.get_executor(), MakeAuthWire()).Provider);
    Harness.SubmitExporter(TestExporter);
    Io.run();

    auto Bidi = MakeScriptedStream(Io.get_executor(), MakeConnectWire());
    Bidi.Provider->MarkPeerFin();
    ASSERT_TRUE(Bidi.Provider->IsClosed());
    Io.restart();
    Harness.SubmitBidirectional(Bidi.Provider);
    Io.run();

    EXPECT_EQ(DialCalls, 1U);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveStreams(), 0U);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 1U);
    Io.restart();
    Harness.Admission()->OnClosed();
    Io.run();
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 0U);
    Harness.CloseAndDrain();
}

TEST(TuicAdmission, WaitsForBothAuthenticationInputsAndAuthenticatesOnce)
{
    Net::io_context Io;
    AdmissionHarness Harness(Io);
    Harness.Install();
    auto AuthStream = MakeScriptedStream(Io.get_executor(), MakeAuthWire());
    Harness.SubmitUnidirectional(AuthStream.Provider);
    Io.run();
    EXPECT_EQ(Harness.Authenticator()->Calls(), 0U);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 0U);

    Io.restart();
    Harness.SubmitExporter(TestExporter);
    Harness.SubmitExporter(TestExporter);
    Io.run();

    EXPECT_EQ(Harness.Authenticator()->Calls(), 1U);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 1U);
    EXPECT_FALSE(AuthStream.Transmission->IsOpen());

    Io.restart();
    Harness.Admission()->OnClosed();
    Harness.Admission()->Close();
    Io.run();
    EXPECT_EQ(Harness.CloseOwnerCalls(), 1U);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 0U);
    Harness.CloseAndDrain();
}

TEST(TuicAdmission, ConcurrentBidiStreamsHoldIndependentLeases)
{
    Net::io_context Io;
    AdmissionHarness Harness(Io);
    std::size_t RelayCalls = 0;
    std::size_t LeasesReceived = 0;
    std::uint32_t MaxActiveStreams = 0;
    Preview::Tuic::AdmissionServices Services;
    const auto AccountRuntime = Harness.Record()->Runtime();
    const auto Executor = Io.get_executor();
    Services.Dial = [AccountRuntime, Executor, &MaxActiveStreams](Preview::Tuic::DialRequest)
        -> Net::awaitable<std::expected<Preview::SharedTransmission,
            Preview::Fault::Failure>>
    {
        co_await Net::post(Executor, Net::use_awaitable);
        MaxActiveStreams = (std::max)(MaxActiveStreams, AccountRuntime->ActiveStreams());
        co_return Preview::SharedTransmission{
            std::make_shared<ScriptedTransmission>(Executor)};
    };
    Services.RelayStream = [&RelayCalls, &LeasesReceived](
                               Preview::Tuic::StreamRelayRequest Request) -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
    {
        ++RelayCalls;
        LeasesReceived += static_cast<std::size_t>(static_cast<bool>(Request.Lease));
        co_return std::expected<void, Preview::Fault::Failure>{};
    };
    Harness.Install(std::move(Services));
    Harness.SubmitUnidirectional(
        MakeScriptedStream(Io.get_executor(), MakeAuthWire()).Provider);
    Harness.SubmitExporter(TestExporter);
    Harness.SubmitBidirectional(
        MakeScriptedStream(Io.get_executor(), MakeConnectWire()).Provider);
    Harness.SubmitBidirectional(
        MakeScriptedStream(Io.get_executor(), MakeConnectWire()).Provider);
    Io.run();

    EXPECT_EQ(Harness.Authenticator()->Calls(), 1U);
    EXPECT_EQ(RelayCalls, 2U);
    EXPECT_EQ(LeasesReceived, 2U);
    EXPECT_EQ(MaxActiveStreams, 2U);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveStreams(), 0U);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 1U);
    Io.restart();
    Harness.Admission()->OnClosed();
    Io.run();
    EXPECT_EQ(Harness.CloseOwnerCalls(), 1U);
    Harness.CloseAndDrain();
}

TEST(TuicAdmission, BidiCompletionKeepsConnectionLeaseUntilQuicClose)
{
    Net::io_context Io;
    AdmissionHarness Harness(Io);
    Harness.Install();
    Harness.SubmitUnidirectional(
        MakeScriptedStream(Io.get_executor(), MakeAuthWire()).Provider);
    Harness.SubmitExporter(TestExporter);
    Harness.SubmitBidirectional(
        MakeScriptedStream(Io.get_executor(), MakeConnectWire()).Provider);
    Io.run();

    EXPECT_EQ(Harness.Authenticator()->Calls(), 1U);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveStreams(), 0U);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 1U);

    Io.restart();
    Harness.Admission()->OnClosed();
    Io.run();
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 0U);
    Harness.CloseAndDrain();
}

TEST(TuicAdmission, BidiLeaseIsHeldFromAdmissionThroughPendingHandshake)
{
    Net::io_context Io;
    AdmissionHarness Harness(Io);
    Harness.Install();
    Harness.SubmitUnidirectional(
        MakeScriptedStream(Io.get_executor(), MakeAuthWire()).Provider);
    Harness.SubmitExporter(TestExporter);
    Io.run();
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 1U);

    const auto Executor = Io.get_executor();
    std::uint32_t ActiveStreamsAtHandshake{0};
    auto Bidi = MakeScriptedStream(Executor, std::vector<std::byte>{}, true);
    auto Probe = std::make_shared<BidiReadProbe>();
    Probe->Executor = Executor;
    Probe->Admission = Harness.Admission();
    Probe->CaptureActiveStreams = [&ActiveStreamsAtHandshake,
        Runtime = Harness.Record()->Runtime()]
    {
        ActiveStreamsAtHandshake = Runtime->ActiveStreams();
    };
    Bidi.Transmission->SetReadStarted([Probe] { OnBidiReadStarted(Probe); });

    Io.restart();
    Harness.SubmitBidirectional(Bidi.Provider);
    Io.run();

    EXPECT_EQ(Bidi.Transmission->ReadCalls(), 1U);
    EXPECT_GE(Bidi.Transmission->CancelCalls(), 1U);
    EXPECT_EQ(ActiveStreamsAtHandshake, 1U);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveStreams(), 0U);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 0U);
    EXPECT_EQ(Harness.CloseOwnerCalls(), 1U);
    Harness.CloseAndDrain();
}

TEST(TuicAdmission, RejectsWrongExporterBeforeCallingAccountAuthenticator)
{
    Net::io_context Io;
    AdmissionHarness Harness(Io);
    Harness.Install();
    Harness.SubmitUnidirectional(
        MakeScriptedStream(Io.get_executor(), MakeAuthWire("wrong-password")).Provider);
    Harness.SubmitExporter(TestExporter);
    Io.run();

    EXPECT_EQ(Harness.Authenticator()->Calls(), 0U);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 0U);
    EXPECT_EQ(Harness.CloseOwnerCalls(), 1U);
    Io.restart();
    Harness.Admission()->OnClosed();
    Io.run();
    EXPECT_EQ(Harness.CloseOwnerCalls(), 1U);
    Harness.CloseAndDrain();
}

TEST(TuicAdmission, RetainsPreAuthenticationDatagramProviderUntilAuthentication)
{
    Net::io_context Io;
    AdmissionHarness Harness(Io);
    auto Observation = std::make_shared<DatagramObservation>();
    Preview::Tuic::AdmissionServices Services;
    Services.ExchangeDatagram = [Observation](Preview::Tuic::DatagramRequest Request)
    { return ExchangeObservedDatagram(Observation, std::move(Request)); };
    Services.ReportDatagramSession = [Observation](Preview::Tuic::DatagramSessionReport Report)
    { RecordDatagramObservation(Observation, std::move(Report)); };
    Harness.Install(std::move(Services));
    auto Provider = std::make_shared<ScriptedDatagramProvider>(
        Io.get_executor(), MakePacketWire());
    Harness.SubmitDatagram(Provider);
    Io.run();
    EXPECT_FALSE(Provider->IsClosed());
    EXPECT_EQ(Provider->ReceiveCalls(), 0U);

    Io.restart();
    Harness.SubmitUnidirectional(
        MakeScriptedStream(Io.get_executor(), MakeAuthWire()).Provider);
    Harness.SubmitExporter(TestExporter);
    Io.run();

    EXPECT_EQ(Harness.Authenticator()->Calls(), 1U);
    EXPECT_EQ(Observation->ExchangeCalls, 1U);
    EXPECT_EQ(Provider->ReceiveCalls(), 2U);
    EXPECT_EQ(Provider->SendCalls(), 1U);
    EXPECT_FALSE(Provider->Sent().empty());
    EXPECT_EQ(Observation->ReportCalls, 1U);
    EXPECT_EQ(Observation->ByteUploaded, std::string_view{"request-payload"}.size());
    EXPECT_EQ(Observation->ByteDownloaded, 2U);
    EXPECT_EQ(Observation->SessionReport.Kind, Preview::Foundation::TrafficEventKind::Completed);
    EXPECT_EQ(Observation->SessionReport.AccountId, Preview::AccountId{42});
    EXPECT_EQ(Observation->SessionReport.DatagramCount, 1U);
    EXPECT_EQ(Observation->SessionReport.UploadedBytes, std::string_view{"request-payload"}.size());
    EXPECT_EQ(Observation->SessionReport.DownloadedBytes, 2U);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 1U);
    Io.restart();
    Harness.Admission()->OnClosed();
    Io.run();
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 0U);
    Harness.CloseAndDrain();
}

TEST(TuicAdmission, CloseCancelsPendingAuthenticationAndIsIdempotent)
{
    Net::io_context Io;
    AdmissionHarness Harness(Io);
    Harness.Install();
    auto AuthStream = MakeScriptedStream(Io.get_executor(), std::vector<std::byte>{}, true);
    AuthStream.Transmission->SetReadStarted([&Harness]
                               {
                                   Harness.Admission()->Close();
                                   Harness.Admission()->OnClosed();
                               });
    Harness.SubmitExporter(TestExporter);
    Harness.SubmitUnidirectional(AuthStream.Provider);
    Io.run();

    EXPECT_EQ(AuthStream.Transmission->ReadCalls(), 1U);
    EXPECT_GE(AuthStream.Transmission->CancelCalls(), 1U);
    EXPECT_EQ(Harness.Authenticator()->Calls(), 0U);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 0U);
    EXPECT_EQ(Harness.CloseOwnerCalls(), 1U);
    Harness.CloseAndDrain();
}

TEST(TuicAdmission, RejectsMissingAuthenticationConfiguration)
{
    Net::io_context Io;
    AdmissionHarness Harness(Io);
    std::size_t BusinessCalls = 0;
    Preview::Tuic::AdmissionServices Services;
    Services.Dial = [&BusinessCalls](Preview::Tuic::DialRequest)
        -> Net::awaitable<std::expected<Preview::SharedTransmission,
            Preview::Fault::Failure>>
    {
        ++BusinessCalls;
        co_return std::unexpected(
            Preview::Fault::Failure{Preview::Fault::Code::NotSupported});
    };

    auto MissingCredential = Harness.BaseOptions();
    MissingCredential.Credential.reset();
    EXPECT_FALSE(Preview::Tuic::ConnectionAdmission::Create(
        std::move(MissingCredential), Services));

    auto MissingAuthenticator = Harness.BaseOptions();
    MissingAuthenticator.AuthenticatorOwner.reset();
    EXPECT_FALSE(Preview::Tuic::ConnectionAdmission::Create(
        std::move(MissingAuthenticator), Services));
    EXPECT_EQ(BusinessCalls, 0U);
    Harness.CloseAndDrain();
}

TEST(TuicAdmission, RejectsAuthenticationResultWithoutAccountLease)
{
    Net::io_context Io;
    AdmissionHarness Harness(Io);
    Harness.Authenticator()->DropLease();
    std::size_t DialCalls = 0;
    Preview::Tuic::AdmissionServices Services;
    const auto Executor = Io.get_executor();
    Services.Dial = [&DialCalls, Executor](Preview::Tuic::DialRequest)
        -> Net::awaitable<std::expected<Preview::SharedTransmission,
            Preview::Fault::Failure>>
    {
        ++DialCalls;
        co_return Preview::SharedTransmission{
            std::make_shared<ScriptedTransmission>(Executor)};
    };
    Harness.Install(std::move(Services));
    Harness.SubmitUnidirectional(
        MakeScriptedStream(Io.get_executor(), MakeAuthWire()).Provider);
    Harness.SubmitExporter(TestExporter);
    Harness.SubmitBidirectional(
        MakeScriptedStream(Io.get_executor(), MakeConnectWire()).Provider);
    Io.run();

    EXPECT_EQ(Harness.Authenticator()->Calls(), 1U);
    EXPECT_EQ(DialCalls, 0U);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 0U);
    EXPECT_EQ(Harness.CloseOwnerCalls(), 1U);
    Io.restart();
    Harness.Admission()->OnClosed();
    Io.run();
    Harness.CloseAndDrain();
}

TEST(TuicAdmission, RejectsUnidirectionalStreamAfterAuthentication)
{
    Net::io_context Io;
    AdmissionHarness Harness(Io);
    std::size_t RelayCalls = 0;
    Preview::Tuic::AdmissionServices Services;
    Services.RelayStream = [&RelayCalls](Preview::Tuic::StreamRelayRequest)
        -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
    {
        ++RelayCalls;
        co_return std::expected<void, Preview::Fault::Failure>{};
    };
    Harness.Install(std::move(Services));
    Harness.SubmitUnidirectional(
        MakeScriptedStream(Io.get_executor(), MakeAuthWire()).Provider);
    Harness.SubmitExporter(TestExporter);
    std::fprintf(stderr, "RUA before auth run\n");
    Io.run();
    std::fprintf(stderr, "RUA after auth run\n");
    EXPECT_EQ(Harness.Authenticator()->Calls(), 1U);

    Io.restart();
    auto RepeatedAuth = MakeScriptedStream(Io.get_executor(), MakeAuthWire("unused"));
    Harness.SubmitUnidirectional(RepeatedAuth.Provider);
    Harness.SubmitBidirectional(
        MakeScriptedStream(Io.get_executor(), MakeConnectWire()).Provider);
    std::fprintf(stderr, "RUA before repeated run\n");
    Io.run();
    std::fprintf(stderr, "RUA after repeated run\n");

    EXPECT_FALSE(RepeatedAuth.Transmission->IsOpen());
    EXPECT_EQ(RepeatedAuth.Transmission->ReadCalls(), 0U);
    EXPECT_EQ(Harness.Authenticator()->Calls(), 1U);
    EXPECT_EQ(RelayCalls, 1U);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 1U);
    Io.restart();
    Harness.Admission()->OnClosed();
    Io.run();
    std::fprintf(stderr, "RUA after close run\n");
    Harness.CloseAndDrain();
    std::fprintf(stderr, "RUA after drain\n");
}

TEST(TuicAdmission, ZeroPendingBidiCapacityRejectsEarlyStream)
{
    Net::io_context Io;
    AdmissionHarness Harness(Io);
    std::size_t DialCalls = 0;
    Preview::Tuic::AdmissionServices Services;
    const auto Executor = Io.get_executor();
    Services.Dial = [&DialCalls, Executor](Preview::Tuic::DialRequest)
        -> Net::awaitable<std::expected<Preview::SharedTransmission,
            Preview::Fault::Failure>>
    {
        ++DialCalls;
        co_return Preview::SharedTransmission{
            std::make_shared<ScriptedTransmission>(Executor)};
    };
    Harness.Install(std::move(Services), 0U);
    auto Bidi = MakeScriptedStream(Io.get_executor(), MakeConnectWire());
    Harness.SubmitBidirectional(Bidi.Provider);
    Harness.SubmitUnidirectional(
        MakeScriptedStream(Io.get_executor(), MakeAuthWire()).Provider);
    Harness.SubmitExporter(TestExporter);
    std::fprintf(stderr, "ZP before run\n");
    Io.run();
    std::fprintf(stderr, "ZP after run\n");

    EXPECT_FALSE(Bidi.Transmission->IsOpen());
    EXPECT_EQ(DialCalls, 0U);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 1U);
    Io.restart();
    Harness.Admission()->OnClosed();
    Io.run();
    std::fprintf(stderr, "ZP after close run\n");
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 0U);
    Harness.CloseAndDrain();
    std::fprintf(stderr, "ZP after drain\n");
}

TEST(TuicAdmission, PendingBidiCapacityClosesOnlyOverflowStreams)
{
    Net::io_context Io;
    AdmissionHarness Harness(Io);
    std::size_t DialCalls = 0;
    Preview::Tuic::AdmissionServices Services;
    const auto Executor = Io.get_executor();
    Services.Dial = [&DialCalls, Executor](Preview::Tuic::DialRequest)
        -> Net::awaitable<std::expected<Preview::SharedTransmission,
            Preview::Fault::Failure>>
    {
        ++DialCalls;
        co_return Preview::SharedTransmission{
            std::make_shared<ScriptedTransmission>(Executor)};
    };
    Harness.Install(std::move(Services), 1U);
    auto First = MakeScriptedStream(Io.get_executor(), MakeConnectWire());
    auto Overflow = MakeScriptedStream(Io.get_executor(), MakeConnectWire());
    Harness.SubmitBidirectional(First.Provider);
    Harness.SubmitBidirectional(Overflow.Provider);
    Harness.SubmitUnidirectional(
        MakeScriptedStream(Io.get_executor(), MakeAuthWire()).Provider);
    Harness.SubmitExporter(TestExporter);
    std::fprintf(stderr, "PB before run\n");
    Io.run();
    std::fprintf(stderr, "PB after run\n");

    EXPECT_GT(First.Transmission->ReadCalls(), 0U);
    EXPECT_EQ(Overflow.Transmission->ReadCalls(), 0U);
    EXPECT_FALSE(Overflow.Transmission->IsOpen());
    EXPECT_EQ(DialCalls, 1U);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 1U);
    Io.restart();
    Harness.Admission()->OnClosed();
    Io.run();
    std::fprintf(stderr, "PB after close run\n");
    Harness.CloseAndDrain();
    std::fprintf(stderr, "PB after drain\n");
}

