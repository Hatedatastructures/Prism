/**
 * @file TuicAdmissionCloseTest.cpp
 * @brief TUIC admission close, datagram and owner release tests.
 */
#include "TuicAdmissionSupport.hpp"

namespace
{
    /** @brief 保留取消 relay 的 gate、category、回调退出与 admission owner。 */
    struct SuspendedRelayProbe final
    {
        Net::any_io_executor Executor;
        std::weak_ptr<Preview::Tuic::ConnectionAdmission> Admission;
        std::shared_ptr<Gate> RelayGate;
        std::shared_ptr<Gate> RelayCompleted;
        boost::system::error_code RelayError;
        std::string RelayErrorCategory;
        bool GateRegistered{false};
        bool GateRegisteredAtClose{false};
        bool CallbackCancelled{false};
        bool CallbackExited{false};
    };

    /** @brief 记录原生 gate 的取消错误并唤醒测试等待者。 */
    auto RecordRelayCancellation(
        const std::shared_ptr<SuspendedRelayProbe> &Probe,
        boost::system::error_code Error) -> void
    {
        Probe->RelayError = Error;
        Probe->RelayErrorCategory = Error.category().name();
        Probe->CallbackCancelled = Error == Net::experimental::error::make_error_code(
            Net::experimental::error::channel_cancelled);
        (void)Probe->RelayCompleted->try_send(boost::system::error_code{});
    }

    /** @brief 仅在 relay gate 已登记后关闭 admission owner。 */
    auto CloseSuspendedRelayOwner(const std::shared_ptr<SuspendedRelayProbe> &Probe) -> void
    {
        Probe->GateRegisteredAtClose = Probe->GateRegistered;
        if (auto Admission = Probe->Admission.lock())
        {
            Admission->Close();
            Admission->OnClosed();
        }
    }

    /** @brief 等待 relay gate 被 admission 关闭取消并返回原成功结果。 */
    auto WaitForRelayCancellation(const std::shared_ptr<SuspendedRelayProbe> &Probe)
        -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
    {
        const auto Cancellation = co_await Net::this_coro::cancellation_state;
        Probe->RelayGate->async_receive(Net::bind_cancellation_slot(
            Cancellation.slot(), [Probe](boost::system::error_code Error)
            { RecordRelayCancellation(Probe, Error); }));
        Probe->GateRegistered = true;
        Net::post(Probe->Executor, [Probe] { CloseSuspendedRelayOwner(Probe); });
        co_await Probe->RelayCompleted->async_receive(Net::bind_cancellation_slot(
            Net::cancellation_slot{}, Net::use_awaitable));
        Probe->CallbackExited = true;
        co_return std::expected<void, Preview::Fault::Failure>{};
    }

    /** @brief 保留取消 datagram exchange 的 gate、category、报告与 owner。 */
    struct SuspendedDatagramProbe final
    {
        Net::any_io_executor Executor;
        std::weak_ptr<Preview::Tuic::ConnectionAdmission> Admission;
        std::shared_ptr<Gate> ExchangeGate;
        std::shared_ptr<Gate> ExchangeCompleted;
        boost::system::error_code ExchangeError;
        std::string ExchangeErrorCategory;
        bool GateRegistered{false};
        bool GateRegisteredAtClose{false};
        bool CallbackCancelled{false};
        bool CallbackExited{false};
        std::size_t ReportCalls{0};
        std::size_t ExchangeCalls{0};
        Net::io_context *Context{nullptr};
        bool StopBeforeClose{false};
        Preview::Tuic::DatagramSessionReport SessionReport{};
    };

    /** @brief 记录 datagram gate 取消并唤醒完整等待协程。 */
    auto RecordExchangeCancellation(
        const std::shared_ptr<SuspendedDatagramProbe> &Probe,
        boost::system::error_code Error) -> void
    {
        Probe->ExchangeError = Error;
        Probe->ExchangeErrorCategory = Error.category().name();
        Probe->CallbackCancelled = Error == Net::experimental::error::make_error_code(
            Net::experimental::error::channel_cancelled);
        (void)Probe->ExchangeCompleted->try_send(boost::system::error_code{});
    }

    /** @brief 在 gate 注册后关闭 admission 与关联 owner。 */
    auto CloseSuspendedDatagramOwner(
        const std::shared_ptr<SuspendedDatagramProbe> &Probe) -> void
    {
        Probe->GateRegisteredAtClose = Probe->GateRegistered;
        if (Probe->StopBeforeClose && Probe->Context) Probe->Context->stop();
        if (auto Admission = Probe->Admission.lock())
        {
            Admission->Close();
            Admission->OnClosed();
        }
    }

    /** @brief 保持原账户断言并等待 exchange 的取消回调退栈。 */
    auto WaitForDatagramCancellation(
        const std::shared_ptr<SuspendedDatagramProbe> &Probe,
        Preview::Tuic::DatagramRequest Request)
        -> Net::awaitable<Preview::Tuic::DatagramResult>
    {
        ++Probe->ExchangeCalls;
        EXPECT_EQ(Request.AccountId, Preview::AccountId{42});
        const auto Cancellation = co_await Net::this_coro::cancellation_state;
        Probe->ExchangeGate->async_receive(Net::bind_cancellation_slot(
            Cancellation.slot(), [Probe](boost::system::error_code Error)
            { RecordExchangeCancellation(Probe, Error); }));
        Probe->GateRegistered = true;
        Net::post(Probe->Executor, [Probe] { CloseSuspendedDatagramOwner(Probe); });
        co_await Probe->ExchangeCompleted->async_receive(Net::bind_cancellation_slot(
            Net::cancellation_slot{}, Net::use_awaitable));
        Probe->CallbackExited = true;
        co_return Preview::Tuic::DatagramResult{};
    }

    /** @brief 保存唯一终结报告，忽略单独的字节增量事件。 */
    auto RecordDatagramReport(
        const std::shared_ptr<SuspendedDatagramProbe> &Probe,
        Preview::Tuic::DatagramSessionReport Report) -> void
    {
        if (Report.Kind == Preview::Foundation::TrafficEventKind::Bytes)
        {
            return;
        }
        ++Probe->ReportCalls;
        Probe->SessionReport = Report;
    }

    /** @brief 汇总上传失败测试的字节事件与唯一终结报告。 */
    struct UploadFailureObservation final
    {
        std::size_t ReportCalls{0};
        std::uint64_t ByteUploaded{0};
        Preview::Tuic::DatagramSessionReport SessionReport{};
    };

    /** @brief 保存上传结果与会话终结统计。 */
    auto RecordUploadFailureReport(
        const std::shared_ptr<UploadFailureObservation> &Observation,
        Preview::Tuic::DatagramSessionReport Report) -> void
    {
        if (Report.Kind == Preview::Foundation::TrafficEventKind::Bytes)
        {
            Observation->ByteUploaded += Report.UploadedBytes;
            return;
        }
        ++Observation->ReportCalls;
        Observation->SessionReport = Report;
    }
}

TEST(TuicAdmission, CloseCancelsSuspendedRelayAndReleasesBothLeases)
{
    Net::io_context Io;
    AdmissionHarness Harness(Io);
    const auto Executor = Io.get_executor();
    auto Probe = std::make_shared<SuspendedRelayProbe>();
    Probe->Executor = Executor;
    Probe->RelayGate = std::make_shared<Gate>(Executor, 1);
    Probe->RelayCompleted = std::make_shared<Gate>(Executor, 1);
    Preview::Tuic::AdmissionServices Services;
    Services.RelayStream = [Probe](Preview::Tuic::StreamRelayRequest)
    { return WaitForRelayCancellation(Probe); };
    Harness.Install(std::move(Services));
    Probe->Admission = Harness.Admission();
    Harness.SubmitUnidirectional(
        MakeScriptedStream(Io.get_executor(), MakeAuthWire()).Provider);
    Harness.SubmitExporter(TestExporter);
    Harness.SubmitBidirectional(
        MakeScriptedStream(Io.get_executor(), MakeConnectWire()).Provider);
    Io.run();

    EXPECT_TRUE(Probe->GateRegisteredAtClose);
    EXPECT_TRUE(Probe->CallbackCancelled);
    const auto ExpectedRelayCancellation = Net::experimental::error::make_error_code(
        Net::experimental::error::channel_cancelled);
    EXPECT_EQ(Probe->RelayError, ExpectedRelayCancellation)
        << "actual value=" << Probe->RelayError.value()
        << " category=" << Probe->RelayErrorCategory;
    EXPECT_EQ(Probe->RelayErrorCategory, ExpectedRelayCancellation.category().name());
    EXPECT_TRUE(Probe->CallbackExited);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveStreams(), 0U);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 0U);
    EXPECT_EQ(Harness.CloseOwnerCalls(), 1U);
    Harness.CloseAndDrain();
}

TEST(TuicAdmission, CloseCancelsSuspendedDatagramExchange)
{
    Net::io_context Io;
    AdmissionHarness Harness(Io);
    const auto Executor = Io.get_executor();
    auto Probe = std::make_shared<SuspendedDatagramProbe>();
    Probe->Executor = Executor;
    Probe->ExchangeGate = std::make_shared<Gate>(Executor, 1);
    Probe->ExchangeCompleted = std::make_shared<Gate>(Executor, 1);
    Preview::Tuic::AdmissionServices Services;
    Services.ReportDatagramSession = [Probe](Preview::Tuic::DatagramSessionReport Report)
    { RecordDatagramReport(Probe, std::move(Report)); };
    Services.ExchangeDatagram = [Probe](Preview::Tuic::DatagramRequest Request)
    { return WaitForDatagramCancellation(Probe, std::move(Request)); };
    Harness.Install(std::move(Services));
    Probe->Admission = Harness.Admission();
    auto Provider = std::make_shared<ScriptedDatagramProvider>(Executor, MakePacketWire());
    Harness.SubmitUnidirectional(
        MakeScriptedStream(Executor, MakeAuthWire()).Provider);
    Harness.SubmitExporter(TestExporter);
    Harness.SubmitDatagram(Provider);
    Io.run();

    EXPECT_TRUE(Probe->GateRegisteredAtClose);
    EXPECT_TRUE(Probe->CallbackCancelled);
    const auto ExpectedExchangeCancellation = Net::experimental::error::make_error_code(
        Net::experimental::error::channel_cancelled);
    EXPECT_EQ(Probe->ExchangeError, ExpectedExchangeCancellation)
        << "actual value=" << Probe->ExchangeError.value()
        << " category=" << Probe->ExchangeErrorCategory;
    EXPECT_EQ(Probe->ExchangeErrorCategory, ExpectedExchangeCancellation.category().name());
    EXPECT_TRUE(Probe->CallbackExited);
    EXPECT_GE(Provider->CancelCalls(), 1U);
    EXPECT_TRUE(Provider->IsClosed());
    EXPECT_EQ(Probe->ReportCalls, 1U);
    EXPECT_EQ(Probe->SessionReport.AccountId, Preview::AccountId{42});
    EXPECT_EQ(Probe->SessionReport.DatagramCount, 1U);
    EXPECT_EQ(Probe->SessionReport.UploadedBytes, 0U);
    EXPECT_EQ(Probe->SessionReport.DownloadedBytes, 0U);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 0U);
    EXPECT_EQ(Harness.CloseOwnerCalls(), 1U);
    Harness.CloseAndDrain();
}

TEST(TuicAdmission, ReportsCompletedUploadWhenDatagramResponseFails)
{
    Net::io_context Io;
    AdmissionHarness Harness(Io);
    auto Observation = std::make_shared<UploadFailureObservation>();
    Preview::Tuic::AdmissionServices Services;
    Services.ExchangeDatagram = [](Preview::Tuic::DatagramRequest Request)
        -> Net::awaitable<Preview::Tuic::DatagramResult>
    {
        EXPECT_EQ(Request.AccountId, Preview::AccountId{42});
        const auto UploadedBytes = static_cast<std::uint64_t>(Request.Payload.size());
        co_return Preview::Tuic::DatagramResult{
            Preview::Error::IoError, {}, {}, UploadedBytes, 0U};
    };
    Services.ReportDatagramSession = [Observation](
        Preview::Tuic::DatagramSessionReport Report)
    { RecordUploadFailureReport(Observation, std::move(Report)); };
    Harness.Install(std::move(Services));
    auto Provider = std::make_shared<ScriptedDatagramProvider>(
        Io.get_executor(), MakePacketWire());
    Harness.SubmitUnidirectional(
        MakeScriptedStream(Io.get_executor(), MakeAuthWire()).Provider);
    Harness.SubmitExporter(TestExporter);
    Harness.SubmitDatagram(Provider);
    Io.run();

    EXPECT_TRUE(Provider->IsClosed());
    EXPECT_EQ(Observation->ReportCalls, 1U);
    EXPECT_EQ(Observation->SessionReport.AccountId, Preview::AccountId{42});
    EXPECT_EQ(Observation->SessionReport.DatagramCount, 1U);
    EXPECT_EQ(Observation->SessionReport.UploadedBytes,
        std::string_view{"request-payload"}.size());
    EXPECT_EQ(Observation->SessionReport.DownloadedBytes, 0U);
    EXPECT_EQ(Observation->ByteUploaded, std::string_view{"request-payload"}.size());
    EXPECT_EQ(Observation->SessionReport.Kind,
        Preview::Foundation::TrafficEventKind::Completed);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 1U);
    Harness.CloseAndDrain();
}

TEST(TuicAdmission, PreservesRejectedOwnerCloseFailureUntilSameOwnerRetrySucceeds)
{
    Net::io_context Io;
    AdmissionHarness Harness(Io);
    const Preview::Fault::Failure OriginalFailure{
        Preview::Fault::Code::Blocked,
        std::make_error_code(std::errc::operation_not_permitted)};
    Harness.RejectCloseOwner(2U, OriginalFailure);
    Harness.SetExpectedCloseOwnerCalls(3U);
    Harness.Install();
    const auto Admission = Harness.Admission();
    Admission->OnClosed();
    Io.run();
    EXPECT_EQ(Harness.CloseOwnerCalls(), 1U);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 1U);

    Io.restart();
    std::optional<Preview::Fault::Failure> DrainFailure;
    std::exception_ptr DrainException;
    Net::co_spawn(Io, Admission->Drain(),
        [&DrainFailure, &DrainException](std::exception_ptr Error,
            std::expected<void, Preview::Fault::Failure> Result)
        {
            DrainException = std::move(Error);
            if (!DrainException && !Result) DrainFailure = Result.error();
        });
    Io.run();
    ASSERT_FALSE(DrainException);
    ASSERT_TRUE(DrainFailure);
    EXPECT_EQ(DrainFailure->Code, OriginalFailure.Code);
    EXPECT_EQ(DrainFailure->Native, OriginalFailure.Native);
    EXPECT_EQ(Harness.CloseOwnerCalls(), 2U);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 1U);

    Harness.CloseAndDrain();
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 0U);
}

TEST(TuicAdmission, RetriesRejectedCloseReceiptsAfterExecutorRestart)
{
    Net::io_context Io;
    auto Storage = std::make_shared<Preview::Executor::ClosingStorage>();
    auto &Ownership = Net::use_service<Preview::Executor::ContextOwnership>(Io);
    Ownership.Storage = Storage;
    AdmissionHarness Harness(Io);
    const auto Executor = Io.get_executor();
    auto Probe = std::make_shared<SuspendedDatagramProbe>();
    Probe->Executor = Executor;
    Probe->Context = &Io;
    Probe->StopBeforeClose = true;
    Probe->ExchangeGate = std::make_shared<Gate>(Executor, 1);
    Probe->ExchangeCompleted = std::make_shared<Gate>(Executor, 1);
    Preview::Tuic::AdmissionServices Services;
    Services.ReportDatagramSession = [Probe](Preview::Tuic::DatagramSessionReport Report)
    { RecordDatagramReport(Probe, std::move(Report)); };
    Services.ExchangeDatagram = [Probe](Preview::Tuic::DatagramRequest Request)
    { return WaitForDatagramCancellation(Probe, std::move(Request)); };
    Harness.Install(std::move(Services));
    Probe->Admission = Harness.Admission();
    const auto Admission = Harness.Admission();
    auto Provider = std::make_shared<ScriptedDatagramProvider>(Executor, MakePacketWire());
    Harness.SubmitUnidirectional(MakeScriptedStream(Executor, MakeAuthWire()).Provider);
    Harness.SubmitExporter(TestExporter);
    Io.run();
    ASSERT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 1U);
    const auto StorageBaseline = Storage->Pending();

    Io.restart();
    Harness.SubmitDatagram(Provider);
    Io.run();

    ASSERT_TRUE(Probe->GateRegisteredAtClose);
    EXPECT_FALSE(Probe->CallbackCancelled);
    EXPECT_EQ(Probe->ExchangeCalls, 1U);
    EXPECT_GE(Storage->Pending(), StorageBaseline + 2U);
    EXPECT_EQ(Harness.CloseOwnerCalls(), 0U);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 1U);

    Net::io_context DrainIo;
    std::optional<Preview::Fault::Failure> DrainFailure;
    std::exception_ptr DrainException;
    Net::co_spawn(DrainIo, Admission->Drain(),
        [&DrainFailure, &DrainException](std::exception_ptr Error,
            std::expected<void, Preview::Fault::Failure> Result)
        {
            DrainException = std::move(Error);
            if (!DrainException && !Result) DrainFailure = Result.error();
        });
    DrainIo.run();
    ASSERT_FALSE(DrainException);
    ASSERT_TRUE(DrainFailure);
    EXPECT_EQ(DrainFailure->Code, Preview::Fault::Code::Blocked);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 1U);

    Io.restart();
    Storage->Retry();
    Io.run();
    const auto ExpectedCancellation = Net::experimental::error::make_error_code(
        Net::experimental::error::channel_cancelled);
    EXPECT_TRUE(Probe->CallbackCancelled);
    EXPECT_EQ(Probe->ExchangeError, ExpectedCancellation);
    EXPECT_EQ(Probe->ExchangeErrorCategory, ExpectedCancellation.category().name());
    EXPECT_TRUE(Probe->CallbackExited);
    EXPECT_EQ(Probe->ExchangeCalls, 1U);
    EXPECT_TRUE(Provider->IsClosed());
    EXPECT_EQ(Probe->ReportCalls, 1U);
    EXPECT_EQ(Probe->SessionReport.DatagramCount, 1U);
    EXPECT_EQ(Harness.CloseOwnerCalls(), 1U);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 0U);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveStreams(), 0U);
    EXPECT_EQ(Storage->Pending(), StorageBaseline);
    Harness.CloseAndDrain();
}
TEST(TuicAdmission, LastOwnerReleaseDestroysAdmissionOnConnectionExecutor)
{
    Net::io_context Io;
    AdmissionHarness Harness(Io);
    std::thread::id ExecutorThreadId{};
    std::promise<void> CloseOwnerCalled;
    auto CloseOwnerCompleted = CloseOwnerCalled.get_future();
    bool CloseOwnerOnExecutor = false;
    Harness.SetCloseOwnerObserver([&]
                                  {
                                      CloseOwnerOnExecutor =
                                          std::this_thread::get_id() == ExecutorThreadId;
                                      CloseOwnerCalled.set_value();
                                  });
    Harness.Install();
    Harness.SubmitUnidirectional(
        MakeScriptedStream(Io.get_executor(), MakeAuthWire()).Provider);
    Harness.SubmitExporter(TestExporter);
    Io.run();
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 1U);

    Io.restart();
    auto Work = Net::make_work_guard(Io);
    std::promise<std::thread::id> ExecutorReady;
    auto ExecutorReadyFuture = ExecutorReady.get_future();
    std::thread ExecutorThread([&]
                               {
                                   ExecutorReady.set_value(std::this_thread::get_id());
                                   Io.run();
                               });
    ExecutorThreadId = ExecutorReadyFuture.get();
    auto LastOwner = Harness.TakeAdmission();
    EXPECT_FALSE(Harness.Admission());
    std::thread Releaser([Admission = std::move(LastOwner)]() mutable
                         { Admission.reset(); });
    Releaser.join();
    CloseOwnerCompleted.get();
    Work.reset();
    ExecutorThread.join();

    EXPECT_TRUE(CloseOwnerOnExecutor);
    EXPECT_EQ(Harness.CloseOwnerCalls(), 1U);
    EXPECT_EQ(Harness.Record()->Runtime()->ActiveConnections(), 0U);
}

