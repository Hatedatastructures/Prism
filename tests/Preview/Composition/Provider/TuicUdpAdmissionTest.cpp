/**
 * @file TuicUdpAdmissionTest.cpp
 * @brief TUIC 类型化 UDP 出口绑定与连接、流租约契约。
 */
#include "TuicFactoryFixture.hpp"

#include <gtest/gtest.h>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace
{
    namespace Net = boost::asio;
    using Udp = Net::ip::udp;

    using Preview::Testing::TuicFactory::MakeConnectWire;
    using Preview::Testing::TuicFactory::MakePacketWire;
    using Preview::Testing::TuicFactory::RecordingDatagramProvider;
    using Preview::Testing::TuicFactory::ScriptedStreamProvider;
    using Preview::Testing::TuicFactory::TestExporter;
    using Preview::Testing::TuicFactory::TuicTestHarness;

    struct UdpEchoState final
    {
        explicit UdpEchoState(Net::any_io_executor Executor)
            : Socket(std::make_shared<Udp::socket>(
                  std::move(Executor),
                  Udp::endpoint(Net::ip::address_v4::loopback(), 0)))
        {
        }

        std::shared_ptr<Udp::socket> Socket;
        std::atomic<bool> Stopping{false};
    };

    struct UdpExchangeRequest final
    {
        std::shared_ptr<UdpEchoState> Echo;
        Udp::endpoint Target;
        std::vector<std::uint8_t> Payload;
    };

    auto StopEchoServer(const std::shared_ptr<UdpEchoState> &Echo) -> void
    {
        Echo->Stopping.store(true, std::memory_order_release);
        boost::system::error_code Error;
        Echo->Socket->cancel(Error);
        Echo->Socket->close(Error);
    }

    [[nodiscard]] auto EchoOnce(std::shared_ptr<UdpEchoState> Echo)
        -> Net::awaitable<bool>
    {
        std::array<std::byte, 256> Buffer{};
        Udp::endpoint Peer;
        boost::system::error_code Error;
        const auto Count = co_await Echo->Socket->async_receive_from(
            Net::buffer(Buffer), Peer, Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            if (Echo->Stopping.load(std::memory_order_acquire) ||
                Error == Net::error::operation_aborted)
            {
                co_return false;
            }
            throw boost::system::system_error(Error);
        }
        (void)co_await Echo->Socket->async_send_to(
            Net::buffer(Buffer.data(), Count), Peer,
            Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            if (Echo->Stopping.load(std::memory_order_acquire) ||
                Error == Net::error::operation_aborted)
            {
                co_return false;
            }
            throw boost::system::system_error(Error);
        }
        co_return true;
    }

    [[nodiscard]] auto SendAndReceiveUdp(UdpExchangeRequest Request)
        -> Net::awaitable<Preview::Tuic::DatagramResult>
    {
        Udp::socket Egress(Request.Echo->Socket->get_executor());
        boost::system::error_code Error;
        Egress.open(Request.Target.protocol(), Error);
        if (Error)
        {
            StopEchoServer(Request.Echo);
            co_return Preview::Tuic::DatagramResult{Preview::Error::IoError, {}, {}};
        }

        const auto UploadedBytes = co_await Egress.async_send_to(
            Net::buffer(Request.Payload), Request.Target,
            Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            StopEchoServer(Request.Echo);
            co_return Preview::Tuic::DatagramResult{
                Preview::Error::IoError, {}, {}, 0U, 0U};
        }

        std::array<std::uint8_t, 256> Buffer{};
        Udp::endpoint Source;
        const auto Count = co_await Egress.async_receive_from(
            Net::buffer(Buffer), Source,
            Net::redirect_error(Net::use_awaitable, Error));
        if (Error || Count == 0U)
        {
            StopEchoServer(Request.Echo);
            co_return Preview::Tuic::DatagramResult{
                Preview::Error::IoError, {}, {}, UploadedBytes, 0U};
        }

        std::vector<std::uint8_t> Payload(Buffer.begin(), Buffer.begin() + Count);
        const auto SourceType = Source.address().is_v4()
                                    ? Preview::Tuic::AddressType::Ipv4
                                    : Preview::Tuic::AddressType::Ipv6;
        co_return Preview::Tuic::DatagramResult{
            Preview::Error::None,
            {SourceType, Source.address().to_string(), Source.port()},
            std::move(Payload),
            UploadedBytes,
            Count};
    }

    [[nodiscard]] auto ExchangeUdp(UdpExchangeRequest Request)
        -> Net::awaitable<Preview::Tuic::DatagramResult>
    {
        auto Egress = SendAndReceiveUdp(Request);
        auto Echo = Net::co_spawn(
            Request.Echo->Socket->get_executor(), EchoOnce(Request.Echo), Net::use_awaitable);
        using Net::experimental::awaitable_operators::operator&&;
        auto [Result, EchoSucceeded] =
            co_await (std::move(Egress) && std::move(Echo));
        if (!EchoSucceeded && Result.Status == Preview::Error::None)
        {
            co_return Preview::Tuic::DatagramResult{
                Preview::Error::IoError, {}, {}, Result.UploadedBytes, 0U};
        }
        co_return Result;
    }

    /** @brief 执行 TUIC UDP egress 并保留原测试观察值的具名服务任务。 */
    struct UdpExchangeTask final
    {
        std::shared_ptr<UdpEchoState> EchoServer;
        std::size_t &ExchangeCalls;
        std::string &EchoedPayload;

        /** @brief 解析原目标并执行有界 UDP 请求。 */
        auto Run(Preview::Tuic::DatagramRequest Request) const
            -> Net::awaitable<Preview::Tuic::DatagramResult>
        {
            ++ExchangeCalls;
            EXPECT_EQ(Request.AccountId, Preview::AccountId{8101});
            boost::system::error_code AddressError;
            const auto Address = Net::ip::make_address(Request.Target.Host, AddressError);
            if (AddressError)
            {
                co_return Preview::Tuic::DatagramResult{
                    Preview::Error::BadAddress, {}, {}};
            }
            const Udp::endpoint Target(Address, Request.Target.Port);
            auto Result = co_await ExchangeUdp(UdpExchangeRequest{
                EchoServer, Target, std::move(Request.Payload)});
            if (Result.Status == Preview::Error::None)
            {
                EchoedPayload.assign(Result.Payload.begin(), Result.Payload.end());
            }
            co_return Result;
        }

        /** @brief 将服务调用转交给具名 egress 任务。 */
        auto operator()(Preview::Tuic::DatagramRequest Request) const
            -> Net::awaitable<Preview::Tuic::DatagramResult>
        {
            return Run(std::move(Request));
        }
    };

    /** @brief 记录 datagram 会话报告并在正式终结报告后关闭回显 socket。 */
    struct UdpReportTask final
    {
        std::shared_ptr<UdpEchoState> EchoServer;
        std::size_t &ReportCalls;
        std::uint64_t &ByteUploaded;
        std::uint64_t &ByteDownloaded;
        Preview::Tuic::DatagramSessionReport &SessionReport;

        /** @brief 汇总字节事件或关闭终结后的回显 socket。 */
        auto Run(Preview::Tuic::DatagramSessionReport Report) const -> void
        {
            if (Report.Kind == Preview::Foundation::TrafficEventKind::Bytes)
            {
                ByteUploaded += Report.UploadedBytes;
                ByteDownloaded += Report.DownloadedBytes;
                return;
            }
            ++ReportCalls;
            SessionReport = Report;
            StopEchoServer(EchoServer);
        }

        /** @brief 将报告回调转交给具名统计任务。 */
        auto operator()(Preview::Tuic::DatagramSessionReport Report) const -> void
        {
            Run(std::move(Report));
        }
    };
} // namespace

TEST(TuicUdpAdmission, PreAuthProviderUsesTypedUdpEgressService)
{
    TuicTestHarness Harness;
    ASSERT_TRUE(Harness.Installed());
    auto EchoServer = std::make_shared<UdpEchoState>(Harness.Io.get_executor());
    const auto EchoEndpoint = EchoServer->Socket->local_endpoint();
    std::string EchoedPayload;
    std::size_t ExchangeCalls = 0;
    std::size_t ReportCalls = 0;
    std::uint64_t ByteUploaded = 0;
    std::uint64_t ByteDownloaded = 0;
    Preview::Tuic::DatagramSessionReport SessionReport{};

    Harness.Binding().Services.Resolve = [EchoEndpoint](Preview::Tuic::ResolveRequest)
        -> Net::awaitable<Preview::Tuic::ResolveResult>
    {
        co_return Preview::Tuic::ResolveResult{
            Preview::Error::None,
            {{Preview::Tuic::AddressType::Ipv4,
              EchoEndpoint.address().to_string(), EchoEndpoint.port()}}};
    };
    Harness.Binding().Services.ExchangeDatagram =
        UdpExchangeTask{EchoServer, ExchangeCalls, EchoedPayload};
    Harness.Binding().Services.ReportDatagramSession = UdpReportTask{
        EchoServer, ReportCalls, ByteUploaded, ByteDownloaded, SessionReport};

    auto Options = Harness.Configure();
    auto DatagramProvider = std::make_shared<RecordingDatagramProvider>(
        Harness.Io.get_executor());
    DatagramProvider->Inject(MakePacketWire());
    Options.OnDatagram(DatagramProvider);
    Harness.Io.run();

    EXPECT_FALSE(DatagramProvider->IsClosed());
    EXPECT_EQ(DatagramProvider->ReceiveCalls(), 0U);
    EXPECT_EQ(ExchangeCalls, 0U);

    Harness.Io.restart();
    auto AuthProvider = std::make_shared<ScriptedStreamProvider>(
        Harness.Io.get_executor(), Harness.ValidAuthWire());
    Options.OnUnidirectional(AuthProvider);
    Options.OnExporter(TestExporter);
    Harness.Io.run();

    EXPECT_EQ(Harness.Authenticator()->Calls(), 1U);
    EXPECT_EQ(ExchangeCalls, 1U);
    EXPECT_EQ(EchoedPayload, "udp-payload");
    EXPECT_EQ(DatagramProvider->ReceiveCalls(), 2U);
    EXPECT_EQ(DatagramProvider->SendCalls(), 1U);
    EXPECT_EQ(ReportCalls, 1U);
    EXPECT_EQ(ByteUploaded, std::string_view{"udp-payload"}.size());
    EXPECT_EQ(ByteDownloaded, EchoedPayload.size());
    EXPECT_EQ(SessionReport.Kind, Preview::Foundation::TrafficEventKind::Completed);
    EXPECT_EQ(SessionReport.AccountId, Preview::AccountId{8101});
    EXPECT_EQ(SessionReport.DatagramCount, 1U);
    EXPECT_EQ(SessionReport.UploadedBytes, std::string_view{"udp-payload"}.size());
    EXPECT_EQ(SessionReport.DownloadedBytes, EchoedPayload.size());
    EXPECT_EQ(Harness.AccountActiveConnections(), 1U);
    Harness.Io.restart();
    Options.OnClosed();
    Harness.Io.run();
    EXPECT_EQ(Harness.AccountActiveConnections(), 0U);
    Harness.CloseAndDrain(Options);
    StopEchoServer(EchoServer);
}

TEST(TuicUdpAdmission, DialFailureReleasesStreamLeaseButRetainsConnectionLease)
{
    TuicTestHarness Harness;
    ASSERT_TRUE(Harness.Installed());
    std::size_t DialCalls = 0;
    std::size_t CloseOwnerCalls = 0;
    Harness.Binding().Admission.CloseOwner = [&CloseOwnerCalls]()
        -> std::expected<void, Preview::Fault::Failure>
    {
        ++CloseOwnerCalls;
        return {};
    };
    Harness.Binding().Services.Dial = [&DialCalls](Preview::Tuic::DialRequest)
        -> Net::awaitable<std::expected<Preview::SharedTransmission, Preview::Fault::Failure>>
    {
        ++DialCalls;
        co_return std::unexpected(Preview::Fault::FromNative(
            Preview::make_error_code(Preview::Error::IoError)));
    };

    auto Options = Harness.Configure();
    Options.OnUnidirectional(std::make_shared<ScriptedStreamProvider>(
        Harness.Io.get_executor(), Harness.ValidAuthWire()));
    Options.OnExporter(TestExporter);
    Harness.Io.run();
    EXPECT_EQ(Harness.AccountActiveConnections(), 1U);

    Harness.Io.restart();
    auto Bidi = std::make_shared<ScriptedStreamProvider>(
        Harness.Io.get_executor(), MakeConnectWire());
    Options.OnStream(Bidi);
    Harness.Io.run();

    EXPECT_EQ(DialCalls, 1U);
    EXPECT_TRUE(Bidi->IsClosed());
    EXPECT_EQ(Harness.AccountActiveStreams(), 0U);
    EXPECT_EQ(Harness.AccountActiveConnections(), 1U);
    Harness.Io.restart();
    Options.OnClosed();
    Harness.Io.run();
    EXPECT_EQ(CloseOwnerCalls, 1U);
    EXPECT_EQ(Harness.AccountActiveConnections(), 0U);
    Harness.CloseAndDrain(Options);
}

TEST(TuicUdpAdmission, StoppedExecutorRetainsConnectionLeaseUntilCloseReceiptIsRetried)
{
    TuicTestHarness Harness;
    ASSERT_TRUE(Harness.Installed());
    std::size_t CloseOwnerCalls = 0;
    Harness.Binding().Admission.CloseOwner = [&CloseOwnerCalls]()
        -> std::expected<void, Preview::Fault::Failure>
    {
        ++CloseOwnerCalls;
        return {};
    };
    auto Options = Harness.Configure();
    Options.OnUnidirectional(std::make_shared<ScriptedStreamProvider>(
        Harness.Io.get_executor(), Harness.ValidAuthWire()));
    Options.OnExporter(TestExporter);
    Harness.Io.run();
    ASSERT_EQ(Harness.AccountActiveConnections(), 1U);

    Options.OnClosed();
    EXPECT_EQ(Harness.AccountActiveConnections(), 1U);
    EXPECT_EQ(CloseOwnerCalls, 0U);

    Harness.Io.restart();
    Options.OnClosed();
    Harness.Io.run();
    EXPECT_EQ(Harness.AccountActiveConnections(), 0U);
    EXPECT_EQ(CloseOwnerCalls, 1U);
    Harness.CloseAndDrain(Options);
}
