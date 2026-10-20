/**
 * @file VmessDatagramErrorTest.cpp
 * @brief VMess Dgram 未握手和对端关闭错误契约。
 */
#include "VmessConnSessionSupport.hpp"
#include <Prism/Protocols/Vmess/DatagramSession.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

namespace
{
    /** @brief 可在 VMess 握手后注入一次真实 category/value 读取失败的共享传输。 */
    class NativeDatagramFailureTransport final : public Prism::Transmission
    {
    public:
        explicit NativeDatagramFailureTransport(Prism::SharedTransmission Inner)
            : Prism::Transmission(Inner->Executor()), Inner_(std::move(Inner))
        {
        }

        auto SetReadFailure(std::error_code Native, std::size_t PartialBytes = 0) -> void
        {
            SetReadFault(Prism::Fault::FromNative(std::move(Native)), PartialBytes);
        }

        auto SetReadFault(Prism::Fault::Failure Failure, std::size_t PartialBytes = 0) -> void
        {
            ReadFailure_ = std::move(Failure);
            ReadFailureBytes_ = PartialBytes;
        }

        auto SetWriteFailure(std::error_code Native, std::size_t PartialBytes = 0) -> void
        {
            WriteFailure_ = std::move(Native);
            WriteFailureBytes_ = PartialBytes;
        }

        auto SetReadOverreportAfter(std::size_t ConfirmedBytes) -> void
        {
            ReadOverreportAfter_ = ConfirmedBytes;
            ReadBytesConfirmed_ = 0;
        }

        auto SetWriteOverreportAfter(std::size_t ConfirmedBytes) -> void
        {
            WriteOverreportAfter_ = ConfirmedBytes;
            WriteBytesConfirmed_ = 0;
        }

        [[nodiscard]] auto WriteFailureBytesReported() const noexcept -> std::size_t
        {
            return WriteFailureBytesReported_;
        }

        [[nodiscard]] auto ReadUnderlyingCalls() const noexcept -> std::size_t
        {
            return ReadUnderlyingCalls_;
        }

        [[nodiscard]] auto ReadBytesConfirmed() const noexcept -> std::size_t
        {
            return ReadBytesConfirmed_;
        }

        [[nodiscard]] auto WriteBytesConfirmed() const noexcept -> std::size_t
        {
            return WriteBytesConfirmed_;
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Inner_->Executor();
        }

        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Inner_->TransportType();
        }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            if (ReadOverreportAfter_)
            {
                if (ReadBytesConfirmed_ >= *ReadOverreportAfter_)
                {
                    ReadOverreportAfter_.reset();
                    const auto Reported = Buffer.size() + 1U;
                    Prism::Transmission::PostResult(
                        Executor(), std::move(Handler), Prism::IoResult{Reported, {}});
                    return;
                }
                const auto Count = (std::min)(
                    *ReadOverreportAfter_ - ReadBytesConfirmed_, Buffer.size());
                ++ReadUnderlyingCalls_;
                Inner_->ReadSome(Buffer.first(Count),
                    [this, Handler = std::move(Handler)](Prism::IoResult Result) mutable
                    {
                        ReadBytesConfirmed_ += Result.Bytes;
                        Handler(std::move(Result));
                    });
                return;
            }
            if (ReadFailure_)
            {
                const auto Bytes = (std::min)(ReadFailureBytes_, Buffer.size());
                if (Bytes != 0) Buffer.front() = std::byte{0x11};
                const auto Failure = *ReadFailure_;
                ReadFailure_.reset();
                Prism::Transmission::PostResult(
                    Executor(), std::move(Handler), Prism::IoResult{Bytes, Failure});
                return;
            }
            ++ReadUnderlyingCalls_;
            Inner_->ReadSome(Buffer, std::move(Handler));
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            if (WriteOverreportAfter_)
            {
                if (WriteBytesConfirmed_ >= *WriteOverreportAfter_)
                {
                    WriteOverreportAfter_.reset();
                    const auto Reported = Buffer.size() + 1U;
                    Prism::Transmission::PostResult(
                        Executor(), std::move(Handler), Prism::IoResult{Reported, {}});
                    return;
                }
                const auto Count = (std::min)(
                    *WriteOverreportAfter_ - WriteBytesConfirmed_, Buffer.size());
                Inner_->WriteSome(Buffer.first(Count),
                    [this, Handler = std::move(Handler)](Prism::IoResult Result) mutable
                    {
                        WriteBytesConfirmed_ += Result.Bytes;
                        Handler(std::move(Result));
                    });
                return;
            }
            if (WriteFailure_)
            {
                WriteFailureBytesReported_ = (std::min)(WriteFailureBytes_, Buffer.size());
                const auto Failure = Prism::Fault::FromNative(*WriteFailure_);
                WriteFailure_.reset();
                Prism::Transmission::PostResult(
                    Executor(), std::move(Handler),
                    Prism::IoResult{WriteFailureBytesReported_, Failure});
                return;
            }
            Inner_->WriteSome(Buffer, std::move(Handler));
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Inner_->WriteShutdown(std::move(Handler));
        }

        [[nodiscard]] auto OnClose() -> ControlResult override { return Inner_->Close(); }
        [[nodiscard]] auto OnCancel() -> ControlResult override { return Inner_->Cancel(); }
        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission* override
        { return Inner_.get(); }
        [[nodiscard]] auto NextLayer() const noexcept -> const Prism::Transmission* override
        { return Inner_.get(); }
        [[nodiscard]] auto Release() -> Prism::SharedTransmission override
        { return std::move(Inner_); }

    private:
        Prism::SharedTransmission Inner_;
        std::optional<Prism::Fault::Failure> ReadFailure_;
        std::optional<std::error_code> WriteFailure_;
        std::size_t ReadFailureBytes_{0};
        std::size_t WriteFailureBytes_{0};
        std::size_t WriteFailureBytesReported_{0};
        std::optional<std::size_t> ReadOverreportAfter_;
        std::optional<std::size_t> WriteOverreportAfter_;
        std::size_t ReadBytesConfirmed_{0};
        std::size_t WriteBytesConfirmed_{0};
        std::size_t ReadUnderlyingCalls_{0};
    };

    /** @brief 等待注入传输自己的活动退栈并验证物理退休。 */
    auto DrainNativeDatagramFailureTransport(
        std::shared_ptr<NativeDatagramFailureTransport> Transport)
        -> Net::awaitable<void>
    {
        const auto Activity = Transport->Activity();
        const auto Drain = co_await Activity->Drain();
        EXPECT_TRUE(Drain);
        EXPECT_TRUE(Activity->IsRetired());
    }

    /** @brief 关闭未被 Dgram 接管的注入传输并验证关闭回执。 */
    auto CloseNativeDatagramFailureTransport(
        std::shared_ptr<NativeDatagramFailureTransport> Transport)
        -> Net::awaitable<void>
    {
        const auto Receipt = co_await Prism::Testing::CloseFixture(Transport);
        Prism::Testing::ExpectFixtureCloseReceipt(Receipt);
        EXPECT_TRUE(Transport->Activity()->IsRetired());
    }

    /** @brief 关闭 Dgram/Conn 后排空注入传输自己的 Activity。 */
    auto CloseVmessDatagramAndNativeTransport(
        Vmess::SharedDgram Datagram,
        std::shared_ptr<NativeDatagramFailureTransport> Transport)
        -> Net::awaitable<void>
    {
        const auto Receipts = co_await CloseVmessDatagram(std::move(Datagram));
        Prism::Testing::ExpectFixtureCloseReceipt(Receipts.Datagram);
        Prism::Testing::ExpectFixtureCloseReceipt(Receipts.Connection);
        co_await DrainNativeDatagramFailureTransport(Transport);
    }

    /** @brief 构造数据报错误测试使用的固定 UUID。 */
    [[nodiscard]] auto MakeUuid() -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> Uuid{};
        for (std::size_t Index = 0; Index < Uuid.size(); ++Index)
        {
            Uuid[Index] = static_cast<std::uint8_t>(0x11 * (Index + 1));
        }
        return Uuid;
    }

    /** @brief 服务端接受后立即关闭 Dgram 与内部 Conn 两层 owner。 */
    auto RunClosedPeerServer(
        const std::shared_ptr<MemoryStream>& Upstream,
        const std::array<std::uint8_t, 16>& Uuid) -> Net::awaitable<bool>
    {
        Vmess::ServerConfig Config;
        Config.uuid = Uuid;
        auto AcceptResult = co_await AcceptVmessDatagram(Upstream, Config);
        EXPECT_TRUE(AcceptResult);
        if (AcceptResult) EXPECT_TRUE(AcceptResult->Connection);
        if (!AcceptResult || !AcceptResult->Connection)
        {
            co_return false;
        }
        auto Datagram = std::move(AcceptResult->Connection);
        const auto CloseReceipts = co_await CloseVmessDatagram(Datagram);
        Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipts.Datagram);
        Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipts.Connection);
        co_return true;
    }

    /** @brief 未握手 Dgram 的包操作返回协议 NotOpen 并完整退出 owner。 */
    auto RunNotHandshakenOperations(Net::io_context& Context) -> Net::awaitable<void>
    {
        auto Connection = std::make_shared<Vmess::Conn<>>(Vmess::ConnOptions{
            .Executor = Context.get_executor(), .Uuid = MakeUuid()});
        auto Datagram = std::make_shared<Vmess::Dgram<>>(Connection);
        const std::string Payload = "x";
        EXPECT_EQ(DatagramStatus(co_await Datagram->AsyncSendDatagram(AsU8Span(Payload))),
                  FaultStatus(Error::NotOpen));
        std::vector<std::uint8_t> Received;
        EXPECT_EQ(DatagramStatus(co_await Datagram->AsyncReceiveDatagram(Received)),
                  FaultStatus(Error::NotOpen));
        const auto CloseReceipts = co_await CloseVmessDatagram(Datagram);
        Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipts.Datagram);
        Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipts.Connection);
    }

    /** @brief 对端最终关闭后保留发送的连接中止与接收 EOF。 */
    auto RunPeerClosedOperations(Net::io_context& Context) -> Net::awaitable<void>
    {
        auto Pair = MakeVmessTransportPair(Context);
        const auto Uuid = MakeUuid();
        VmessTestTask<bool> ServerTask(Context.get_executor());
        ServerTask.Start(RunClosedPeerServer(Pair.SecondOwner, Uuid));

        Vmess::ClientConfig Config;
        Config.uuid = Uuid;
        auto ConnectResult = co_await Vmess::ConnectPacket(
            Pair.FirstOwner, Config,
            MakeAddress(Vmess::AddressType::Domain, "example.com", 53));
        EXPECT_TRUE(ConnectResult);
        if (ConnectResult) EXPECT_TRUE(*ConnectResult);
        Vmess::SharedDgram Datagram;
        if (ConnectResult && *ConnectResult) Datagram = std::move(*ConnectResult);
        EXPECT_TRUE(Datagram);
        if (!Datagram)
        {
            const auto Endpoints = co_await CloseVmessEndpoints(Pair);
            Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
            Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
            (void)co_await ServerTask.Wait();
            co_return;
        }
        EXPECT_TRUE(co_await ServerTask.Wait());

        const std::string Payload = "x";
        EXPECT_EQ(DatagramStatus(co_await Datagram->AsyncSendDatagram(AsU8Span(Payload))),
                  Prism::Fault::Code::ConnectionAborted);
        std::vector<std::uint8_t> Received;
        EXPECT_EQ(DatagramStatus(co_await Datagram->AsyncReceiveDatagram(Received)),
                  Prism::Fault::Code::Eof);
        const auto CloseReceipts = co_await CloseVmessDatagram(Datagram);
        Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipts.Datagram);
        Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipts.Connection);
        const auto Endpoints = co_await CloseVmessEndpoints(Pair);
        Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
        Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
    }

    /** @brief 验证 VMess chunk 部分写入失败保留 Native category/value。 */
    auto RunNativePartialPacketWriteFailure(
        Net::io_context &Context, std::error_code Native) -> Net::awaitable<void>
    {
        auto Pair = MakeVmessTransportPair(Context);
        auto ClientTransport = std::make_shared<NativeDatagramFailureTransport>(Pair.FirstOwner);
        const auto Uuid = MakeUuid();
        Vmess::ServerConfig ServerConfig;
        ServerConfig.uuid = Uuid;
        using ServerResultType = std::expected<Vmess::AcceptedDatagram, Prism::Fault::Failure>;
        VmessTestTask<ServerResultType> ServerTask(
            Context.get_executor());
        ServerTask.Start(AcceptVmessDatagram(Pair.SecondOwner, ServerConfig));

        Vmess::ClientConfig ClientConfig;
        ClientConfig.uuid = Uuid;
        auto ClientResult = co_await Vmess::ConnectPacket(
            ClientTransport, ClientConfig,
            MakeAddress(Vmess::AddressType::Ipv4, "127.0.0.1", 53));
        EXPECT_TRUE(ClientResult);
        if (ClientResult) EXPECT_TRUE(*ClientResult);
        Vmess::SharedDgram ClientDatagram;
        if (ClientResult && *ClientResult) ClientDatagram = std::move(*ClientResult);
        auto AcceptResult = co_await ServerTask.Wait();
        EXPECT_TRUE(AcceptResult);
        if (AcceptResult) EXPECT_TRUE(AcceptResult->Connection);
        Vmess::SharedDgram ServerDatagram;
        if (AcceptResult && AcceptResult->Connection)
        {
            EXPECT_EQ(AcceptResult->Request.Cmd, static_cast<std::uint8_t>(Vmess::Command::Udp));
            ServerDatagram = std::move(AcceptResult->Connection);
        }
        if (!ClientDatagram || !ServerDatagram)
        {
            if (ClientDatagram)
            {
                co_await CloseVmessDatagramAndNativeTransport(
                    ClientDatagram, ClientTransport);
            }
            else
            {
                co_await CloseNativeDatagramFailureTransport(ClientTransport);
            }
            if (ServerDatagram)
            {
                const auto ServerReceipts = co_await CloseVmessDatagram(ServerDatagram);
                Prism::Testing::ExpectFixtureCloseReceipt(ServerReceipts.Datagram);
                Prism::Testing::ExpectFixtureCloseReceipt(ServerReceipts.Connection);
            }
            const auto Endpoints = co_await CloseVmessEndpoints(Pair);
            Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
            Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
            co_return;
        }

        ClientTransport->SetWriteFailure(Native, 1);
        const std::string Payload = "partial-vmess-native";
        const auto Result = co_await ClientDatagram->AsyncSendDatagram(AsU8Span(Payload));
        EXPECT_TRUE(Result.Failed());
        EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Result.Failure.Native, Native);
        EXPECT_EQ(Result.PayloadBytes, 0U);
        EXPECT_EQ(Result.WireBytes, ClientTransport->WriteFailureBytesReported());
        EXPECT_EQ(ClientTransport->WriteFailureBytesReported(), 1U);

        co_await CloseVmessDatagramAndNativeTransport(ClientDatagram, ClientTransport);
        const auto ServerReceipts = co_await CloseVmessDatagram(ServerDatagram);
        Prism::Testing::ExpectFixtureCloseReceipt(ServerReceipts.Datagram);
        Prism::Testing::ExpectFixtureCloseReceipt(ServerReceipts.Connection);
        const auto Endpoints = co_await CloseVmessEndpoints(Pair);
        Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
        Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
    }

    /** @brief 验证 VMess 真实 Run 保留包读取的 Native 失败。 */
    auto RunNativePacketReadFailureSurvivesDatagramRun(
        Net::io_context &Context, std::error_code Native) -> Net::awaitable<void>
    {
        auto Pair = MakeVmessTransportPair(Context);
        auto ServerTransport = std::make_shared<NativeDatagramFailureTransport>(Pair.SecondOwner);
        const auto Uuid = MakeUuid();
        Vmess::ServerConfig ServerConfig;
        ServerConfig.uuid = Uuid;
        using ServerResultType = std::expected<Vmess::AcceptedDatagram, Prism::Fault::Failure>;
        VmessTestTask<ServerResultType> ServerTask(
            Context.get_executor());
        ServerTask.Start(AcceptVmessDatagram(ServerTransport, ServerConfig));
        Vmess::ClientConfig ClientConfig;
        ClientConfig.uuid = Uuid;
        auto ClientResult = co_await Vmess::ConnectPacket(
            Pair.FirstOwner, ClientConfig,
            MakeAddress(Vmess::AddressType::Ipv4, "127.0.0.1", 53));
        EXPECT_TRUE(ClientResult);
        if (ClientResult) EXPECT_TRUE(*ClientResult);
        Vmess::SharedDgram ClientDatagram;
        if (ClientResult && *ClientResult) ClientDatagram = std::move(*ClientResult);
        EXPECT_TRUE(ClientDatagram);
        auto AcceptResult = co_await ServerTask.Wait();
        EXPECT_TRUE(AcceptResult);
        if (AcceptResult) EXPECT_TRUE(AcceptResult->Connection);
        Vmess::SharedDgram ServerDatagram;
        if (AcceptResult && AcceptResult->Connection)
        {
            EXPECT_EQ(AcceptResult->Request.Cmd, static_cast<std::uint8_t>(Vmess::Command::Udp));
            ServerDatagram = std::move(AcceptResult->Connection);
        }
        EXPECT_TRUE(ServerDatagram);
        if (!ClientDatagram || !ServerDatagram)
        {
            if (ClientDatagram)
            {
                const auto ClientReceipts = co_await CloseVmessDatagram(ClientDatagram);
                Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipts.Datagram);
                Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipts.Connection);
            }
            if (ServerDatagram)
            {
                co_await CloseVmessDatagramAndNativeTransport(
                    ServerDatagram, ServerTransport);
            }
            else
            {
                co_await CloseNativeDatagramFailureTransport(ServerTransport);
            }
            const auto Endpoints = co_await CloseVmessEndpoints(Pair);
            Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
            Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
            co_return;
        }

        ServerTransport->SetReadFailure(Native, 1);
        const auto Host = Prism::Network::ParseHost("127.0.0.1");
        auto SessionResult = Vmess::DatagramSession::Create(
            ServerDatagram, {*Host, 53},
            Vmess::DatagramSession::Options{{}, {}});
        EXPECT_TRUE(SessionResult);
        if (!SessionResult)
        {
            const auto ClientReceipts = co_await CloseVmessDatagram(ClientDatagram);
            Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipts.Datagram);
            Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipts.Connection);
            co_await CloseVmessDatagramAndNativeTransport(ServerDatagram, ServerTransport);
            const auto EndpointReceipts = co_await CloseVmessEndpoints(Pair);
            Prism::Testing::ExpectFixtureCloseReceipt(EndpointReceipts.First);
            Prism::Testing::ExpectFixtureCloseReceipt(EndpointReceipts.Second);
            co_return;
        }
        auto Session = std::move(*SessionResult);
        const auto Result = co_await Session->Run();
        EXPECT_FALSE(Result);
        if (!Result)
        {
            EXPECT_EQ(Result.error().Code, Prism::Fault::Code::ConnectionReset);
            EXPECT_EQ(Result.error().Native, Native);
        }
        const auto ClientReceipts = co_await CloseVmessDatagram(ClientDatagram);
        Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipts.Datagram);
        Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipts.Connection);
        co_await CloseVmessDatagramAndNativeTransport(ServerDatagram, ServerTransport);
        const auto EndpointReceipts = co_await CloseVmessEndpoints(Pair);
        Prism::Testing::ExpectFixtureCloseReceipt(EndpointReceipts.First);
        Prism::Testing::ExpectFixtureCloseReceipt(EndpointReceipts.Second);
    }

    /** @brief 帧边界零进度后，下一包仍可读取。 */
    auto RunZeroProgressReadAtFrameBoundaryAllowsRetry(
        Net::io_context &Context, Prism::Fault::Failure ReadFault) -> Net::awaitable<void>
    {
        auto Pair = MakeVmessTransportPair(Context);
        auto ServerTransport = std::make_shared<NativeDatagramFailureTransport>(Pair.SecondOwner);
        const auto Uuid = MakeUuid();
        Vmess::ServerConfig ServerConfig;
        ServerConfig.uuid = Uuid;
        using ServerResultType = std::expected<Vmess::AcceptedDatagram, Prism::Fault::Failure>;
        VmessTestTask<ServerResultType> ServerTask(Context.get_executor());
        ServerTask.Start(AcceptVmessDatagram(ServerTransport, ServerConfig));

        Vmess::ClientConfig ClientConfig;
        ClientConfig.uuid = Uuid;
        auto ClientResult = co_await Vmess::ConnectPacket(
            Pair.FirstOwner, ClientConfig,
            MakeAddress(Vmess::AddressType::Ipv4, "127.0.0.1", 53));
        EXPECT_TRUE(ClientResult && *ClientResult);
        Vmess::SharedDgram ClientDatagram;
        if (ClientResult && *ClientResult) ClientDatagram = std::move(*ClientResult);
        auto AcceptResult = co_await ServerTask.Wait();
        EXPECT_TRUE(AcceptResult && AcceptResult->Connection);
        Vmess::SharedDgram ServerDatagram;
        if (AcceptResult && AcceptResult->Connection)
            ServerDatagram = std::move(AcceptResult->Connection);
        if (!ClientDatagram || !ServerDatagram)
        {
            if (ClientDatagram)
            {
                const auto Receipts = co_await CloseVmessDatagram(ClientDatagram);
                Prism::Testing::ExpectFixtureCloseReceipt(Receipts.Datagram);
                Prism::Testing::ExpectFixtureCloseReceipt(Receipts.Connection);
            }
            if (ServerDatagram)
                co_await CloseVmessDatagramAndNativeTransport(ServerDatagram, ServerTransport);
            else
                co_await CloseNativeDatagramFailureTransport(ServerTransport);
            const auto Endpoints = co_await CloseVmessEndpoints(Pair);
            Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
            Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
            co_return;
        }
        const auto ReadsBeforeFault = ServerTransport->ReadUnderlyingCalls();
        ServerTransport->SetReadFault(std::move(ReadFault));
        std::vector<std::uint8_t> ReceivedPayload;
        const auto First = co_await ServerDatagram->AsyncReceiveDatagram(ReceivedPayload);
        EXPECT_EQ(First.PayloadBytes, 0U);
        EXPECT_EQ(First.WireBytes, 0U);
        EXPECT_EQ(First.Failure.Code, Prism::Fault::Code::WouldBlock);
        EXPECT_FALSE(First.Failure.Native);
        EXPECT_TRUE(ReceivedPayload.empty());
        EXPECT_EQ(ServerTransport->ReadUnderlyingCalls(), ReadsBeforeFault);
        const std::vector<std::uint8_t> ExpectedPayload{0xA1, 0xB2, 0xC3, 0xD4};
        const auto Sent = co_await ClientDatagram->AsyncSendDatagram(
            std::span<const std::uint8_t>(ExpectedPayload));
        EXPECT_FALSE(Sent.Failure.Failed());
        EXPECT_EQ(Sent.PayloadBytes, ExpectedPayload.size());
        EXPECT_GT(Sent.WireBytes, 0U);
        if (Sent.Failure.Failed())
        {
            const auto ClientReceipts = co_await CloseVmessDatagram(ClientDatagram);
            Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipts.Datagram);
            Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipts.Connection);
            co_await CloseVmessDatagramAndNativeTransport(ServerDatagram, ServerTransport);
            const auto Endpoints = co_await CloseVmessEndpoints(Pair);
            Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
            Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
            co_return;
        }

        const auto ReadsBeforeRetry = ServerTransport->ReadUnderlyingCalls();
        const auto Retry = co_await ServerDatagram->AsyncReceiveDatagram(ReceivedPayload);
        EXPECT_FALSE(Retry.Failure.Failed());
        EXPECT_EQ(Retry.PayloadBytes, ExpectedPayload.size());
        EXPECT_GT(Retry.WireBytes, 0U);
        EXPECT_EQ(ReceivedPayload, ExpectedPayload);
        EXPECT_GT(ServerTransport->ReadUnderlyingCalls(), ReadsBeforeRetry);

        const auto ClientReceipts = co_await CloseVmessDatagram(ClientDatagram);
        Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipts.Datagram);
        Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipts.Connection);
        co_await CloseVmessDatagramAndNativeTransport(ServerDatagram, ServerTransport);
        const auto Endpoints = co_await CloseVmessEndpoints(Pair);
        Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
        Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
    }

    /** @brief 超报写入长度时只保留已由底层确认的 wire 字节。 */
    auto RunOverreportedPacketWriteKeepsConfirmedWireBytes(
        Net::io_context& Context) -> Net::awaitable<void>
    {
        auto Pair = MakeVmessTransportPair(Context);
        auto ClientTransport = std::make_shared<NativeDatagramFailureTransport>(Pair.FirstOwner);
        const auto Uuid = MakeUuid();
        Vmess::ServerConfig ServerConfig;
        ServerConfig.uuid = Uuid;
        using ServerResultType = std::expected<Vmess::AcceptedDatagram, Prism::Fault::Failure>;
        VmessTestTask<ServerResultType> ServerTask(Context.get_executor());
        ServerTask.Start(AcceptVmessDatagram(Pair.SecondOwner, ServerConfig));

        Vmess::ClientConfig ClientConfig;
        ClientConfig.uuid = Uuid;
        auto ClientResult = co_await Vmess::ConnectPacket(
            ClientTransport, ClientConfig,
            MakeAddress(Vmess::AddressType::Ipv4, "127.0.0.1", 53));
        EXPECT_TRUE(ClientResult);
        if (ClientResult) EXPECT_TRUE(*ClientResult);
        Vmess::SharedDgram ClientDatagram;
        if (ClientResult && *ClientResult) ClientDatagram = std::move(*ClientResult);
        auto AcceptResult = co_await ServerTask.Wait();
        EXPECT_TRUE(AcceptResult);
        if (AcceptResult) EXPECT_TRUE(AcceptResult->Connection);
        Vmess::SharedDgram ServerDatagram;
        if (AcceptResult && AcceptResult->Connection)
        {
            EXPECT_EQ(AcceptResult->Request.Cmd, static_cast<std::uint8_t>(Vmess::Command::Udp));
            ServerDatagram = std::move(AcceptResult->Connection);
        }
        if (!ClientDatagram || !ServerDatagram)
        {
            if (ClientDatagram)
            {
                co_await CloseVmessDatagramAndNativeTransport(
                    ClientDatagram, ClientTransport);
            }
            else
            {
                co_await CloseNativeDatagramFailureTransport(ClientTransport);
            }
            if (ServerDatagram)
            {
                const auto ServerReceipts = co_await CloseVmessDatagram(ServerDatagram);
                Prism::Testing::ExpectFixtureCloseReceipt(ServerReceipts.Datagram);
                Prism::Testing::ExpectFixtureCloseReceipt(ServerReceipts.Connection);
            }
            const auto Endpoints = co_await CloseVmessEndpoints(Pair);
            Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
            Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
            co_return;
        }

        ClientTransport->SetWriteOverreportAfter(3U);
        const std::string Payload = "overreported-vmess-write";
        const auto Result = co_await ClientDatagram->AsyncSendDatagram(AsU8Span(Payload));
        EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::InvalidArgument);
        EXPECT_FALSE(Result.Failure.Native);
        EXPECT_EQ(Result.PayloadBytes, 0U);
        EXPECT_EQ(Result.WireBytes, 3U);
        EXPECT_EQ(ClientTransport->WriteBytesConfirmed(), 3U);

        co_await CloseVmessDatagramAndNativeTransport(ClientDatagram, ClientTransport);
        const auto ServerReceipts = co_await CloseVmessDatagram(ServerDatagram);
        Prism::Testing::ExpectFixtureCloseReceipt(ServerReceipts.Datagram);
        Prism::Testing::ExpectFixtureCloseReceipt(ServerReceipts.Connection);
        const auto Endpoints = co_await CloseVmessEndpoints(Pair);
        Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
        Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
    }

    /** @brief 超报读取长度时保留真实进度并将失败固定为后续读取终态。 */
    auto RunOverreportedPacketReadKeepsConfirmedWireBytes(
        Net::io_context& Context) -> Net::awaitable<void>
    {
        auto Pair = MakeVmessTransportPair(Context);
        auto ServerTransport = std::make_shared<NativeDatagramFailureTransport>(Pair.SecondOwner);
        const auto Uuid = MakeUuid();
        Vmess::ServerConfig ServerConfig;
        ServerConfig.uuid = Uuid;
        using ServerResultType = std::expected<Vmess::AcceptedDatagram, Prism::Fault::Failure>;
        VmessTestTask<ServerResultType> ServerTask(Context.get_executor());
        ServerTask.Start(AcceptVmessDatagram(ServerTransport, ServerConfig));

        Vmess::ClientConfig ClientConfig;
        ClientConfig.uuid = Uuid;
        auto ClientResult = co_await Vmess::ConnectPacket(
            Pair.FirstOwner, ClientConfig,
            MakeAddress(Vmess::AddressType::Ipv4, "127.0.0.1", 53));
        EXPECT_TRUE(ClientResult);
        if (ClientResult) EXPECT_TRUE(*ClientResult);
        Vmess::SharedDgram ClientDatagram;
        if (ClientResult && *ClientResult) ClientDatagram = std::move(*ClientResult);
        auto AcceptResult = co_await ServerTask.Wait();
        EXPECT_TRUE(AcceptResult);
        if (AcceptResult) EXPECT_TRUE(AcceptResult->Connection);
        Vmess::SharedDgram ServerDatagram;
        if (AcceptResult && AcceptResult->Connection)
        {
            EXPECT_EQ(AcceptResult->Request.Cmd, static_cast<std::uint8_t>(Vmess::Command::Udp));
            ServerDatagram = std::move(AcceptResult->Connection);
        }
        if (!ClientDatagram || !ServerDatagram)
        {
            if (ClientDatagram)
            {
                const auto ClientReceipts = co_await CloseVmessDatagram(ClientDatagram);
                Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipts.Datagram);
                Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipts.Connection);
            }
            if (ServerDatagram)
            {
                co_await CloseVmessDatagramAndNativeTransport(
                    ServerDatagram, ServerTransport);
            }
            else
            {
                co_await CloseNativeDatagramFailureTransport(ServerTransport);
            }
            const auto Endpoints = co_await CloseVmessEndpoints(Pair);
            Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
            Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
            co_return;
        }

        const std::string Payload = "packet-to-trigger-overreported-read";
        const auto Sent = co_await ClientDatagram->AsyncSendDatagram(AsU8Span(Payload));
        EXPECT_FALSE(Sent.Failed());
        if (Sent.Failed())
        {
            const auto ClientReceipts = co_await CloseVmessDatagram(ClientDatagram);
            Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipts.Datagram);
            Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipts.Connection);
            co_await CloseVmessDatagramAndNativeTransport(ServerDatagram, ServerTransport);
            const auto Endpoints = co_await CloseVmessEndpoints(Pair);
            Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
            Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
            co_return;
        }

        const auto ReadsBeforePacket = ServerTransport->ReadUnderlyingCalls();
        ServerTransport->SetReadOverreportAfter(1U);
        std::vector<std::uint8_t> Received;
        const auto Result = co_await ServerDatagram->AsyncReceiveDatagram(Received);
        EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::InvalidArgument);
        EXPECT_FALSE(Result.Failure.Native);
        EXPECT_EQ(Result.PayloadBytes, 0U);
        EXPECT_EQ(Result.WireBytes, 1U);
        EXPECT_TRUE(Received.empty());
        EXPECT_EQ(ServerTransport->ReadBytesConfirmed(), 1U);
        EXPECT_EQ(ServerTransport->ReadUnderlyingCalls(), ReadsBeforePacket + 1U);

        std::vector<std::uint8_t> RetryPayload;
        const auto Retry = co_await ServerDatagram->AsyncReceiveDatagram(RetryPayload);
        EXPECT_EQ(Retry.Failure.Code, Prism::Fault::Code::InvalidArgument);
        EXPECT_FALSE(Retry.Failure.Native);
        EXPECT_EQ(Retry.PayloadBytes, 0U);
        EXPECT_EQ(Retry.WireBytes, 0U);
        EXPECT_TRUE(RetryPayload.empty());
        EXPECT_EQ(ServerTransport->ReadUnderlyingCalls(), ReadsBeforePacket + 1U);

        const auto ClientReceipts = co_await CloseVmessDatagram(ClientDatagram);
        Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipts.Datagram);
        Prism::Testing::ExpectFixtureCloseReceipt(ClientReceipts.Connection);
        co_await CloseVmessDatagramAndNativeTransport(ServerDatagram, ServerTransport);
        const auto Endpoints = co_await CloseVmessEndpoints(Pair);
        Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
        Prism::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
    }
} // namespace

TEST(VmessDgramErr, NotHandshakenOperations)
{
    Net::io_context Context;
    RunCoroutine(Context, RunNotHandshakenOperations(Context));
}

TEST(VmessDgramErr, PeerClosedOperations)
{
    Net::io_context Context;
    RunCoroutine(Context, RunPeerClosedOperations(Context));
}

TEST(VmessDgramErr, NativePacketReadFailureSurvivesDatagramRun)
{
    Net::io_context Context;
    const auto Native = std::make_error_code(std::errc::connection_reset);
    RunCoroutine(Context,
        RunNativePacketReadFailureSurvivesDatagramRun(Context, Native));
}

TEST(VmessDgramErr, ZeroProgressAtFrameBoundaryAllowsRetry)
{
    Net::io_context Context;
    RunCoroutine(Context, RunZeroProgressReadAtFrameBoundaryAllowsRetry(
        Context, {Prism::Fault::Code::WouldBlock}));
    Context.restart();
    RunCoroutine(Context, RunZeroProgressReadAtFrameBoundaryAllowsRetry(Context, {}));
}

TEST(VmessDgramErr, NativePartialPacketWriteFailure)
{
    Net::io_context Context;
    const auto Native = std::make_error_code(std::errc::connection_reset);
    RunCoroutine(Context, RunNativePartialPacketWriteFailure(Context, Native));
}

TEST(VmessDgramErr, OverreportedPacketWriteKeepsConfirmedWireBytes)
{
    Net::io_context Context;
    RunCoroutine(Context, RunOverreportedPacketWriteKeepsConfirmedWireBytes(Context));
}

TEST(VmessDgramErr, OverreportedPacketReadKeepsConfirmedWireBytes)
{
    Net::io_context Context;
    RunCoroutine(Context, RunOverreportedPacketReadKeepsConfirmedWireBytes(Context));
}

TEST(VmessDgramErr, RejectsNullCarrierBeforePumpConstruction)
{
    const auto Host = Prism::Network::ParseHost("127.0.0.1");
    ASSERT_TRUE(Host);

    auto Session = Vmess::DatagramSession::Create(
        {}, {*Host, 53}, Vmess::DatagramSession::Options{{}, {}});
    ASSERT_FALSE(Session);
    EXPECT_EQ(Session.error().Code, Prism::Fault::Code::InvalidArgument);
}
