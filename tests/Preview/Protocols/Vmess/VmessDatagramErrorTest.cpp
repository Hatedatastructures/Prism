/**
 * @file VmessDatagramErrorTest.cpp
 * @brief VMess Dgram 未握手和对端关闭错误契约。
 */
#include "VmessConnSessionSupport.hpp"
#include <Preview/Protocols/Vmess/DatagramSession.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <expected>
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
    class NativeDatagramFailureTransport final : public Preview::Transmission
    {
    public:
        explicit NativeDatagramFailureTransport(Preview::SharedTransmission Inner)
            : Preview::Transmission(Inner->Executor()), Inner_(std::move(Inner))
        {
        }

        auto SetReadFailure(std::error_code Native, std::size_t PartialBytes = 0) -> void
        {
            ReadFailure_ = std::move(Native);
            ReadFailureBytes_ = PartialBytes;
        }

        auto SetWriteFailure(std::error_code Native, std::size_t PartialBytes = 0) -> void
        {
            WriteFailure_ = std::move(Native);
            WriteFailureBytes_ = PartialBytes;
        }

        [[nodiscard]] auto WriteFailureBytesReported() const noexcept -> std::size_t
        {
            return WriteFailureBytesReported_;
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
            if (ReadFailure_)
            {
                const auto Bytes = (std::min)(ReadFailureBytes_, Buffer.size());
                if (Bytes != 0) Buffer.front() = std::byte{0x11};
                const auto Failure = Preview::Fault::FromNative(*ReadFailure_);
                ReadFailure_.reset();
                Preview::Transport::Detail::PostResult(
                    Executor(), std::move(Handler), Preview::IoResult{Bytes, Failure});
                return;
            }
            Inner_->ReadSome(Buffer, std::move(Handler));
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            if (WriteFailure_)
            {
                WriteFailureBytesReported_ = (std::min)(WriteFailureBytes_, Buffer.size());
                const auto Failure = Preview::Fault::FromNative(*WriteFailure_);
                WriteFailure_.reset();
                Preview::Transport::Detail::PostResult(
                    Executor(), std::move(Handler),
                    Preview::IoResult{WriteFailureBytesReported_, Failure});
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
        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission* override
        { return Inner_.get(); }
        [[nodiscard]] auto NextLayer() const noexcept -> const Preview::Transmission* override
        { return Inner_.get(); }
        [[nodiscard]] auto Release() -> Preview::SharedTransmission override
        { return std::move(Inner_); }

    private:
        Preview::SharedTransmission Inner_;
        std::optional<std::error_code> ReadFailure_;
        std::optional<std::error_code> WriteFailure_;
        std::size_t ReadFailureBytes_{0};
        std::size_t WriteFailureBytes_{0};
        std::size_t WriteFailureBytesReported_{0};
    };

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
        Preview::Testing::ExpectFixtureCloseReceipt(CloseReceipts.Datagram);
        Preview::Testing::ExpectFixtureCloseReceipt(CloseReceipts.Connection);
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
        Preview::Testing::ExpectFixtureCloseReceipt(CloseReceipts.Datagram);
        Preview::Testing::ExpectFixtureCloseReceipt(CloseReceipts.Connection);
    }

    /** @brief 对端最终关闭后保持发送 IoError 与接收 UnexpectedEof。 */
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
            Preview::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
            Preview::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
            (void)co_await ServerTask.Wait();
            co_return;
        }
        EXPECT_TRUE(co_await ServerTask.Wait());

        const std::string Payload = "x";
        EXPECT_EQ(DatagramStatus(co_await Datagram->AsyncSendDatagram(AsU8Span(Payload))),
                  FaultStatus(Error::IoError));
        std::vector<std::uint8_t> Received;
        EXPECT_EQ(DatagramStatus(co_await Datagram->AsyncReceiveDatagram(Received)),
                  Preview::Fault::Code::Eof);
        const auto CloseReceipts = co_await CloseVmessDatagram(Datagram);
        Preview::Testing::ExpectFixtureCloseReceipt(CloseReceipts.Datagram);
        Preview::Testing::ExpectFixtureCloseReceipt(CloseReceipts.Connection);
        const auto Endpoints = co_await CloseVmessEndpoints(Pair);
        Preview::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
        Preview::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
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
        using ServerResultType = std::expected<Vmess::AcceptedDatagram, Preview::Fault::Failure>;
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
            if (ClientDatagram) (void)co_await CloseVmessDatagram(ClientDatagram);
            if (ServerDatagram) (void)co_await CloseVmessDatagram(ServerDatagram);
            (void)co_await CloseVmessEndpoints(Pair);
            co_return;
        }

        ClientTransport->SetWriteFailure(Native, 1);
        const std::string Payload = "partial-vmess-native";
        const auto Result = co_await ClientDatagram->AsyncSendDatagram(AsU8Span(Payload));
        EXPECT_TRUE(Result.Failed());
        EXPECT_EQ(Result.Failure.Code, Preview::Fault::Code::ConnectionReset);
        EXPECT_EQ(Result.Failure.Native, Native);
        EXPECT_EQ(Result.PayloadBytes, 0U);
        EXPECT_EQ(Result.WireBytes, ClientTransport->WriteFailureBytesReported());
        EXPECT_EQ(ClientTransport->WriteFailureBytesReported(), 1U);

        const auto ClientReceipts = co_await CloseVmessDatagram(ClientDatagram);
        Preview::Testing::ExpectFixtureCloseReceipt(ClientReceipts.Datagram);
        Preview::Testing::ExpectFixtureCloseReceipt(ClientReceipts.Connection);
        const auto ServerReceipts = co_await CloseVmessDatagram(ServerDatagram);
        Preview::Testing::ExpectFixtureCloseReceipt(ServerReceipts.Datagram);
        Preview::Testing::ExpectFixtureCloseReceipt(ServerReceipts.Connection);
        const auto Endpoints = co_await CloseVmessEndpoints(Pair);
        Preview::Testing::ExpectFixtureCloseReceipt(Endpoints.First);
        Preview::Testing::ExpectFixtureCloseReceipt(Endpoints.Second);
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
        using ServerResultType = std::expected<Vmess::AcceptedDatagram, Preview::Fault::Failure>;
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
            if (ClientDatagram) (void)co_await CloseVmessDatagram(ClientDatagram);
            if (ServerDatagram) (void)co_await CloseVmessDatagram(ServerDatagram);
            (void)co_await CloseVmessEndpoints(Pair);
            co_return;
        }

        ServerTransport->SetReadFailure(Native, 1);
        const auto Host = Preview::Network::ParseHost("127.0.0.1");
        auto Session = std::make_shared<Vmess::DatagramSession>(
            Vmess::DatagramWire{ServerDatagram, {*Host, 53}},
            Vmess::DatagramSession::Relay::Options{{}, {}});
        const auto Result = co_await Session->Run();
        EXPECT_FALSE(Result);
        if (!Result)
        {
            EXPECT_EQ(Result.error().Code, Preview::Fault::Code::ConnectionReset);
            EXPECT_EQ(Result.error().Native, Native);
        }
        const auto ClientReceipts = co_await CloseVmessDatagram(ClientDatagram);
        Preview::Testing::ExpectFixtureCloseReceipt(ClientReceipts.Datagram);
        Preview::Testing::ExpectFixtureCloseReceipt(ClientReceipts.Connection);
        const auto EndpointReceipts = co_await CloseVmessEndpoints(Pair);
        Preview::Testing::ExpectFixtureCloseReceipt(EndpointReceipts.First);
        Preview::Testing::ExpectFixtureCloseReceipt(EndpointReceipts.Second);
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

TEST(VmessDgramErr, NativePartialPacketWriteFailure)
{
    Net::io_context Context;
    const auto Native = std::make_error_code(std::errc::connection_reset);
    RunCoroutine(Context, RunNativePartialPacketWriteFailure(Context, Native));
}
