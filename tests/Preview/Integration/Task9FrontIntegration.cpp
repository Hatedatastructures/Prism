/**
 * @file Task9FrontIntegration.cpp
 * @brief Task 9 类型化 UDP/QUIC 入口集成测试。
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <memory>
#include <span>
#include <system_error>
#include <utility>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <Preview/Boundary/Datagram/DatagramAssociation.hpp>
#include <Preview/Boundary/Quic/QuicConnectionRegistry.hpp>
#include <Preview/Boundary/Quic/QuicPacketGateway.hpp>
#include <Preview/Protocols/Socks5/UdpAssoc.hpp>
#include <Preview/Protocols/Quic/StreamAdapter.hpp>
#include <Preview/Protocols/Quic/DatagramAdapter.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>
#include <TestSupport/Preview/QuicFactory.hpp>
#include <TestSupport/Preview/QuicStreamProviderActivity.hpp>
#include <Preview/Composition/Builtin/ProtocolBuiltins.hpp>
#include <Preview/Composition/Recognition/ProtocolMatrix.hpp>
#include <Experiments/Preview/Quic/GatewayCommon.hpp>

namespace
{

    namespace Net = boost::asio;

    [[nodiscard]] auto MakeGatewayOptions(
        const std::size_t MaxConnections = 4096U,
        const std::size_t MaxPacketsPerConnection = 65536U)
        -> Preview::Boundary::QuicPacketGatewayOptions
    {
        auto Budget = std::make_shared<Preview::Boundary::QuicAdmissionBudget>(
            Preview::Boundary::QuicAdmissionBudgetLimits{
                MaxConnections, MaxPacketsPerConnection});
        return {std::move(Budget), {}, {}};
    }

    class FakeDatagramProvider final : public Preview::Quic::DatagramProvider
    {
    public:
        explicit FakeDatagramProvider(Net::any_io_executor Executor) : Executor_(std::move(Executor)) {}

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Executor_;
        }

        [[nodiscard]] auto Receive(std::span<std::byte>, std::error_code &Error)
            -> Net::awaitable<std::size_t> override
        {
            Error.clear();
            if (OverreportReceive_)
            {
                co_return 5;
            }
            co_return 0;
        }

        [[nodiscard]] auto Send(std::span<const std::byte> Buffer, std::error_code &Error)
            -> Net::awaitable<std::size_t> override
        {
            Error.clear();
            co_return Buffer.size();
        }

        auto Close() -> void override { Closed_ = true; }
        auto Cancel() -> void override { Cancelled_ = true; }

        [[nodiscard]] auto IsClosed() const noexcept -> bool override
        {
            return Closed_;
        }

        bool Cancelled_{false};
        bool OverreportReceive_{false};

    private:
        Net::any_io_executor Executor_;
        bool Closed_{false};
    };

    class FakeStreamProvider final : public Preview::Quic::StreamProvider
    {
    public:
        explicit FakeStreamProvider(Net::any_io_executor Executor)
            : Executor_(std::move(Executor)),
              Activity_(std::make_shared<Preview::Testing::Quic::StreamProviderActivity>(Executor_))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Executor_;
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        [[nodiscard]] auto Read(std::span<std::byte> Buffer, std::error_code &Error)
            -> Net::awaitable<std::size_t> override
        {
            const auto Operation = Activity_->BeginOperation();
            Error.clear();
            if (!Operation)
            {
                Error = std::make_error_code(std::errc::operation_canceled);
                co_return 0;
            }
            if (OverreportRead_)
            {
                co_return Buffer.size() + 1;
            }
            co_return 0;
        }

        [[nodiscard]] auto Write(std::span<const std::byte> Buffer, std::error_code &Error)
            -> Net::awaitable<std::size_t> override
        {
            const auto Operation = Activity_->BeginOperation();
            Error.clear();
            if (!Operation)
            {
                Error = std::make_error_code(std::errc::operation_canceled);
                co_return 0;
            }
            if (OverreportWrite_)
            {
                co_return Buffer.size() + 1;
            }
            co_return Buffer.size();
        }

        auto Close() -> ControlResult override
        {
            Closed_ = true;
            Activity_->CompleteClose();
            return {};
        }
        auto ShutdownWrite()
            -> Net::awaitable<Preview::Quic::StreamProvider::ShutdownResult> override
        {
            const auto Operation = Activity_->BeginOperation();
            if (!Operation)
            {
                co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            }
            WriteShutdown_ = true;
            co_return Preview::Quic::StreamProvider::ShutdownResult{};
        }
        auto WaitForWriteAcknowledgement()
            -> Net::awaitable<Preview::Quic::StreamProvider::ShutdownResult> override
        {
            const auto Operation = Activity_->BeginOperation();
            if (!Operation)
            {
                co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            }
            if (!WriteShutdown_)
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            co_return Preview::Quic::StreamProvider::ShutdownResult{};
        }
        [[nodiscard]] auto StreamId() const noexcept -> std::int64_t override { return 11; }
        [[nodiscard]] auto IsClosed() const noexcept -> bool override { return Closed_; }

        bool WriteShutdown_{false};
        bool OverreportRead_{false};
        bool OverreportWrite_{false};

    private:
        Net::any_io_executor Executor_;
        std::shared_ptr<Preview::Testing::Quic::StreamProviderActivity> Activity_;
        bool Closed_{false};
    };

    auto RunIo(Net::io_context &Io, Net::awaitable<void> Operation) -> void
    {
        Io.restart();
        Net::co_spawn(Io, std::move(Operation), Net::detached);
        Io.run();
    }

    /// 把正式 I/O 结果还原为原生 error_code，并返回本次完成字节数（既有断言文字保持不变）。
    auto ApplyIoResult(Preview::IoResult Result, std::error_code &Error) -> std::size_t
    {
        Error = Preview::Fault::ToNative(Result.Failure);
        return Result.Bytes;
    }

    using Udp = Net::ip::udp;
    using Registry = Preview::Boundary::QuicConnectionRegistry;
    using Table = Preview::Boundary::DatagramAssociationTable;

    auto MakeNativeServer(Net::io_context& Io, std::shared_ptr<Udp::socket> Socket)
        -> std::shared_ptr<Preview::Quic::Server>
    {
        Preview::Quic::ServerOptions Options;
        Options.Executor = Io.get_executor();
        Options.Socket = Socket;
        Options.Sender = Preview::Testing::Quic::MakeSender(Socket);
        Options.ExternalReceive = true;
        return std::make_shared<Preview::Quic::Server>(std::move(Options));
    }

    TEST(Task9Front, AssociationRemovalClosesProtocolOwner)
    {
        Net::io_context Io;
        auto Raw = std::make_shared<Preview::PreviewMockTransport>(Io.get_executor());
        auto Carrier = std::make_shared<Preview::Socks5::Conn<>>(Raw);
        auto Session = std::make_shared<Preview::Socks5::UdpAssoc>(
            Io.get_executor(), Carrier, Preview::Socks5::UdpAssocOptions{});
        const Preview::Boundary::DatagramAssociationKey Key{
            Udp::endpoint(Net::ip::address_v4::loopback(), 20001), 41, 1};
        auto Association = std::make_shared<Preview::Boundary::DatagramAssociation>(
            Key, Preview::Boundary::DatagramAssociationOptions{
                Io.get_executor(), [Session] { Session->Cancel(); }});
        Table Owners;
        ASSERT_TRUE(Owners.Register(Key, Association));
        EXPECT_FALSE(Owners.Register(Key, Association));
        EXPECT_EQ(Owners.Size(), 1U);
        EXPECT_TRUE(Owners.Remove(Key));
        EXPECT_TRUE(Raw->IsClosed());
        EXPECT_EQ(Owners.Size(), 0U);
        EXPECT_FALSE(Owners.Remove(Key));
    }

    TEST(Task9Front, NativeRegistryRequiresBoundOwnerAndPreservesListenerSocket)
    {
        Net::io_context Io;
        auto Socket = std::make_shared<Udp::socket>(Io, Udp::v4());
        auto Server = MakeNativeServer(Io, Socket);
        auto Lease = Preview::Testing::Quic::MakeLease(Server);
        Registry Owners(Registry::Options{
            .AdmissionBudget = std::make_shared<Preview::Boundary::QuicAdmissionBudget>(
                Preview::Boundary::QuicAdmissionBudgetLimits{4096U, 65536U})});
        const Udp::endpoint Peer(Net::ip::address_v4::loopback(), 20002);
        Registry::Cid Cid{std::byte{1}, std::byte{2}};
        Preview::Boundary::BoundaryPacket Packet;
        Packet.Peer = Peer;
        Packet.Classification.ConnectionIdBytes = Cid;
        Packet.Payload = {std::byte{0x01}};
        EXPECT_EQ(Owners.Handle(Packet, Preview::Testing::Quic::MakeIngress()),
            Preview::Boundary::QuicAdmissionDisposition::NotHandled);
        EXPECT_EQ(Owners.Size(), 0U);
        ASSERT_TRUE(Owners.Register({Cid, Lease, Peer}));
        EXPECT_FALSE(Owners.Register({Cid, Lease, Peer}));
        EXPECT_TRUE(Owners.Remove(Cid));
        Io.run();
        EXPECT_TRUE(Server->Health().Closed);
        EXPECT_TRUE(Socket->is_open());
        EXPECT_EQ(Owners.Size(), 0U);
        Socket->close();
    }

    TEST(Task9Front, SocketReadinessDoesNotClaimProtocolAcceptance)
    {
        Preview::Boundary::QuicPacketGateway Gateway(MakeGatewayOptions());
        Gateway.MarkSocketReady();
        Gateway.MarkReceiveLoopReady();
        EXPECT_FALSE(Gateway.Health().Healthy());
        EXPECT_FALSE(Gateway.Health().ProtocolReady);
        Gateway.MarkHandshakeReady();
        EXPECT_FALSE(Gateway.Health().Healthy());
        Gateway.MarkProtocolReady();
        EXPECT_TRUE(Gateway.Health().Healthy());
        Gateway.Drain();
        EXPECT_FALSE(Gateway.Health().Healthy());
        EXPECT_TRUE(Gateway.Health().Draining);
        Gateway.Close();
    }

    TEST(Task9Front, GatewayEnforcesConnectionAndPacketBudgets)
    {
        Preview::Boundary::QuicPacketGateway Gateway(MakeGatewayOptions(1U, 2U));
        const std::array<std::byte, 2> Cid{std::byte{3}, std::byte{4}};
        const std::array<std::byte, 2> Other{std::byte{5}, std::byte{6}};
        std::size_t Delivered = 0;
        auto Handler = [&Delivered](const Preview::Boundary::BoundaryPacket&)
        { ++Delivered; return true; };
        ASSERT_TRUE(Gateway.RegisterConnection(Cid, Handler));
        EXPECT_FALSE(Gateway.RegisterConnection(Cid, Handler));
        EXPECT_FALSE(Gateway.RegisterConnection(Other, Handler));
        Preview::Boundary::BoundaryPacket Packet;
        Packet.Classification.Kind = Preview::Boundary::DatagramKind::Quic;
        Packet.Classification.ConnectionIdBytes.assign(Cid.begin(), Cid.end());
        Packet.Classification.Route = Preview::Boundary::DatagramRoute::RegisteredCid;
        EXPECT_TRUE(Gateway.Handle(Packet));
        EXPECT_TRUE(Gateway.Handle(Packet));
        EXPECT_FALSE(Gateway.Handle(Packet));
        EXPECT_EQ(Delivered, 2U);
        EXPECT_TRUE(Gateway.Health().BoundedFailure);
        EXPECT_EQ(Gateway.Health().Packets, 2U);
        Gateway.Close();
    }

    TEST(Task9Front, DrainRejectsNewAssociationAndNativeConnectionOwners)
    {
        Net::io_context Io;
        const Udp::endpoint Peer(Net::ip::address_v4::loopback(), 20003);
        const Preview::Boundary::DatagramAssociationKey Key{Peer, 71, 2};
        std::size_t Closed = 0;
        auto Association = std::make_shared<Preview::Boundary::DatagramAssociation>(
            Key, Preview::Boundary::DatagramAssociationOptions{Io.get_executor(), [&Closed] { ++Closed; }});
        Table Associations;
        ASSERT_TRUE(Associations.Register(Key, Association));
        Associations.Drain();
        EXPECT_FALSE(Associations.Register(Key, Association));
        EXPECT_TRUE(Associations.Remove(Key));
        EXPECT_EQ(Closed, 1U);
        Associations.Close();
        EXPECT_EQ(Closed, 1U);

        auto Socket = std::make_shared<Udp::socket>(Io, Udp::v4());
        auto Server = MakeNativeServer(Io, Socket);
        auto Lease = Preview::Testing::Quic::MakeLease(Server);
        Registry Owners(Registry::Options{});
        const Registry::Cid Cid{std::byte{7}, std::byte{8}};
        ASSERT_TRUE(Owners.Register({Cid, Lease, Peer}));
        ASSERT_TRUE(Owners.Drain());
        EXPECT_FALSE(Owners.Register({{std::byte{9}}, Lease, Peer}));
        EXPECT_TRUE(Owners.Remove(Cid));
        ASSERT_TRUE(Owners.Close());
        Io.run();
        EXPECT_TRUE(Server->Health().Closed);
        EXPECT_TRUE(Socket->is_open());
        Socket->close();
    }

    TEST(Task9Front, GatewayTypedRegistrationAndDrainAreExplicit)
    {
        Preview::Experiments::Quic::GatewayCommon Gateway;
        EXPECT_EQ(Gateway.RegisterTypedConnection(
                      0, Preview::Experiments::Quic::ConnectionProtocol::H3, "h3", 1),
                  Preview::Error::BadMessage);
        EXPECT_EQ(Gateway.RegisterTypedConnection(
                      21, Preview::Experiments::Quic::ConnectionProtocol::H3, "h3", 1),
                  Preview::Error::None);
        EXPECT_EQ(Gateway.BeginDrain(21), Preview::Error::None);
        EXPECT_EQ(Gateway.DispatchTyped(21, {}), Preview::Error::Canceled);
        EXPECT_EQ(Gateway.DispatchTyped(21, 7, {}), Preview::Error::Canceled);
        EXPECT_EQ(Gateway.BeginDrain(999), Preview::Error::NotOpen);
    }

    TEST(Task9Front, StaticBuiltinsCoverProtocolMatrixWithClosedCapabilityRequirements)
    {
        using namespace Preview::Composition::Builtin;
        const auto Specs = StaticBuiltinSpecs();
        const auto Capabilities = ProtocolBuiltinCapabilities();
        EXPECT_EQ(Specs.size(), 17U);

        for (const auto &Spec : Specs)
        {
            EXPECT_TRUE(Capabilities.Includes(Spec.Requires));
            if (Spec.Kind == "protocol")
            {
                const auto Found = std::any_of(
                    Preview::Composition::Recognition::ProtocolMatrix::TcpRecognition().begin(),
                    Preview::Composition::Recognition::ProtocolMatrix::TcpRecognition().end(),
                    [&Spec](const auto &Binding) { return Binding.Name == Spec.Name; });
                const auto UdpFound = std::any_of(
                    Preview::Composition::Recognition::ProtocolMatrix::DatagramAssociations().begin(),
                    Preview::Composition::Recognition::ProtocolMatrix::DatagramAssociations().end(),
                    [&Spec](const auto &Binding) { return Binding.Name == Spec.Name; });
                EXPECT_TRUE(Found || UdpFound || Spec.Name == "hysteria2" || Spec.Name == "tuic");
            }
            else
            {
                const auto Found = std::any_of(
                    Preview::Composition::Recognition::ProtocolMatrix::Carriers().begin(),
                    Preview::Composition::Recognition::ProtocolMatrix::Carriers().end(),
                    [&Spec](const auto &Binding) { return Binding.Name == Spec.Name; });
                EXPECT_TRUE(Found);
            }
        }
    }

    TEST(Task9Front, QuicAdaptersRejectOverreportedProviderCounts)
    {
        Net::io_context Io;
        std::array<std::byte, 4> Buffer{};
        std::error_code DatagramError;
        std::error_code StreamReadError;
        std::error_code StreamWriteError;
        std::size_t DatagramRead{0};
        std::size_t StreamRead{0};
        std::size_t StreamWritten{0};

        auto DatagramProvider = std::make_shared<FakeDatagramProvider>(Io.get_executor());
        DatagramProvider->OverreportReceive_ = true;
        auto Datagram = std::make_shared<Preview::Quic::DatagramAdapter>(DatagramProvider);

        auto StreamProvider = std::make_shared<FakeStreamProvider>(Io.get_executor());
        StreamProvider->OverreportRead_ = true;
        StreamProvider->OverreportWrite_ = true;
        auto Stream = std::make_shared<Preview::Quic::StreamAdapter>(
            Io.get_executor(), StreamProvider);

        RunIo(Io, [&]() -> Net::awaitable<void>
        {
            DatagramRead = ApplyIoResult(co_await Datagram->ReadSome(Buffer), DatagramError);
            StreamRead = ApplyIoResult(co_await Stream->ReadSome(Buffer), StreamReadError);
            StreamWritten = ApplyIoResult(co_await Stream->WriteSome(Buffer), StreamWriteError);
            Io.stop();
            co_return;
        }());

        EXPECT_EQ(DatagramRead, 0U);
        EXPECT_EQ(StreamRead, 0U);
        EXPECT_EQ(StreamWritten, 0U);
        EXPECT_EQ(DatagramError, Preview::make_error_code(Preview::Error::BadLength));
        EXPECT_EQ(StreamReadError, Preview::make_error_code(Preview::Error::BadLength));
        EXPECT_EQ(StreamWriteError, Preview::make_error_code(Preview::Error::BadLength));
    }

} // namespace
