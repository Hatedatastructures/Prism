/**
 * @file Task9FrontIntegration.cpp
 * @brief Task 9 typed UDP/QUIC front integration tests.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <memory>
#include <span>
#include <system_error>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <Preview/Composition/Adapters/DataPlane.hpp>
#include <Preview/Composition/Builtin/ProtocolBuiltins.hpp>
#include <Preview/Composition/Recognition/ProtocolMatrix.hpp>
#include <Preview/Protocols/Quic/GatewayCommon.hpp>
#include <Preview/Runtime/Front/QuicFront.hpp>
#include <Preview/Runtime/Front/UdpFront.hpp>

namespace
{

    namespace Net = boost::asio;
    using Preview::Composition::Adapters::DataPlaneResult;

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
        explicit FakeStreamProvider(Net::any_io_executor Executor = {})
            : Executor_(std::move(Executor))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Executor_;
        }

        [[nodiscard]] auto Read(std::span<std::byte> Buffer, std::error_code &Error)
            -> Net::awaitable<std::size_t> override
        {
            Error.clear();
            if (OverreportRead_)
            {
                co_return Buffer.size() + 1;
            }
            co_return 0;
        }

        [[nodiscard]] auto Write(std::span<const std::byte> Buffer, std::error_code &Error)
            -> Net::awaitable<std::size_t> override
        {
            Error.clear();
            if (OverreportWrite_)
            {
                co_return Buffer.size() + 1;
            }
            co_return Buffer.size();
        }

        auto Close() -> void override { Closed_ = true; }
        auto ShutdownWrite() -> void override { WriteShutdown_ = true; }
        [[nodiscard]] auto StreamId() const noexcept -> std::int64_t override { return 11; }
        [[nodiscard]] auto IsClosed() const noexcept -> bool override { return Closed_; }

        bool WriteShutdown_{false};
        bool OverreportRead_{false};
        bool OverreportWrite_{false};

    private:
        Net::any_io_executor Executor_;
        bool Closed_{false};
    };

    auto RunIo(Net::io_context &Io, Net::awaitable<void> Operation) -> void
    {
        Io.restart();
        Net::co_spawn(Io, std::move(Operation), Net::detached);
        Io.run();
    }

    TEST(Task9Front, UdpFrontReturnsOnlyTypedDatagramPlanes)
    {
        Net::io_context Io;
        Preview::Runtime::Front::UdpFront Front(
            Preview::Runtime::Front::UdpFrontOptions{Io.get_executor(), 4});
        ASSERT_EQ(Front.RegisterAssociation(
                      Preview::Runtime::Front::UdpAssociationRegistration{
                          Preview::Recognition::ProtocolType::Vless,
                          [](Preview::Runtime::Front::UdpAssociationRequest Request)
                              -> Net::awaitable<DataPlaneResult>
                          {
                              co_return DataPlaneResult::Datagram(std::move(Request.Carrier));
                          }}),
                  Preview::Error::None);

        auto Provider = std::make_shared<FakeDatagramProvider>(Io.get_executor());
        auto Carrier = std::make_shared<Preview::Quic::DatagramAdapter>(Provider);
        DataPlaneResult Result;
        RunIo(Io, [&]() -> Net::awaitable<void>
        {
            Result = co_await Front.Associate(
                Preview::Runtime::Front::UdpAssociationRequest{
                    Preview::Recognition::ProtocolType::Vless, Carrier, 1});
            Io.stop();
            co_return;
        }());

        EXPECT_EQ(Result.Status, Preview::Error::None);
        EXPECT_TRUE(Result.IsDatagram());
        EXPECT_FALSE(Result.IsStream());
        EXPECT_EQ(Front.AssociationCount(), 1U);
        EXPECT_TRUE(Front.Release(1));
        EXPECT_TRUE(Provider->IsClosed());
        EXPECT_EQ(Front.AssociationCount(), 0U);
    }

    TEST(Task9Front, QuicFrontBindsBeforeOpeningStreamsAndDatagrams)
    {
        Net::io_context Io;
        Preview::Runtime::Front::QuicFront Front(
            Preview::Runtime::Front::QuicFrontOptions{Io.get_executor(), 1, 1});
        ASSERT_EQ(Front.RegisterProtocol(
                      Preview::Runtime::Front::QuicProtocolRegistration{
                          Preview::Recognition::ProtocolType::Tuic, "h3", true, true}),
                  Preview::Error::None);
        ASSERT_EQ(Front.BindConnection(
                      Preview::Runtime::Front::QuicBindRequest{
                          7, Preview::Recognition::ProtocolType::Tuic, "h3", 1}),
                  Preview::Error::None);

        DataPlaneResult Stream;
        DataPlaneResult Datagram;
        DataPlaneResult Overflow;
        DataPlaneResult DatagramOverflow;
        auto StreamProvider = std::make_shared<FakeStreamProvider>(Io.get_executor());
        auto DatagramProvider = std::make_shared<FakeDatagramProvider>(Io.get_executor());
        RunIo(Io, [&]() -> Net::awaitable<void>
        {
            Stream = co_await Front.OpenStream(
                Preview::Runtime::Front::QuicStreamRequest{
                    7, StreamProvider});
            Datagram = co_await Front.OpenDatagram(
                Preview::Runtime::Front::QuicDatagramRequest{
                    7, DatagramProvider});
            Overflow = co_await Front.OpenStream(
                Preview::Runtime::Front::QuicStreamRequest{
                    7, std::make_shared<FakeStreamProvider>(Io.get_executor())});
            DatagramOverflow = co_await Front.OpenDatagram(
                Preview::Runtime::Front::QuicDatagramRequest{
                    7, std::make_shared<FakeDatagramProvider>(Io.get_executor())});
            Io.stop();
            co_return;
        }());

        EXPECT_TRUE(Stream.IsStream());
        EXPECT_TRUE(Datagram.IsDatagram());
        EXPECT_EQ(Front.StreamCount(7), 1U);
        EXPECT_EQ(Front.DatagramCount(7), 1U);
        EXPECT_EQ(Overflow.Status, Preview::Error::NotSupported);
        EXPECT_EQ(DatagramOverflow.Status, Preview::Error::NotSupported);
        EXPECT_TRUE(Front.CloseConnection(7));
        EXPECT_TRUE(StreamProvider->IsClosed());
        EXPECT_TRUE(DatagramProvider->IsClosed());
        EXPECT_EQ(Front.StreamCount(7), 0U);
        EXPECT_EQ(Front.DatagramCount(7), 0U);
    }

    TEST(Task9Front, FrontRejectionsRemainTypedAndHealthIsNotSuccessful)
    {
        Net::io_context Io;
        Preview::Runtime::Front::UdpFront Udp(
            Preview::Runtime::Front::UdpFrontOptions{Io.get_executor(), 1});
        ASSERT_EQ(Udp.RegisterAssociation(
                      Preview::Runtime::Front::UdpAssociationRegistration{
                          Preview::Recognition::ProtocolType::Vless,
                          [](Preview::Runtime::Front::UdpAssociationRequest Request)
                              -> Net::awaitable<DataPlaneResult>
                          {
                              co_return DataPlaneResult::Datagram(std::move(Request.Carrier));
                          }}),
                  Preview::Error::None);
        EXPECT_EQ(Udp.Bind(0), Preview::Error::None);
        EXPECT_TRUE(Udp.Healthy());
        EXPECT_FALSE(Udp.Health().UnsupportedService);
        EXPECT_EQ(Udp.LastError(), Preview::Error::None);

        Preview::Runtime::Front::QuicFront Quic(
            Preview::Runtime::Front::QuicFrontOptions{Io.get_executor(), 2, 2});
        ASSERT_EQ(Quic.RegisterProtocol(
                      Preview::Runtime::Front::QuicProtocolRegistration{
                          Preview::Recognition::ProtocolType::Tuic, "h3", true, true}),
                  Preview::Error::None);
        ASSERT_EQ(Quic.BindConnection(
                      Preview::Runtime::Front::QuicBindRequest{
                          9, Preview::Recognition::ProtocolType::Tuic, "h3", 1}),
                  Preview::Error::None);
        EXPECT_FALSE(Quic.Healthy());
        EXPECT_TRUE(Quic.Health().UnsupportedService);

        auto ClosedStream = std::make_shared<FakeStreamProvider>(Io.get_executor());
        ClosedStream->Close();
        auto WrongExecutorStream = std::make_shared<FakeStreamProvider>(
            Net::system_executor());
        DataPlaneResult ClosedResult;
        DataPlaneResult WrongExecutorResult;
        RunIo(Io, [&]() -> Net::awaitable<void>
        {
            ClosedResult = co_await Quic.OpenStream(
                Preview::Runtime::Front::QuicStreamRequest{9, ClosedStream});
            WrongExecutorResult = co_await Quic.OpenStream(
                Preview::Runtime::Front::QuicStreamRequest{9, WrongExecutorStream});
            Io.stop();
            co_return;
        }());

        EXPECT_EQ(ClosedResult.Status, Preview::Error::NotOpen);
        EXPECT_EQ(WrongExecutorResult.Status, Preview::Error::IoError);
        EXPECT_FALSE(Quic.Healthy());
        EXPECT_EQ(Quic.LastError(), Preview::Error::IoError);
        EXPECT_EQ(Quic.DispatchTyped(999, {}), Preview::Error::NotOpen);
        EXPECT_TRUE(Quic.CloseConnection(9));
        EXPECT_FALSE(Quic.Healthy());
        EXPECT_EQ(Quic.LastError(), Preview::Error::None);
    }

    TEST(Task9Front, UdpFrontRegistrationAndAssociationBudgetAreTyped)
    {
        Net::io_context Io;
        Preview::Runtime::Front::UdpFront Front(
            Preview::Runtime::Front::UdpFrontOptions{Io.get_executor(), 1, 2});

        EXPECT_EQ(Front.RegisterAssociation(
                      Preview::Runtime::Front::UdpAssociationRegistration{
                          Preview::Recognition::ProtocolType::Http, {}}),
                  Preview::Error::BadAddress);
        ASSERT_EQ(Front.RegisterAssociation(
                      Preview::Runtime::Front::UdpAssociationRegistration{
                          Preview::Recognition::ProtocolType::Vless,
                          [](Preview::Runtime::Front::UdpAssociationRequest Request)
                              -> Net::awaitable<DataPlaneResult>
                          {
                              co_return DataPlaneResult::Datagram(std::move(Request.Carrier));
                          }}),
                  Preview::Error::None);
        EXPECT_EQ(Front.RegisterAssociation(
                      Preview::Runtime::Front::UdpAssociationRegistration{
                          Preview::Recognition::ProtocolType::Vless,
                          [](Preview::Runtime::Front::UdpAssociationRequest Request)
                              -> Net::awaitable<DataPlaneResult>
                          {
                              co_return DataPlaneResult::Datagram(std::move(Request.Carrier));
                          }}),
                  Preview::Error::ProtocolError);

        auto FirstProvider = std::make_shared<FakeDatagramProvider>(Io.get_executor());
        auto SecondProvider = std::make_shared<FakeDatagramProvider>(Io.get_executor());
        auto FirstCarrier = std::make_shared<Preview::Quic::DatagramAdapter>(FirstProvider);
        auto SecondCarrier = std::make_shared<Preview::Quic::DatagramAdapter>(SecondProvider);
        DataPlaneResult First;
        DataPlaneResult Duplicate;
        DataPlaneResult Overflow;
        DataPlaneResult Reused;
        RunIo(Io, [&]() -> Net::awaitable<void>
        {
            First = co_await Front.Associate(
                Preview::Runtime::Front::UdpAssociationRequest{
                    Preview::Recognition::ProtocolType::Vless, FirstCarrier, 41});
            Duplicate = co_await Front.Associate(
                Preview::Runtime::Front::UdpAssociationRequest{
                    Preview::Recognition::ProtocolType::Vless, SecondCarrier, 41});
            Overflow = co_await Front.Associate(
                Preview::Runtime::Front::UdpAssociationRequest{
                    Preview::Recognition::ProtocolType::Vless, SecondCarrier, 42});
            Io.stop();
            co_return;
        }());

        EXPECT_TRUE(First.IsDatagram());
        EXPECT_EQ(Duplicate.Status, Preview::Error::ProtocolError);
        EXPECT_EQ(Overflow.Status, Preview::Error::NotSupported);
        EXPECT_EQ(Front.AssociationCount(), 1U);
        EXPECT_EQ(Front.AdmitPacket(41), Preview::Error::None);
        EXPECT_EQ(Front.AdmitPacket(41), Preview::Error::None);
        EXPECT_EQ(Front.AdmitPacket(41), Preview::Error::NotSupported);
        EXPECT_EQ(Front.PacketCount(41), 2U);
        EXPECT_TRUE(Front.Release(41));
        EXPECT_TRUE(FirstProvider->IsClosed());

        RunIo(Io, [&]() -> Net::awaitable<void>
        {
            Reused = co_await Front.Associate(
                Preview::Runtime::Front::UdpAssociationRequest{
                    Preview::Recognition::ProtocolType::Vless, SecondCarrier, 42});
            Io.stop();
            co_return;
        }());

        EXPECT_TRUE(Reused.IsDatagram());
        Front.Drain();
        EXPECT_FALSE(Front.Healthy());
        EXPECT_EQ(Front.Health().LastError, Preview::Error::Canceled);
        EXPECT_EQ(Front.AssociationCount(), 1U);
        Front.Close();
        EXPECT_TRUE(SecondProvider->IsClosed());
        EXPECT_EQ(Front.AssociationCount(), 0U);
        EXPECT_EQ(Front.Release(42), false);
    }

    TEST(Task9Front, QuicFrontRequiresTypedProtocolRegistrationAndDrainsCarriers)
    {
        Net::io_context Io;
        Preview::Runtime::Front::QuicFront Front(
            Preview::Runtime::Front::QuicFrontOptions{Io.get_executor(), 1, 1});

        EXPECT_EQ(Front.BindConnection(
                      Preview::Runtime::Front::QuicBindRequest{
                          11, Preview::Recognition::ProtocolType::Tuic, "h3", 1}),
                  Preview::Error::NotSupported);
        ASSERT_EQ(Front.RegisterProtocol(
                      Preview::Runtime::Front::QuicProtocolRegistration{
                          Preview::Recognition::ProtocolType::Hysteria2, "h3", true, false}),
                  Preview::Error::None);
        ASSERT_EQ(Front.BindConnection(
                      Preview::Runtime::Front::QuicBindRequest{
                          11, Preview::Recognition::ProtocolType::Hysteria2, "h3", 1}),
                  Preview::Error::None);

        auto StreamProvider = std::make_shared<FakeStreamProvider>(Io.get_executor());
        auto DatagramProvider = std::make_shared<FakeDatagramProvider>(Io.get_executor());
        DataPlaneResult Stream;
        DataPlaneResult Datagram;
        RunIo(Io, [&]() -> Net::awaitable<void>
        {
            Stream = co_await Front.OpenStream(
                Preview::Runtime::Front::QuicStreamRequest{11, StreamProvider});
            Datagram = co_await Front.OpenDatagram(
                Preview::Runtime::Front::QuicDatagramRequest{11, DatagramProvider});
            Io.stop();
            co_return;
        }());

        EXPECT_TRUE(Stream.IsStream());
        EXPECT_EQ(Datagram.Status, Preview::Error::NotSupported);
        Front.Drain();
        DataPlaneResult Drained;
        RunIo(Io, [&]() -> Net::awaitable<void>
        {
            Drained = co_await Front.OpenStream(
                Preview::Runtime::Front::QuicStreamRequest{
                    11, std::make_shared<FakeStreamProvider>(Io.get_executor())});
            Io.stop();
            co_return;
        }());
        EXPECT_EQ(Drained.Status, Preview::Error::Canceled);
        EXPECT_EQ(Front.Health().LastError, Preview::Error::Canceled);
        EXPECT_FALSE(Front.Healthy());
        Front.Close();
        EXPECT_TRUE(StreamProvider->IsClosed());
        EXPECT_EQ(Front.CloseConnection(11), false);
    }

    TEST(Task9Front, GatewayTypedRegistrationAndDrainAreExplicit)
    {
        Preview::Quic::GatewayCommon Gateway;
        EXPECT_EQ(Gateway.RegisterTypedConnection(
                      0, Preview::Quic::ConnectionProtocol::H3, "h3", 1),
                  Preview::Error::BadMessage);
        EXPECT_EQ(Gateway.RegisterTypedConnection(
                      21, Preview::Quic::ConnectionProtocol::H3, "h3", 1),
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
                    Preview::Composition::Recognition::ProtocolMatrix::UdpAssociations().begin(),
                    Preview::Composition::Recognition::ProtocolMatrix::UdpAssociations().end(),
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
            DatagramRead = co_await Datagram->async_read_some(Buffer, DatagramError);
            StreamRead = co_await Stream->async_read_some(Buffer, StreamReadError);
            StreamWritten = co_await Stream->async_write_some(Buffer, StreamWriteError);
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
