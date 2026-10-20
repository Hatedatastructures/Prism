/**
 * @file Hysteria2ConnTerminalReadTest.cpp
 * @brief Hysteria2 完整目标帧与同次读取终态的顺序回归。
 */
#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/this_coro.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <exception>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Hysteria2/Conn.hpp>
#include <Prism/Protocols/Hysteria2/Dgram.hpp>
#include <Prism/Protocols/Hysteria2/Http3Auth.hpp>
#include <Prism/Protocols/Hysteria2/Types.hpp>
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Fault = Prism::Fault;
    namespace Hysteria2 = Prism::Hysteria2;

    class TerminalTransmission final : public Prism::Transmission
    {
    public:
        TerminalTransmission(
            Net::any_io_executor Executor,
            std::vector<std::uint8_t> Input,
            Fault::Failure Terminal)
            : Prism::Transmission(std::move(Executor)),
              Input_(std::move(Input)), Terminal_(std::move(Terminal))
        {
        }

        [[nodiscard]] auto ReadsDone() const noexcept -> std::size_t
        {
            return ReadsDone_;
        }

        auto SetTransportType(const Type Value) noexcept -> void
        {
            TransportType_ = Value;
        }

        auto SetInput(std::vector<std::uint8_t> Input, Fault::Failure Terminal) -> void
        {
            Input_ = std::move(Input);
            Terminal_ = std::move(Terminal);
            Offset_ = 0;
        }

        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return TransportType_;
        }

    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadsDone_;
            const auto Count = (std::min)(Buffer.size(), Input_.size() - Offset_);
            if (Count != 0U)
            {
                std::memcpy(Buffer.data(), Input_.data() + Offset_, Count);
                Offset_ += Count;
            }
            const auto Failure = Offset_ == Input_.size() ? Terminal_ : Fault::Failure{};
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {Count, Failure});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {Buffer.size(), {}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        std::vector<std::uint8_t> Input_;
        Fault::Failure Terminal_;
        std::size_t Offset_{0};
        std::size_t ReadsDone_{0};
        Type TransportType_{Type::Tcp};
    };

    [[nodiscard]] auto ResetFailure() -> Fault::Failure
    {
        return {Fault::Code::ConnectionReset,
                std::make_error_code(std::errc::connection_reset)};
    }

    [[nodiscard]] auto EofFailure() -> Fault::Failure
    {
        return {Fault::Code::Eof};
    }

    [[nodiscard]] auto CanceledFailure() -> Fault::Failure
    {
        return {Fault::Code::Canceled};
    }

    [[nodiscard]] auto TimeoutFailure() -> Fault::Failure
    {
        return {Fault::Code::Timeout,
                std::make_error_code(std::errc::timed_out)};
    }

    [[nodiscard]] auto ErrorForTerminal(const Fault::Failure &Terminal) noexcept
        -> Prism::Error
    {
        switch (Terminal.Code)
        {
        case Fault::Code::Eof: return Prism::Error::UnexpectedEof;
        case Fault::Code::Canceled: return Prism::Error::Canceled;
        case Fault::Code::Timeout: return Prism::Error::Timeout;
        default: return Prism::Error::IoError;
        }
    }

    [[nodiscard]] auto DatagramWire() -> std::vector<std::uint8_t>
    {
        const auto Target = Hysteria2::Address{
            Hysteria2::AddressType::Ipv4, "127.0.0.1", 443};
        const std::array<std::uint8_t, 3> Payload{0xA1U, 0xB2U, 0xC3U};
        return Hysteria2::BuildUdp(
            Hysteria2::UdpFrameInput{3U, 5U, &Target, Payload});
    }

    /** @brief 关闭传输并等待它自己的所有 I/O 预约退出。 */
    auto CloseAndDrain(Prism::Transmission &Carrier) -> Net::awaitable<bool>
    {
        const auto Closed = Carrier.Close();
        const auto Activity = Carrier.Activity();
        if (!Activity)
        {
            co_return false;
        }
        const auto Drained = co_await Activity->Drain();
        co_return Closed.has_value() && Drained.has_value();
    }

    /** @brief 等待已由上层关闭的底层传输退出。 */
    auto DrainActivity(Prism::Transmission &Carrier) -> Net::awaitable<bool>
    {
        const auto Activity = Carrier.Activity();
        if (!Activity)
        {
            co_return false;
        }
        const auto Drained = co_await Activity->Drain();
        co_return Drained.has_value();
    }

    [[nodiscard]] auto HandshakeWire() -> std::vector<std::uint8_t>
    {
        const auto Auth = Hysteria2::MakeAuthRequest("terminal-test");
        const auto Target = Hysteria2::Address{
            Hysteria2::AddressType::Ipv4, "127.0.0.1", 443};
        const std::vector<std::uint8_t> EmptyPayload;
        const auto Frame = Hysteria2::BuildTcp(Target, EmptyPayload);
        std::vector<std::uint8_t> Wire(Auth.begin(), Auth.end());
        Wire.insert(Wire.end(), Frame.begin(), Frame.end());
        return Wire;
    }

    auto RunHandshakeTerminal(Fault::Failure Terminal, const bool CompleteFrame)
        -> Net::awaitable<void>
    {
        const auto Auth = Hysteria2::MakeAuthRequest("terminal-test");
        const auto ExtraLengthRead = (Auth[1] >> 6U) == 0U ? 0U : 1U;
        const auto ExpectedReads = 7U + ExtraLengthRead;
        auto Wire = HandshakeWire();
        if (!CompleteFrame)
        {
            Wire.pop_back();
        }
        auto Raw = std::make_shared<TerminalTransmission>(
            co_await Net::this_coro::executor, std::move(Wire), Terminal);
        auto Connection = std::make_shared<Hysteria2::Conn<>>(Raw, "terminal-test");

        auto [ErrorValue, MessageValue] = co_await Connection->ReadHandshake();
        EXPECT_EQ(ErrorValue, CompleteFrame
                                  ? Prism::Error::None
                                  : ErrorForTerminal(Terminal));
        EXPECT_EQ(Raw->ReadsDone(), ExpectedReads);
        if (CompleteFrame)
        {
            EXPECT_EQ(MessageValue.Type, Hysteria2::Message::Kind::Tcp);
            EXPECT_EQ(MessageValue.dst.Host, "127.0.0.1");
            EXPECT_EQ(MessageValue.dst.Port, 443U);
        }

        const auto Reads = Raw->ReadsDone();
        if (CompleteFrame)
        {
            std::array<std::byte, 8> Buffer{};
            const auto Read = co_await Connection->ReadSome(Buffer);
            EXPECT_EQ(Read.Bytes, 0U);
            EXPECT_EQ(Read.Failure.Code, Terminal.Code);
            EXPECT_EQ(Read.Failure.Native, Terminal.Native);
            EXPECT_EQ(Raw->ReadsDone(), Reads);
            const auto StickyRead = co_await Connection->ReadSome(Buffer);
            EXPECT_EQ(StickyRead.Bytes, 0U);
            EXPECT_EQ(StickyRead.Failure.Code, Terminal.Code);
            EXPECT_EQ(StickyRead.Failure.Native, Terminal.Native);
            EXPECT_EQ(Raw->ReadsDone(), Reads);
        }
        else
        {
            const auto RetryResult = co_await Connection->ReadHandshake();
            EXPECT_EQ(RetryResult.first, ErrorForTerminal(Terminal));
            EXPECT_EQ(Raw->ReadsDone(), Reads);
        }
        EXPECT_TRUE(co_await CloseAndDrain(*Connection));
        EXPECT_TRUE(co_await DrainActivity(*Raw));
    }

    auto RunHandshakeFieldTerminal(
        Fault::Failure Terminal,
        const std::size_t FrameBytes) -> Net::awaitable<void>
    {
        auto Wire = HandshakeWire();
        const auto AuthSize = Hysteria2::MakeAuthRequest("terminal-test").size();
        EXPECT_LT(FrameBytes, Wire.size() - AuthSize);
        if (FrameBytes >= Wire.size() - AuthSize)
        {
            co_return;
        }
        Wire.resize(AuthSize + FrameBytes);
        auto Raw = std::make_shared<TerminalTransmission>(
            co_await Net::this_coro::executor, std::move(Wire), Terminal);
        auto Connection = std::make_shared<Hysteria2::Conn<>>(Raw, "terminal-test");

        const auto HandshakeResult = co_await Connection->ReadHandshake();
        EXPECT_EQ(HandshakeResult.first, ErrorForTerminal(Terminal));
        const auto Reads = Raw->ReadsDone();

        const auto RetryResult = co_await Connection->ReadHandshake();
        EXPECT_EQ(RetryResult.first, ErrorForTerminal(Terminal));
        EXPECT_EQ(Raw->ReadsDone(), Reads);
        EXPECT_TRUE(co_await CloseAndDrain(*Connection));
        EXPECT_TRUE(co_await DrainActivity(*Raw));
    }

    auto RunConnectionDatagramTerminal(Fault::Failure Terminal)
        -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<TerminalTransmission>(
            co_await Net::this_coro::executor, HandshakeWire(), Fault::Failure{});
        auto Connection = std::make_shared<Hysteria2::Conn<>>(Raw, "terminal-test");
        const auto [HandshakeError, MessageValue] = co_await Connection->ReadHandshake();
        EXPECT_EQ(HandshakeError, Prism::Error::None);
        EXPECT_EQ(MessageValue.Type, Hysteria2::Message::Kind::Tcp);

        const auto Wire = DatagramWire();
        Raw->SetTransportType(Prism::Transmission::Type::Udp);
        Raw->SetInput(Wire, Terminal);
        Hysteria2::Address Source{};
        std::vector<std::uint8_t> Payload;
        const auto First = co_await Connection->AsyncReceiveDatagram(Source, Payload);
        EXPECT_EQ(First, Prism::Error::None);
        EXPECT_EQ(Source.Host, "127.0.0.1");
        EXPECT_EQ(Source.Port, 443U);
        EXPECT_EQ(Payload, (std::vector<std::uint8_t>{0xA1U, 0xB2U, 0xC3U}));
        const auto Reads = Raw->ReadsDone();

        const auto Next = co_await Connection->AsyncReceiveDatagram(Source, Payload);
        EXPECT_EQ(Next, ErrorForTerminal(Terminal));
        EXPECT_EQ(Raw->ReadsDone(), Reads);
        const auto Retry = co_await Connection->AsyncReceiveDatagram(Source, Payload);
        EXPECT_EQ(Retry, ErrorForTerminal(Terminal));
        EXPECT_EQ(Raw->ReadsDone(), Reads);
        std::array<std::byte, 8> ReadBuffer{};
        const auto StickyRead = co_await Connection->ReadSome(ReadBuffer);
        EXPECT_EQ(StickyRead.Bytes, 0U);
        EXPECT_EQ(StickyRead.Failure.Code, Terminal.Code);
        EXPECT_EQ(StickyRead.Failure.Native, Terminal.Native);
        EXPECT_EQ(Raw->ReadsDone(), Reads);

        EXPECT_TRUE(co_await CloseAndDrain(*Connection));
        EXPECT_TRUE(co_await DrainActivity(*Raw));
    }

    auto RunConnectionDatagramFailure(
        Fault::Failure Terminal,
        const bool Malformed) -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<TerminalTransmission>(
            co_await Net::this_coro::executor, HandshakeWire(), Fault::Failure{});
        auto Connection = std::make_shared<Hysteria2::Conn<>>(Raw, "terminal-test");
        const auto [HandshakeError, MessageValue] = co_await Connection->ReadHandshake();
        EXPECT_EQ(HandshakeError, Prism::Error::None);
        EXPECT_EQ(MessageValue.Type, Hysteria2::Message::Kind::Tcp);

        auto Wire = DatagramWire();
        if (Malformed)
        {
            Wire[0] = 0x7FU;
        }
        else
        {
            Wire.resize(3U);
        }
        Raw->SetTransportType(Prism::Transmission::Type::Udp);
        Raw->SetInput(std::move(Wire), Terminal);
        const auto ReadsBefore = Raw->ReadsDone();
        Hysteria2::Address Source{};
        std::vector<std::uint8_t> Payload;
        const auto First = co_await Connection->AsyncReceiveDatagram(Source, Payload);
        EXPECT_EQ(First, Malformed ? Prism::Error::BadMessage : ErrorForTerminal(Terminal));
        EXPECT_EQ(Raw->ReadsDone(), ReadsBefore + 1U);
        const auto Reads = Raw->ReadsDone();

        const auto Retry = co_await Connection->AsyncReceiveDatagram(Source, Payload);
        EXPECT_EQ(Retry, ErrorForTerminal(Terminal));
        EXPECT_EQ(Raw->ReadsDone(), Reads);
        const auto StickyRetry = co_await Connection->AsyncReceiveDatagram(Source, Payload);
        EXPECT_EQ(StickyRetry, ErrorForTerminal(Terminal));
        EXPECT_EQ(Raw->ReadsDone(), Reads);

        std::array<std::byte, 8> ReadBuffer{};
        const auto StickyRead = co_await Connection->ReadSome(ReadBuffer);
        EXPECT_EQ(StickyRead.Bytes, 0U);
        EXPECT_EQ(StickyRead.Failure.Code, Terminal.Code);
        EXPECT_EQ(StickyRead.Failure.Native, Terminal.Native);
        EXPECT_EQ(Raw->ReadsDone(), Reads);
        EXPECT_TRUE(co_await CloseAndDrain(*Connection));
        EXPECT_TRUE(co_await DrainActivity(*Raw));
    }

    auto RunDgramDatagramTerminal(Fault::Failure Terminal)
        -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<TerminalTransmission>(
            co_await Net::this_coro::executor, DatagramWire(), Terminal);
        Raw->SetTransportType(Prism::Transmission::Type::Udp);
        auto Datagram = std::make_shared<Hysteria2::Dgram<>>(Raw);
        Hysteria2::Address Source{};
        std::vector<std::uint8_t> Payload;

        const auto First = co_await Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(First, Prism::Error::None);
        EXPECT_EQ(Source.Host, "127.0.0.1");
        EXPECT_EQ(Source.Port, 443U);
        EXPECT_EQ(Payload, (std::vector<std::uint8_t>{0xA1U, 0xB2U, 0xC3U}));
        const auto Reads = Raw->ReadsDone();

        const auto Next = co_await Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(Next, ErrorForTerminal(Terminal));
        EXPECT_EQ(Raw->ReadsDone(), Reads);
        const auto Retry = co_await Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(Retry, ErrorForTerminal(Terminal));
        EXPECT_EQ(Raw->ReadsDone(), Reads);

        EXPECT_TRUE(co_await CloseAndDrain(*Datagram));
        EXPECT_TRUE(co_await DrainActivity(*Raw));
    }

    auto RunDgramPartialDatagramTerminal(
        Fault::Failure Terminal,
        const std::size_t DatagramBytes) -> Net::awaitable<void>
    {
        auto Wire = DatagramWire();
        EXPECT_LT(DatagramBytes, Wire.size());
        if (DatagramBytes >= Wire.size())
        {
            co_return;
        }
        Wire.resize(DatagramBytes);
        auto Raw = std::make_shared<TerminalTransmission>(
            co_await Net::this_coro::executor, std::move(Wire), Terminal);
        Raw->SetTransportType(Prism::Transmission::Type::Udp);
        auto Datagram = std::make_shared<Hysteria2::Dgram<>>(Raw);
        Hysteria2::Address Source{};
        std::vector<std::uint8_t> Payload;

        const auto First = co_await Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(First, Prism::Error::NeedMore);
        EXPECT_EQ(Raw->ReadsDone(), 1U);
        const auto Reads = Raw->ReadsDone();
        const auto Retry = co_await Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(Retry, ErrorForTerminal(Terminal));
        EXPECT_EQ(Raw->ReadsDone(), Reads);
        const auto StickyRetry = co_await Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(StickyRetry, ErrorForTerminal(Terminal));
        EXPECT_EQ(Raw->ReadsDone(), Reads);

        EXPECT_TRUE(co_await CloseAndDrain(*Datagram));
        EXPECT_TRUE(co_await DrainActivity(*Raw));
    }

    auto RunCoroutine(Net::awaitable<void> Operation) -> void
    {
        Net::io_context Io;
        std::exception_ptr Failure;
        Net::co_spawn(Io, std::move(Operation),
            [&Failure](std::exception_ptr Error) { Failure = std::move(Error); });
        Io.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    TEST(Hysteria2ConnTerminalRead, CompleteFramePrecedesEof)
    {
        RunCoroutine(RunHandshakeTerminal(EofFailure(), true));
    }

    TEST(Hysteria2ConnTerminalRead, CompleteFramePrecedesReset)
    {
        RunCoroutine(RunHandshakeTerminal(ResetFailure(), true));
    }

    TEST(Hysteria2ConnTerminalRead, CompleteFramePrecedesCancellation)
    {
        RunCoroutine(RunHandshakeTerminal(CanceledFailure(), true));
    }

    TEST(Hysteria2ConnTerminalRead, CompleteFramePrecedesTimeout)
    {
        RunCoroutine(RunHandshakeTerminal(TimeoutFailure(), true));
    }

    TEST(Hysteria2ConnTerminalRead, PartialFrameEofIsSticky)
    {
        RunCoroutine(RunHandshakeTerminal(EofFailure(), false));
    }

    TEST(Hysteria2ConnTerminalRead, PartialFrameResetIsSticky)
    {
        RunCoroutine(RunHandshakeTerminal(ResetFailure(), false));
    }

    TEST(Hysteria2ConnTerminalRead, PartialHeaderResetMapsIoError)
    {
        RunCoroutine(RunHandshakeFieldTerminal(ResetFailure(), 1U));
    }

    TEST(Hysteria2ConnTerminalRead, PartialHeaderCancellationMapsCanceled)
    {
        RunCoroutine(RunHandshakeFieldTerminal(CanceledFailure(), 1U));
    }

    TEST(Hysteria2ConnTerminalRead, PartialHeaderTimeoutMapsTimeout)
    {
        RunCoroutine(RunHandshakeFieldTerminal(TimeoutFailure(), 1U));
    }

    TEST(Hysteria2ConnTerminalRead, PartialAddressResetMapsIoError)
    {
        RunCoroutine(RunHandshakeFieldTerminal(ResetFailure(), 4U));
    }

    TEST(Hysteria2ConnTerminalRead, PartialAddressCancellationMapsCanceled)
    {
        RunCoroutine(RunHandshakeFieldTerminal(CanceledFailure(), 4U));
    }

    TEST(Hysteria2ConnTerminalRead, PartialAddressTimeoutMapsTimeout)
    {
        RunCoroutine(RunHandshakeFieldTerminal(TimeoutFailure(), 4U));
    }

    TEST(Hysteria2ConnTerminalRead, PartialPortResetMapsIoError)
    {
        RunCoroutine(RunHandshakeFieldTerminal(ResetFailure(), 7U));
    }

    TEST(Hysteria2ConnTerminalRead, PartialPortCancellationMapsCanceled)
    {
        RunCoroutine(RunHandshakeFieldTerminal(CanceledFailure(), 7U));
    }

    TEST(Hysteria2ConnTerminalRead, PartialPortTimeoutMapsTimeout)
    {
        RunCoroutine(RunHandshakeFieldTerminal(TimeoutFailure(), 7U));
    }

    TEST(Hysteria2ConnTerminalRead, DatagramPacketPrecedesReset)
    {
        RunCoroutine(RunConnectionDatagramTerminal(ResetFailure()));
    }

    TEST(Hysteria2ConnTerminalRead, DatagramPacketPrecedesCancellation)
    {
        RunCoroutine(RunConnectionDatagramTerminal(CanceledFailure()));
    }

    TEST(Hysteria2ConnTerminalRead, DatagramPacketPrecedesTimeout)
    {
        RunCoroutine(RunConnectionDatagramTerminal(TimeoutFailure()));
    }

    TEST(Hysteria2ConnTerminalRead, MalformedPacketPrecedesStickyReset)
    {
        RunCoroutine(RunConnectionDatagramFailure(ResetFailure(), true));
    }

    TEST(Hysteria2ConnTerminalRead, PartialPacketEofMapsUnexpectedEof)
    {
        RunCoroutine(RunConnectionDatagramFailure(EofFailure(), false));
    }

    TEST(Hysteria2ConnTerminalRead, PartialPacketResetMapsIoError)
    {
        RunCoroutine(RunConnectionDatagramFailure(ResetFailure(), false));
    }

    TEST(Hysteria2DgramTerminalRead, DatagramPacketPrecedesReset)
    {
        RunCoroutine(RunDgramDatagramTerminal(ResetFailure()));
    }

    TEST(Hysteria2DgramTerminalRead, DatagramPacketPrecedesCancellation)
    {
        RunCoroutine(RunDgramDatagramTerminal(CanceledFailure()));
    }

    TEST(Hysteria2DgramTerminalRead, DatagramPacketPrecedesTimeout)
    {
        RunCoroutine(RunDgramDatagramTerminal(TimeoutFailure()));
    }

    TEST(Hysteria2DgramTerminalRead, PartialHeaderKeepsNeedMoreBeforeStickyReset)
    {
        RunCoroutine(RunDgramPartialDatagramTerminal(ResetFailure(), 3U));
    }

    TEST(Hysteria2DgramTerminalRead, PartialAddressKeepsNeedMoreBeforeStickyCancellation)
    {
        RunCoroutine(RunDgramPartialDatagramTerminal(CanceledFailure(), 12U));
    }

    TEST(Hysteria2DgramTerminalRead, PartialPortKeepsNeedMoreBeforeStickyTimeout)
    {
        RunCoroutine(RunDgramPartialDatagramTerminal(TimeoutFailure(), 15U));
    }
} // namespace
