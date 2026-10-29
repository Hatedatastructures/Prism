/**
 * @file ReadTest.cpp
 * @brief TrustTunnel HTTP/2 driver 对合并字节与终态的处理测试。
 */

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Contract/Io/IoResult.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Protocols/Http2/Types.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2/ReadCompletion.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2/Transport.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2/WireWriter.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace H2 = Prism::Http2;
    namespace Trusttunnel = Prism::Trusttunnel::Detail;

    using ReadStep = Trusttunnel::Http2ReadStep;
    using ReadTransport = Trusttunnel::Http2Transport;
    using WriteResult = std::expected<void, Prism::Fault::Failure>;

    auto NoopTransportWrite(std::int32_t, std::span<const std::byte>)
        -> Net::awaitable<WriteResult>
    {
        co_return WriteResult{};
    }

    template <typename Awaitable>
    auto RunCoro(Net::io_context &IoContext, Awaitable Operation) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, std::move(Operation),
            [&Exception, &IoContext](std::exception_ptr Error)
            {
                Exception = std::move(Error);
                IoContext.stop();
            });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    [[nodiscard]] auto MakeClientSettingsWire(Net::io_context &IoContext)
        -> std::vector<std::byte>
    {
        H2::Session Client(IoContext.get_executor(), false);
        const std::array<H2::SettingsEntry, 1> Settings{{
            {H2::SettingsMaxConcurrentStreams, 10}}};
        Client.SendSettings(Settings);
        std::vector<std::byte> Wire;
        (void)Client.Collect(Wire);
        return Wire;
    }

    [[nodiscard]] auto MakeCapturingWire(
        Net::any_io_executor Executor,
        const std::shared_ptr<std::vector<std::byte>> &Output)
        -> std::shared_ptr<Trusttunnel::Http2WireWriter>
    {
        return std::make_shared<Trusttunnel::Http2WireWriter>(
            std::move(Executor),
            [Output](const std::span<const std::byte> Data)
                -> Net::awaitable<Trusttunnel::Http2WireResult>
            {
                Output->insert(Output->end(), Data.begin(), Data.end());
                co_return Trusttunnel::Http2WireResult{};
            });
    }

    struct WireAttempt final
    {
        std::vector<std::byte> Bytes;
        std::size_t Calls{0};
    };

    [[nodiscard]] auto MakeFailingWire(
        Net::any_io_executor Executor,
        const std::shared_ptr<WireAttempt> &Attempt,
        const Prism::Fault::Failure WriteFailure)
        -> std::shared_ptr<Trusttunnel::Http2WireWriter>
    {
        return std::make_shared<Trusttunnel::Http2WireWriter>(
            std::move(Executor),
            [Attempt, WriteFailure](const std::span<const std::byte> Data)
                -> Net::awaitable<Trusttunnel::Http2WireResult>
            {
                ++Attempt->Calls;
                Attempt->Bytes.assign(Data.begin(), Data.end());
                co_return std::unexpected(WriteFailure);
            });
    }

    struct ReadTerminalObservation final
    {
        std::vector<std::byte> Data;
        std::array<std::size_t, 6> Counts{};
        std::array<Prism::Fault::Failure, 2> Terminal{};
    };

    auto ReadQueuedDataAndRepeatTerminal(
        const std::shared_ptr<ReadTransport> &Transport,
        const std::shared_ptr<ReadTerminalObservation> &Observation)
        -> Net::awaitable<void>
    {
        std::array<std::byte, 2> Buffer{};
        for (std::size_t Index = 0; Index < Observation->Counts.size(); ++Index)
        {
            const auto Part = co_await Transport->ReadSome(Buffer);
            EXPECT_LE(Part.Bytes, Buffer.size());
            if (Part.Bytes > Buffer.size()) co_return;
            Observation->Counts[Index] = Part.Bytes;
            Observation->Data.insert(
                Observation->Data.end(), Buffer.begin(),
                Buffer.begin() + static_cast<std::ptrdiff_t>(Part.Bytes));
            if (Index >= 4) Observation->Terminal[Index - 4] = Part.Failure;
            if (Index < 4) EXPECT_FALSE(Part.Failure.Failed());
            else EXPECT_TRUE(Part.Failure.Failed());
        }
    }

    [[nodiscard]] auto HasSettingsAck(const std::vector<std::byte> &Wire) -> bool
    {
        return Wire.size() >= 9U &&
            std::to_integer<std::uint8_t>(Wire[3]) == 4U &&
            std::to_integer<std::uint8_t>(Wire[4]) == 1U;
    }

    [[nodiscard]] auto CountSettingsAcks(const std::vector<std::byte> &Wire) -> std::size_t
    {
        std::size_t Count = 0;
        std::size_t Offset = 0;
        while (Wire.size() - Offset >= 9U)
        {
            const auto PayloadLength =
                (static_cast<std::size_t>(std::to_integer<std::uint8_t>(Wire[Offset])) << 16U) |
                (static_cast<std::size_t>(std::to_integer<std::uint8_t>(Wire[Offset + 1U])) << 8U) |
                static_cast<std::size_t>(std::to_integer<std::uint8_t>(Wire[Offset + 2U]));
            if (PayloadLength > Wire.size() - Offset - 9U)
            {
                return Count;
            }
            const bool IsConnectionSettingsAck = PayloadLength == 0U &&
                std::to_integer<std::uint8_t>(Wire[Offset + 3U]) == 4U &&
                std::to_integer<std::uint8_t>(Wire[Offset + 4U]) == 1U &&
                Wire[Offset + 5U] == std::byte{0} &&
                Wire[Offset + 6U] == std::byte{0} &&
                Wire[Offset + 7U] == std::byte{0} &&
                Wire[Offset + 8U] == std::byte{0};
            if (IsConnectionSettingsAck)
            {
                ++Count;
            }
            Offset += 9U + PayloadLength;
        }
        return Count;
    }

    auto RunReadCompletion(
        const Trusttunnel::Http2ReadCompletion &Completion,
        const std::shared_ptr<H2::Session> &Session,
        const std::shared_ptr<Trusttunnel::Http2WireWriter> &Wire)
        -> Net::awaitable<std::expected<ReadStep, Prism::Fault::Failure>>
    {
        const auto Result = co_await Trusttunnel::ProcessHttp2ReadCompletion(
            Completion, Session, Wire);
        Wire->Close();
        const auto Drained = co_await Wire->Drain();
        if (!Drained)
        {
            co_return std::unexpected(Drained.error());
        }
        co_return Result;
    }

    struct ClientResponseOnHeaders final
    {
        H2::Session &Server;
        const std::array<std::byte, 7> &Payload;
        std::optional<Prism::Fault::Failure> &Failure;

        auto operator()(
            const std::int32_t StreamId,
            const H2::HeaderList &,
            const bool) const -> void
        {
            const auto Headers = Server.SubmitHeaders(StreamId, {{":status", "200"}}, false);
            if (!Headers)
            {
                Failure = Headers.error();
                return;
            }
            if (Server.SubmitData(StreamId, Payload, true) != H2::SubmitDataStatus::Accepted)
                Failure = Prism::Fault::Failure{Prism::Fault::Code::ProtocolError};
        }
    };
}

TEST(TrusttunnelHttp2ReadCompletion, FeedsFrameBeforeEof)
{
    Net::io_context IoContext;
    const auto Input = MakeClientSettingsWire(IoContext);
    ASSERT_FALSE(Input.empty());

    auto Session = std::make_shared<H2::Session>(IoContext.get_executor(), true);
    auto Output = std::make_shared<std::vector<std::byte>>();
    auto Wire = MakeCapturingWire(IoContext.get_executor(), Output);
    const Trusttunnel::Http2ReadCompletion Completion{
        std::span<const std::byte>(Input),
        Prism::IoResult{Input.size(), {Prism::Fault::Code::Eof}}};
    std::optional<std::expected<ReadStep, Prism::Fault::Failure>> Result;

    RunCoro(IoContext, [&]() -> Net::awaitable<void>
    {
        Result.emplace(co_await RunReadCompletion(Completion, Session, Wire));
    }());

    ASSERT_TRUE(Result.has_value());
    ASSERT_TRUE(Result->has_value());
    EXPECT_TRUE(Result->value().Terminal);
    EXPECT_TRUE(Result->value().ReadTerminal);
    EXPECT_EQ(Result->value().Failure.Code, Prism::Fault::Code::Eof);
    EXPECT_EQ(CountSettingsAcks(*Output), 1U);
    EXPECT_TRUE(HasSettingsAck(*Output));
}

TEST(TrusttunnelHttp2ReadCompletion, PreservesPartialDataBeforeEof)
{
    Net::io_context IoContext;
    H2::Session Sender(IoContext.get_executor(), false);
    Sender.SendSettings();
    const auto Stream = Sender.OpenStream({{":method", "POST"}, {":path", "/"}}, false);
    ASSERT_TRUE(Stream);
    const std::array<std::byte, 3> CompletePayload{
        std::byte{'a'}, std::byte{'b'}, std::byte{'c'}};
    const std::array<std::byte, 4> PartialPayload{
        std::byte{'d'}, std::byte{'e'}, std::byte{'f'}, std::byte{'g'}};
    ASSERT_EQ(Sender.SubmitData(*Stream, CompletePayload, false), H2::SubmitDataStatus::Accepted);
    ASSERT_EQ(Sender.SubmitData(*Stream, PartialPayload, true), H2::SubmitDataStatus::Accepted);
    std::vector<std::byte> Input;
    ASSERT_TRUE(Sender.Collect(Input));
    ASSERT_GT(Input.size(), 1U);
    Input.pop_back();

    auto Session = std::make_shared<H2::Session>(IoContext.get_executor(), true);
    std::vector<std::byte> Received;
    Session->OnData = [&Received](std::int32_t, const std::span<const std::byte> Data)
    { Received.insert(Received.end(), Data.begin(), Data.end()); };
    auto Output = std::make_shared<std::vector<std::byte>>();
    auto Wire = MakeCapturingWire(IoContext.get_executor(), Output);
    const Trusttunnel::Http2ReadCompletion Completion{
        std::span<const std::byte>(Input),
        Prism::IoResult{Input.size(), {Prism::Fault::Code::Eof}}};
    std::optional<std::expected<ReadStep, Prism::Fault::Failure>> Result;

    RunCoro(IoContext, [&]() -> Net::awaitable<void>
    {
        Result.emplace(co_await RunReadCompletion(Completion, Session, Wire));
    }());

    ASSERT_TRUE(Result.has_value());
    ASSERT_TRUE(Result->has_value());
    EXPECT_TRUE(Result->value().Terminal);
    EXPECT_TRUE(Result->value().ReadTerminal);
    EXPECT_EQ(Result->value().Failure.Code, Prism::Fault::Code::Eof);
    EXPECT_EQ(Received, std::vector<std::byte>(CompletePayload.begin(), CompletePayload.end()));
}

TEST(TrusttunnelHttp2ReadCompletion, DeliversDataFramesBeforeSameReadEof)
{
    Net::io_context IoContext;
    H2::Session Sender(IoContext.get_executor(), false);
    Sender.SendSettings();
    const auto Stream = Sender.OpenStream({{":method", "POST"}, {":path", "/"}}, false);
    ASSERT_TRUE(Stream);
    const std::array<std::byte, 3> First{
        std::byte{'a'}, std::byte{'b'}, std::byte{'c'}};
    const std::array<std::byte, 4> Second{
        std::byte{'d'}, std::byte{'e'}, std::byte{'f'}, std::byte{'g'}};
    ASSERT_EQ(Sender.SubmitData(*Stream, First, false), H2::SubmitDataStatus::Accepted);
    ASSERT_EQ(Sender.SubmitData(*Stream, Second, true), H2::SubmitDataStatus::Accepted);
    std::vector<std::byte> Input;
    ASSERT_TRUE(Sender.Collect(Input));

    auto Transport = std::make_shared<ReadTransport>(ReadTransport::Options{
        .Executor = IoContext.get_executor(),
        .Write = ReadTransport::WriteCb{NoopTransportWrite},
        .Finish = ReadTransport::FinishCb{},
        .Close = ReadTransport::CloseCb{}});
    auto Session = std::make_shared<H2::Session>(IoContext.get_executor(), true);
    Session->OnData = [Transport](std::int32_t, const std::span<const std::byte> Data)
    { Transport->Push(Data); };
    auto Output = std::make_shared<std::vector<std::byte>>();
    auto Wire = MakeCapturingWire(IoContext.get_executor(), Output);
    const Trusttunnel::Http2ReadCompletion Completion{
        std::span<const std::byte>(Input),
        Prism::IoResult{Input.size(), {Prism::Fault::Code::Eof}}};
    std::optional<std::expected<ReadStep, Prism::Fault::Failure>> Result;

    RunCoro(IoContext, [&]() -> Net::awaitable<void>
    {
        Result.emplace(co_await RunReadCompletion(Completion, Session, Wire));
    }());

    ASSERT_TRUE(Result.has_value());
    ASSERT_TRUE(Result->has_value());
    EXPECT_EQ(Result->value().Failure.Code, Prism::Fault::Code::Eof);
    EXPECT_TRUE(HasSettingsAck(*Output));
    Transport->NotifyReadTerminal(Result->value().Failure);
    IoContext.restart();
    auto Observation = std::make_shared<ReadTerminalObservation>();
    RunCoro(IoContext, ReadQueuedDataAndRepeatTerminal(Transport, Observation));

    const std::array<std::byte, 7> Expected{
        std::byte{'a'}, std::byte{'b'}, std::byte{'c'}, std::byte{'d'},
        std::byte{'e'}, std::byte{'f'}, std::byte{'g'}};
    EXPECT_EQ(Observation->Data, std::vector<std::byte>(Expected.begin(), Expected.end()));
    EXPECT_EQ(Observation->Counts, (std::array<std::size_t, 6>{2U, 1U, 2U, 2U, 0U, 0U}));
    EXPECT_EQ(Observation->Terminal[0].Code, Prism::Fault::Code::Eof);
    EXPECT_EQ(Observation->Terminal[1].Code, Prism::Fault::Code::Eof);
    IoContext.restart();
    EXPECT_TRUE(Transport->Close());
    IoContext.restart();
    std::expected<void, Prism::Fault::Failure> Drain;
    RunCoro(IoContext, [&]() -> Net::awaitable<void>
    {
        Drain = co_await Transport->Activity()->Drain();
    }());
    EXPECT_TRUE(Drain);
}

TEST(TrusttunnelHttp2ReadCompletion, ZeroSuccessReadIsNotCleanEof)
{
    Net::io_context IoContext;
    auto Session = std::make_shared<H2::Session>(IoContext.get_executor(), true);
    auto Output = std::make_shared<std::vector<std::byte>>();
    auto Wire = MakeCapturingWire(IoContext.get_executor(), Output);
    const Trusttunnel::Http2ReadCompletion Completion{
        std::span<const std::byte>{}, Prism::IoResult{0U, {}}};
    std::optional<std::expected<ReadStep, Prism::Fault::Failure>> Result;

    RunCoro(IoContext, [&]() -> Net::awaitable<void>
    {
        Result.emplace(co_await RunReadCompletion(Completion, Session, Wire));
    }());

    ASSERT_TRUE(Result.has_value());
    ASSERT_TRUE(Result->has_value());
    EXPECT_TRUE(Result->value().ReadTerminal);
    EXPECT_EQ(Result->value().Failure.Code, Prism::Fault::Code::WouldBlock);
}

TEST(TrusttunnelHttp2ReadCompletion, FeedsFrameBeforeNativeFailure)
{
    Net::io_context IoContext;
    const auto Input = MakeClientSettingsWire(IoContext);
    ASSERT_FALSE(Input.empty());

    auto Session = std::make_shared<H2::Session>(IoContext.get_executor(), true);
    auto Output = std::make_shared<std::vector<std::byte>>();
    auto Wire = MakeCapturingWire(IoContext.get_executor(), Output);
    const auto Native = std::make_error_code(std::errc::connection_reset);
    const Trusttunnel::Http2ReadCompletion Completion{
        std::span<const std::byte>(Input),
        Prism::IoResult{Input.size(), Prism::Fault::FromNative(Native)}};
    std::optional<std::expected<ReadStep, Prism::Fault::Failure>> Result;

    RunCoro(IoContext, [&]() -> Net::awaitable<void>
    {
        Result.emplace(co_await RunReadCompletion(Completion, Session, Wire));
    }());

    ASSERT_TRUE(Result.has_value());
    ASSERT_TRUE(Result->has_value());
    EXPECT_TRUE(Result->value().Terminal);
    EXPECT_TRUE(Result->value().ReadTerminal);
    EXPECT_EQ(Result->value().Failure.Native, Native);
    EXPECT_EQ(CountSettingsAcks(*Output), 1U);
    EXPECT_TRUE(HasSettingsAck(*Output));
}

TEST(TrusttunnelHttp2ReadCompletion, FeedsFrameBeforeCanceledRead)
{
    Net::io_context IoContext;
    const auto Input = MakeClientSettingsWire(IoContext);
    auto Session = std::make_shared<H2::Session>(IoContext.get_executor(), true);
    auto Output = std::make_shared<std::vector<std::byte>>();
    auto Wire = MakeCapturingWire(IoContext.get_executor(), Output);
    const auto Native = std::make_error_code(std::errc::operation_canceled);
    const Trusttunnel::Http2ReadCompletion Completion{
        std::span<const std::byte>(Input),
        Prism::IoResult{Input.size(), Prism::Fault::FromNative(Native)}};
    std::optional<std::expected<ReadStep, Prism::Fault::Failure>> Result;

    RunCoro(IoContext, [&]() -> Net::awaitable<void>
    {
        Result.emplace(co_await RunReadCompletion(Completion, Session, Wire));
    }());

    ASSERT_TRUE(Result.has_value());
    ASSERT_TRUE(Result->has_value());
    EXPECT_TRUE(Result->value().Terminal);
    EXPECT_TRUE(Result->value().ReadTerminal);
    EXPECT_EQ(Result->value().Failure.Code, Prism::Fault::Code::Canceled);
    EXPECT_EQ(Result->value().Failure.Native, Native);
    EXPECT_EQ(CountSettingsAcks(*Output), 1U);
    EXPECT_TRUE(HasSettingsAck(*Output));
}

TEST(TrusttunnelHttp2ReadCompletion, QueuesSessionDataBeforeSameReadReset)
{
    Net::io_context IoContext;
    const std::array<std::byte, 7> Payload{
        std::byte{'a'}, std::byte{'b'}, std::byte{'c'}, std::byte{'d'},
        std::byte{'e'}, std::byte{'f'}, std::byte{'g'}};
    H2::Session Sender(IoContext.get_executor(), false);
    Sender.SendSettings();
    const auto StreamId = Sender.OpenStream({{":method", "POST"}, {":path", "/"}}, false);
    ASSERT_TRUE(StreamId);
    ASSERT_EQ(Sender.SubmitData(*StreamId, Payload, true), H2::SubmitDataStatus::Accepted);
    std::vector<std::byte> Input;
    ASSERT_TRUE(Sender.Collect(Input));

    const auto CarrierCloseCalls = std::make_shared<std::size_t>(0);
    auto Transport = std::make_shared<ReadTransport>(ReadTransport::Options{
        .Executor = IoContext.get_executor(),
        .Write = ReadTransport::WriteCb{NoopTransportWrite},
        .Finish = ReadTransport::FinishCb{},
        .Close = ReadTransport::CloseCb{[CarrierCloseCalls]
        {
            ++*CarrierCloseCalls;
            return WriteResult{};
        }}});
    auto Session = std::make_shared<H2::Session>(IoContext.get_executor(), true);
    Session->OnData = [Transport](std::int32_t, const std::span<const std::byte> Data)
    {
        Transport->Push(Data);
    };
    auto Output = std::make_shared<std::vector<std::byte>>();
    auto Wire = MakeCapturingWire(IoContext.get_executor(), Output);
    const auto Native = std::make_error_code(std::errc::connection_reset);
    std::optional<std::expected<ReadStep, Prism::Fault::Failure>> Step;

    RunCoro(IoContext, [&]() -> Net::awaitable<void>
    {
        Step.emplace(co_await RunReadCompletion(
            Trusttunnel::Http2ReadCompletion{
                std::span<const std::byte>(Input),
                Prism::IoResult{Input.size(), Prism::Fault::FromNative(Native)}},
            Session, Wire));
    }());

    ASSERT_TRUE(Step.has_value());
    ASSERT_TRUE(Step->has_value());
    EXPECT_TRUE(Step->value().ReadTerminal);
    EXPECT_EQ(Step->value().Failure.Native, Native);
    Transport->NotifyReadTerminal(Step->value().Failure);
    EXPECT_TRUE(Transport->CloseCarrierForReadTerminal().Succeeded());
    EXPECT_EQ(*CarrierCloseCalls, 1U);
    EXPECT_FALSE(Transport->Activity()->IsRetired());
    EXPECT_TRUE(HasSettingsAck(*Output));
    IoContext.restart();
    const auto Observation = std::make_shared<ReadTerminalObservation>();
    RunCoro(IoContext, ReadQueuedDataAndRepeatTerminal(Transport, Observation));
    EXPECT_EQ(Observation->Data, std::vector<std::byte>(Payload.begin(), Payload.end()));
    EXPECT_EQ(Observation->Counts, (std::array<std::size_t, 6>{2U, 2U, 2U, 1U, 0U, 0U}));
    for (const auto &Terminal : Observation->Terminal)
    {
        EXPECT_EQ(Terminal.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Terminal.Native, Native);
    }

    IoContext.restart();
    IoContext.restart();
    IoContext.restart();
    IoContext.restart();
    IoContext.restart();
    IoContext.restart();
    IoContext.restart();
    const auto Closed = Transport->Close();
    ASSERT_TRUE(Closed) << (Closed ? 0U : static_cast<unsigned>(Closed.error().Code));
    EXPECT_EQ(*CarrierCloseCalls, 1U);
    IoContext.restart();
    std::expected<void, Prism::Fault::Failure> Drain;
    RunCoro(IoContext, [&]() -> Net::awaitable<void>
    {
        Drain = co_await Transport->Activity()->Drain();
    }());
    ASSERT_TRUE(Drain) << (Drain ? 0U : static_cast<unsigned>(Drain.error().Code));
}

TEST(TrusttunnelHttp2ReadCompletion, ClientSessionQueuesResponseBeforeSameReadReset)
{
    Net::io_context IoContext;
    const std::array<std::byte, 7> Payload{
        std::byte{'a'}, std::byte{'b'}, std::byte{'c'}, std::byte{'d'},
        std::byte{'e'}, std::byte{'f'}, std::byte{'g'}};
    auto Client = std::make_shared<H2::Session>(IoContext.get_executor(), false);
    Client->SendSettings();
    const auto StreamId = Client->OpenStream(
        {{":method", "CONNECT"}, {":authority", "example.test"}}, false);
    ASSERT_TRUE(StreamId);
    std::vector<std::byte> RequestWire;
    ASSERT_TRUE(Client->Collect(RequestWire));

    H2::Session Server(IoContext.get_executor(), true);
    Server.SendSettings();
    std::optional<Prism::Fault::Failure> ServerFailure;
    Server.OnHeaders = ClientResponseOnHeaders{Server, Payload, ServerFailure};
    std::error_code FrameError;
    ASSERT_TRUE(Server.Feed(RequestWire, FrameError)) << FrameError.message();
    ASSERT_FALSE(ServerFailure.has_value());
    std::vector<std::byte> ResponseWire;
    ASSERT_TRUE(Server.Collect(ResponseWire));

    const auto CarrierCloseCalls = std::make_shared<std::size_t>(0);
    auto Transport = std::make_shared<ReadTransport>(ReadTransport::Options{
        .Executor = IoContext.get_executor(),
        .Write = ReadTransport::WriteCb{NoopTransportWrite},
        .Finish = ReadTransport::FinishCb{},
        .Close = ReadTransport::CloseCb{[CarrierCloseCalls]
        {
            ++*CarrierCloseCalls;
            return WriteResult{};
        }}});
    Client->OnData = [Transport](std::int32_t, const std::span<const std::byte> Data)
    {
        Transport->Push(Data);
    };
    auto Output = std::make_shared<std::vector<std::byte>>();
    auto Wire = MakeCapturingWire(IoContext.get_executor(), Output);
    const auto Native = std::make_error_code(std::errc::connection_reset);
    std::optional<std::expected<ReadStep, Prism::Fault::Failure>> Step;

    RunCoro(IoContext, [&]() -> Net::awaitable<void>
    {
        Step.emplace(co_await RunReadCompletion(
            Trusttunnel::Http2ReadCompletion{
                std::span<const std::byte>(ResponseWire),
                Prism::IoResult{ResponseWire.size(), Prism::Fault::FromNative(Native)}},
            Client, Wire));
    }());

    ASSERT_TRUE(Step.has_value());
    ASSERT_TRUE(Step->has_value());
    EXPECT_TRUE(Step->value().ReadTerminal);
    EXPECT_EQ(Step->value().Failure.Native, Native);
    Transport->NotifyReadTerminal(Step->value().Failure);
    EXPECT_TRUE(Transport->CloseCarrierForReadTerminal().Succeeded());
    EXPECT_EQ(*CarrierCloseCalls, 1U);
    EXPECT_FALSE(Transport->Activity()->IsRetired());
    IoContext.restart();
    const auto Observation = std::make_shared<ReadTerminalObservation>();
    RunCoro(IoContext, ReadQueuedDataAndRepeatTerminal(Transport, Observation));
    EXPECT_EQ(Observation->Data, std::vector<std::byte>(Payload.begin(), Payload.end()));
    EXPECT_EQ(Observation->Counts, (std::array<std::size_t, 6>{2U, 2U, 2U, 1U, 0U, 0U}));
    for (const auto &Terminal : Observation->Terminal)
    {
        EXPECT_EQ(Terminal.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Terminal.Native, Native);
    }

    IoContext.restart();
    IoContext.restart();
    const auto Closed = Transport->Close();
    ASSERT_TRUE(Closed) << (Closed ? 0U : static_cast<unsigned>(Closed.error().Code));
    EXPECT_EQ(*CarrierCloseCalls, 1U);
    IoContext.restart();
    std::expected<void, Prism::Fault::Failure> Drain;
    RunCoro(IoContext, [&]() -> Net::awaitable<void>
    {
        Drain = co_await Transport->Activity()->Drain();
    }());
    ASSERT_TRUE(Drain) << (Drain ? 0U : static_cast<unsigned>(Drain.error().Code));
}

TEST(TrusttunnelHttp2ReadCompletion, ClientSessionDrainsDataBeforeEofAckWriteFailure)
{
    Net::io_context IoContext;
    const std::array<std::byte, 7> Payload{
        std::byte{'a'}, std::byte{'b'}, std::byte{'c'}, std::byte{'d'},
        std::byte{'e'}, std::byte{'f'}, std::byte{'g'}};
    auto Client = std::make_shared<H2::Session>(IoContext.get_executor(), false);
    Client->SendSettings();
    const auto StreamId = Client->OpenStream(
        {{":method", "CONNECT"}, {":authority", "example.test"}}, false);
    ASSERT_TRUE(StreamId);
    std::vector<std::byte> RequestWire;
    ASSERT_TRUE(Client->Collect(RequestWire));

    H2::Session Server(IoContext.get_executor(), true);
    Server.SendSettings();
    std::optional<Prism::Fault::Failure> ServerFailure;
    Server.OnHeaders = ClientResponseOnHeaders{Server, Payload, ServerFailure};
    std::error_code FrameError;
    ASSERT_TRUE(Server.Feed(RequestWire, FrameError)) << FrameError.message();
    ASSERT_FALSE(ServerFailure.has_value());
    std::vector<std::byte> ResponseWire;
    ASSERT_TRUE(Server.Collect(ResponseWire));

    const auto CarrierCloseCalls = std::make_shared<std::size_t>(0);
    auto Transport = std::make_shared<ReadTransport>(ReadTransport::Options{
        .Executor = IoContext.get_executor(),
        .Write = ReadTransport::WriteCb{NoopTransportWrite},
        .Finish = ReadTransport::FinishCb{},
        .Close = ReadTransport::CloseCb{[CarrierCloseCalls]
        {
            ++*CarrierCloseCalls;
            return WriteResult{};
        }}});
    Client->OnData = [Transport](std::int32_t, const std::span<const std::byte> Data)
    {
        Transport->Push(Data);
    };
    const auto Native = std::make_error_code(std::errc::broken_pipe);
    const Prism::Fault::Failure WriteFailure{Prism::Fault::Code::IoError, Native};
    const auto Attempt = std::make_shared<WireAttempt>();
    auto Wire = MakeFailingWire(IoContext.get_executor(), Attempt, WriteFailure);
    const auto Read = Prism::IoResult{
        ResponseWire.size(), Prism::Fault::Failure{Prism::Fault::Code::Eof}};
    std::optional<ReadStep> Step;

    RunCoro(IoContext, [&]() -> Net::awaitable<void>
    {
        Step = co_await Trusttunnel::ProcessHttp2ReadCompletion(
            Trusttunnel::Http2ReadCompletion{
                std::span<const std::byte>(ResponseWire), Read},
            Client, Wire);
    }());

    ASSERT_TRUE(Step.has_value());
    EXPECT_TRUE(Step->Terminal);
    EXPECT_TRUE(Step->ReadTerminal);
    EXPECT_EQ(Step->Failure.Code, WriteFailure.Code);
    EXPECT_EQ(Step->Failure.Native, Native);
    EXPECT_EQ(Attempt->Calls, 1U);
    EXPECT_TRUE(HasSettingsAck(Attempt->Bytes));
    Transport->NotifyReadTerminal(Step->Failure);
    EXPECT_TRUE(Transport->CloseCarrierForReadTerminal().Succeeded());
    EXPECT_EQ(*CarrierCloseCalls, 1U);
    EXPECT_FALSE(Transport->Activity()->IsRetired());

    IoContext.restart();
    std::expected<void, Prism::Fault::Failure> WireDrain;
    RunCoro(IoContext, [&]() -> Net::awaitable<void>
    {
        Wire->Close();
        WireDrain = co_await Wire->Drain();
    }());
    EXPECT_FALSE(WireDrain);
    const auto ObservedWireFailure = WireDrain
        ? Prism::Fault::Failure{}
        : WireDrain.error();
    EXPECT_EQ(ObservedWireFailure.Code, WriteFailure.Code);
    EXPECT_EQ(ObservedWireFailure.Native, Native);
    EXPECT_TRUE(Wire->IsRetired());

    IoContext.restart();
    const auto Observation = std::make_shared<ReadTerminalObservation>();
    RunCoro(IoContext, ReadQueuedDataAndRepeatTerminal(Transport, Observation));
    EXPECT_EQ(Observation->Data, std::vector<std::byte>(Payload.begin(), Payload.end()));
    EXPECT_EQ(Observation->Counts, (std::array<std::size_t, 6>{2U, 2U, 2U, 1U, 0U, 0U}));
    for (const auto &Terminal : Observation->Terminal)
    {
        EXPECT_EQ(Terminal.Code, WriteFailure.Code);
        EXPECT_EQ(Terminal.Native, Native);
    }

    IoContext.restart();
    const auto Closed = Transport->Close();
    ASSERT_TRUE(Closed) << (Closed ? 0U : static_cast<unsigned>(Closed.error().Code));
    EXPECT_EQ(*CarrierCloseCalls, 1U);
    IoContext.restart();
    std::expected<void, Prism::Fault::Failure> Drain;
    RunCoro(IoContext, [&]() -> Net::awaitable<void>
    {
        Drain = co_await Transport->Activity()->Drain();
    }());
    ASSERT_TRUE(Drain) << (Drain ? 0U : static_cast<unsigned>(Drain.error().Code));
}
