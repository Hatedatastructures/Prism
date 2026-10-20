/**
 * @file XhttpReadTerminalTest.cpp
 * @brief XHTTP HTTP/2 部分 DATA 与输出失败顺序测试。
 */

#include "XhttpErrorMatrixSupport.hpp"

#include <Prism/Contract/Io/IoResult.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Protocols/Xhttp/Detail/Http2ReadCompletion.hpp>
#include <Prism/Protocols/Xhttp/Detail/SplitTransport.hpp>
#include <Prism/Protocols/Xhttp/Detail/StreamTransport.hpp>
#include <Prism/Protocols/Xhttp/Detail/Wire.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

namespace
{
    struct WireAttempt final
    {
        std::vector<std::byte> Bytes;
        std::size_t Calls{0};
    };

    [[nodiscard]] auto HasSettingsAck(const std::span<const std::byte> Wire) -> bool
    {
        std::size_t Offset = 0;
        while (Wire.size() - Offset >= 9U)
        {
            const auto Length =
                (static_cast<std::size_t>(std::to_integer<std::uint8_t>(Wire[Offset])) << 16U) |
                (static_cast<std::size_t>(std::to_integer<std::uint8_t>(Wire[Offset + 1U])) << 8U) |
                static_cast<std::size_t>(std::to_integer<std::uint8_t>(Wire[Offset + 2U]));
            if (Length > Wire.size() - Offset - 9U) return false;
            const auto Type = std::to_integer<std::uint8_t>(Wire[Offset + 3U]);
            const auto Flags = std::to_integer<std::uint8_t>(Wire[Offset + 4U]);
            if (Type == 4U && Flags == 1U && Length == 0U) return true;
            Offset += 9U + Length;
        }
        return false;
    }

    template <typename Transport>
    auto VerifyQueuedDataBeforeAckFailure(
        boost::asio::any_io_executor Executor,
        std::shared_ptr<Transport> Carrier,
        Prism::Xhttp::Detail::WireWriter::FailureCallback FailureCallback = {})
        -> boost::asio::awaitable<void>
    {
        namespace H2 = Prism::Http2;
        namespace Xhttp = Prism::Xhttp::Detail;
        H2::Session Sender(Executor, false);
        Sender.SendSettings();
        const auto Stream = Sender.OpenStream(
            {{":method", "POST"}, {":path", "/"}}, false);
        EXPECT_TRUE(Stream.has_value());
        if (!Stream) co_return;
        const std::array<std::byte, 7> Payload{
            std::byte{'a'}, std::byte{'b'}, std::byte{'c'}, std::byte{'d'},
            std::byte{'e'}, std::byte{'f'}, std::byte{'g'}};
        EXPECT_EQ(Sender.SubmitData(*Stream, Payload, true), H2::SubmitDataStatus::Accepted);
        std::vector<std::byte> Input;
        EXPECT_TRUE(Sender.Collect(Input));
        if (Input.empty()) co_return;

        H2::Session Receiver(Executor, true);
        Receiver.OnData = [Carrier](
            std::int32_t, const std::span<const std::byte> Data)
        { Carrier->Push(Data); };
        const auto Read = Prism::IoResult{
            Input.size(), Prism::Fault::Failure{Prism::Fault::Code::Eof}};
        if constexpr (requires { Carrier->PreserveAcceptedDataForOutputFailure(); })
        {
            Carrier->PreserveAcceptedDataForOutputFailure();
        }
        const auto Step = Xhttp::ProcessHttp2ReadCompletion(Receiver, Input, Read);
        EXPECT_TRUE(Step.ReadTerminal);
        EXPECT_EQ(Step.Failure.Code, Prism::Fault::Code::Eof);
        if (!Step.ReadTerminal) co_return;

        std::vector<std::byte> Ack;
        EXPECT_TRUE(Receiver.Collect(Ack));
        EXPECT_FALSE(Ack.empty());
        if (Ack.empty()) co_return;
        EXPECT_TRUE(HasSettingsAck(Ack));
        const auto WriteFailure = Prism::Fault::Failure{
            Prism::Fault::Code::IoError,
            std::make_error_code(std::errc::broken_pipe)};
        auto Attempt = std::make_shared<WireAttempt>();
        auto Writer = std::make_shared<Xhttp::WireWriter>(
            Executor,
            [Attempt, WriteFailure](const std::span<const std::byte> Bytes)
                -> boost::asio::awaitable<Xhttp::WireWriter::WriteResult>
            {
                ++Attempt->Calls;
                Attempt->Bytes.assign(Bytes.begin(), Bytes.end());
                co_return std::unexpected(WriteFailure);
            },
            std::move(FailureCallback));
        const auto Written = co_await Writer->Write(Ack);
        EXPECT_FALSE(Written);
        const auto ObservedWriteFailure = Written
            ? WriteFailure
            : Written.error();
        Xhttp::NotifyHttp2OutputFailure(*Carrier, Step, ObservedWriteFailure);
        EXPECT_TRUE(Carrier->DrainTerminalPending());
        Writer->Close();
        const auto WriterDrain = co_await Writer->Drain();
        EXPECT_FALSE(WriterDrain);
        const auto WriterDrainFailure = WriterDrain
            ? Prism::Fault::Failure{}
            : WriterDrain.error();
        EXPECT_EQ(WriterDrainFailure.Native, WriteFailure.Native);
        EXPECT_TRUE(Writer->IsRetired());
        EXPECT_EQ(Attempt->Calls, 1U);
        EXPECT_TRUE(HasSettingsAck(Attempt->Bytes));
        std::vector<std::byte> Received;
        std::array<std::byte, 2> Buffer{};
        constexpr std::array<std::size_t, 4> ExpectedCounts{2U, 2U, 2U, 1U};
        for (const auto ExpectedCount : ExpectedCounts)
        {
            const auto Part = co_await Carrier->ReadSome(Buffer);
            EXPECT_EQ(Part.Bytes, ExpectedCount);
            EXPECT_FALSE(Part.Failure.Failed());
            Received.insert(Received.end(), Buffer.begin(),
                Buffer.begin() + static_cast<std::ptrdiff_t>(Part.Bytes));
        }
        EXPECT_EQ(Received, std::vector<std::byte>(Payload.begin(), Payload.end()));
        for (std::size_t Index = 0; Index < 2U; ++Index)
        {
            const auto Part = co_await Carrier->ReadSome(Buffer);
            EXPECT_EQ(Part.Bytes, 0U);
            EXPECT_EQ(Part.Failure.Code, ObservedWriteFailure.Code);
            EXPECT_EQ(Part.Failure.Native, ObservedWriteFailure.Native);
        }
        const auto Closed = Carrier->Close();
        EXPECT_TRUE(Closed);
        const auto Activity = Carrier->Activity();
        EXPECT_TRUE(Activity);
        if (!Activity) co_return;
        const auto Drained = co_await Activity->Drain();
        EXPECT_TRUE(Drained);
        EXPECT_TRUE(Activity->IsRetired());
    }

    auto MakeSplitTransport(boost::asio::any_io_executor Executor)
        -> std::shared_ptr<Prism::Xhttp::Detail::SplitTransport>
    {
        namespace Xhttp = Prism::Xhttp::Detail;
        return std::make_shared<Xhttp::SplitTransport>(
            std::move(Executor), Xhttp::SplitTransport::WriteCb(DiscardWire),
            Xhttp::SplitTransport::CloseCb{});
    }
}

TEST(XhttpErrorMatrix, ReadCompletionPreservesPartialDataBeforeEof)
{
    namespace Net = boost::asio;
    namespace H2 = Prism::Http2;
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
    std::vector<std::byte> Wire;
    ASSERT_TRUE(Sender.Collect(Wire));
    ASSERT_GT(Wire.size(), 1U);
    Wire.pop_back();

    H2::Session Receiver(IoContext.get_executor(), true);
    std::vector<std::byte> Received;
    Receiver.OnData = [&Received](std::int32_t, const std::span<const std::byte> Data)
    { Received.insert(Received.end(), Data.begin(), Data.end()); };
    const auto Step = Prism::Xhttp::Detail::ProcessHttp2ReadCompletion(
        Receiver, Wire, Prism::IoResult{Wire.size(), {Prism::Fault::Code::Eof}});

    EXPECT_TRUE(Step.ReadTerminal);
    EXPECT_EQ(Step.Failure.Code, Prism::Fault::Code::Eof);
    EXPECT_EQ(Received, std::vector<std::byte>(CompletePayload.begin(), CompletePayload.end()));
}

TEST(XhttpErrorMatrix, StreamTransportDrainsDataBeforeEofAckWriteFailure)
{
    boost::asio::io_context IoContext;
    auto Transport = MakeTransport(IoContext.get_executor());
    bool CallbackObservedDrainTerminal = false;
    const Prism::Xhttp::Detail::WireWriter::FailureCallback FailureCallback{
        [Transport, &CallbackObservedDrainTerminal](const Prism::Fault::Failure Failure)
        {
            Transport->HandleOutputFailure(Failure, [Transport, &CallbackObservedDrainTerminal]
            {
                CallbackObservedDrainTerminal = Transport->DrainTerminalPending();
                if (!Transport->DrainTerminalPending()) (void)Transport->Close();
            });
        }};
    RunCoroutine(IoContext, VerifyQueuedDataBeforeAckFailure(
        IoContext.get_executor(), std::move(Transport), FailureCallback));
    EXPECT_TRUE(CallbackObservedDrainTerminal);
}

TEST(XhttpErrorMatrix, SplitTransportDrainsDataBeforeEofAckWriteFailure)
{
    boost::asio::io_context IoContext;
    auto Transport = MakeSplitTransport(IoContext.get_executor());
    RunCoroutine(IoContext, VerifyQueuedDataBeforeAckFailure(
        IoContext.get_executor(), std::move(Transport)));
}
