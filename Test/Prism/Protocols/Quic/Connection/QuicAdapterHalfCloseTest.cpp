/**
 * @file QuicAdapterHalfCloseTest.cpp
 * @brief QUIC stream adapter preserves FIN as a relay half-close.
 */
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Net/Relay/Relay.hpp>
#include <Prism/Protocols/Quic/Native.hpp>
#include <Prism/Protocols/Quic/StreamAdapter.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;

    constexpr std::size_t RelayBufferSize{64U};

    class MemoryStreamProvider final : public Prism::Quic::StreamProvider
    {
    public:
        explicit MemoryStreamProvider(Prism::SharedTransmission Inner)
            : Inner_(std::move(Inner))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Inner_ ? Inner_->Executor() : Net::any_io_executor{};
        }

        [[nodiscard]] auto ReadCalls() const noexcept -> std::size_t
        {
            return ReadCalls_;
        }

        [[nodiscard]] auto WriteCalls() const noexcept -> std::size_t
        {
            return WriteCalls_;
        }

        [[nodiscard]] auto ShutdownWriteCalls() const noexcept -> std::size_t
        {
            return ShutdownWriteCalls_;
        }

        [[nodiscard]] auto Read(std::span<std::byte> Buffer, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t> override
        {
            ++ReadCalls_;
            if (!Inner_)
            {
                ErrorCode = std::make_error_code(std::errc::bad_file_descriptor);
                co_return 0U;
            }
            const auto Part = co_await Inner_->ReadSome(Buffer);
            ErrorCode = Prism::Fault::ToNative(Part.Failure);
            co_return Part.Bytes;
        }

        [[nodiscard]] auto Write(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            ++WriteCalls_;
            if (!Inner_)
            {
                ErrorCode = std::make_error_code(std::errc::bad_file_descriptor);
                co_return 0U;
            }
            const auto Part = co_await Inner_->WriteSome(Buffer);
            ErrorCode = Prism::Fault::ToNative(Part.Failure);
            co_return Part.Bytes;
        }

        [[nodiscard]] auto Close() -> ControlResult override
        {
            if (!Inner_) return {};
            return Inner_->Close();
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        {
            return Inner_ ? Inner_->Activity() : nullptr;
        }

        [[nodiscard]] auto ShutdownWrite() -> Net::awaitable<ShutdownResult> override
        {
            ++ShutdownWriteCalls_;
            if (!Inner_)
            {
                co_return std::unexpected(Prism::Fault::Failure{
                    Prism::Fault::Code::InvalidArgument});
            }
            co_return co_await Inner_->WriteShutdown();
        }

        [[nodiscard]] auto WaitForWriteAcknowledgement()
            -> Net::awaitable<ShutdownResult> override
        {
            co_return ShutdownResult{};
        }

        [[nodiscard]] auto StreamId() const noexcept -> std::int64_t override
        {
            return 1;
        }

        [[nodiscard]] auto IsClosed() const noexcept -> bool override
        {
            return !Inner_ || !Inner_->IsOpen();
        }

    private:
        Prism::SharedTransmission Inner_;
        std::size_t ReadCalls_{0U};
        std::size_t WriteCalls_{0U};
        std::size_t ShutdownWriteCalls_{0U};
    };

    struct PeerResult final
    {
        std::vector<std::byte> Request;
        std::vector<std::byte> Response;
    };

    struct RelayOutcome final
    {
        Prism::Network::Relay::Result Relay;
        PeerResult Peer;
    };

    struct AdapterReadOutcome final
    {
        std::array<std::byte, 4> FirstBuffer{};
        Prism::IoResult Empty;
        Prism::IoResult Buffered;
        Prism::IoResult Terminal;
        bool Closed{false};
        bool Retired{false};
    };

    struct InitialTerminalOutcome final
    {
        Prism::IoResult EmptyRead;
        Prism::IoResult FirstRead;
        Prism::IoResult SecondRead;
        Prism::IoResult Write;
        bool Shutdown{false};
        bool Closed{false};
        bool Retired{false};
        std::size_t ReadCalls{0U};
        std::size_t WriteCalls{0U};
        std::size_t ShutdownWriteCalls{0U};
    };

    [[nodiscard]] auto ReadUntilEof(const Prism::SharedTransmission &Carrier)
        -> Net::awaitable<std::vector<std::byte>>
    {
        std::vector<std::byte> Payload;
        std::array<std::byte, RelayBufferSize> Buffer{};
        while (true)
        {
            const auto Part = co_await Carrier->ReadSome(Buffer);
            if (Part.Bytes > Buffer.size())
            {
                throw std::runtime_error("QUIC adapter relay peer returned oversized input");
            }
            Payload.insert(Payload.end(), Buffer.begin(),
                Buffer.begin() + static_cast<std::ptrdiff_t>(Part.Bytes));
            if (Part.Failure.Code == Prism::Fault::Code::Eof)
            {
                co_return Payload;
            }
            if (Part.Failure.Failed() || Part.Bytes == 0U)
            {
                throw std::runtime_error("QUIC adapter relay peer ended before EOF");
            }
        }
    }

    [[nodiscard]] auto RunPeer(
        const Prism::SharedTransmission &Upstream,
        const Prism::SharedTransmission &Client) -> Net::awaitable<PeerResult>
    {
        PeerResult Result;
        Result.Request = co_await ReadUntilEof(Upstream);
        const std::array<std::byte, 6> Response{
            std::byte{0x72}, std::byte{0x65}, std::byte{0x73},
            std::byte{0x70}, std::byte{0x6F}, std::byte{0x6E}};
        const auto Write = co_await Upstream->WriteExact(Response);
        if (Write.Failure.Failed() || Write.Bytes != Response.size())
        {
            throw std::runtime_error("QUIC adapter relay response write failed");
        }
        const auto Shutdown = co_await Upstream->WriteShutdown();
        if (!Shutdown)
        {
            throw std::runtime_error("QUIC adapter relay response half-close failed");
        }
        Result.Response = co_await ReadUntilEof(Client);
        co_return Result;
    }

    [[nodiscard]] auto RunRelay(Net::any_io_executor Executor) -> Net::awaitable<RelayOutcome>
    {
        auto [ClientValue, InboundValue] = Prism::MakeMemoryPair(Executor);
        auto [OutboundValue, UpstreamValue] = Prism::MakeMemoryPair(Executor);
        Prism::SharedTransmission Client =
            std::make_shared<Prism::MemoryStream>(std::move(ClientValue));
        Prism::SharedTransmission InboundRaw =
            std::make_shared<Prism::MemoryStream>(std::move(InboundValue));
        Prism::SharedTransmission Outbound =
            std::make_shared<Prism::MemoryStream>(std::move(OutboundValue));
        Prism::SharedTransmission Upstream =
            std::make_shared<Prism::MemoryStream>(std::move(UpstreamValue));
        auto Provider = std::make_shared<MemoryStreamProvider>(InboundRaw);
        Prism::SharedTransmission Inbound =
            std::make_shared<Prism::Quic::StreamAdapter>(Executor, Provider);
        const std::array<std::byte, 4> Request{
            std::byte{0x71}, std::byte{0x75}, std::byte{0x69}, std::byte{0x63}};
        const auto RequestWrite = co_await Client->WriteExact(Request);
        if (RequestWrite.Failure.Failed() || RequestWrite.Bytes != Request.size())
        {
            throw std::runtime_error("QUIC adapter relay request write failed");
        }
        const auto RequestShutdown = co_await Client->WriteShutdown();
        if (!RequestShutdown)
        {
            throw std::runtime_error("QUIC adapter relay request half-close failed");
        }
        auto Bytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{RelayBufferSize, 2U});
        const Prism::Network::Relay::Request Input{
            .Inbound = std::move(Inbound),
            .Outbound = std::move(Outbound),
            .BufferSize = RelayBufferSize,
            .Bytes = std::move(Bytes)};
        using Net::experimental::awaitable_operators::operator&&;
        auto [Relay, Peer] = co_await (
            Prism::Network::Relay::Run(Input) && RunPeer(Upstream, Client));
        co_return RelayOutcome{std::move(Relay), std::move(Peer)};
    }

    [[nodiscard]] auto RunNativeAdapterFinRead(Net::any_io_executor Executor)
        -> Net::awaitable<AdapterReadOutcome>
    {
        auto State = std::make_shared<Prism::Quic::Detail::StreamState>(Executor, 4U);
        State->Received.push_back({std::byte{0x66}, std::byte{0x69}, std::byte{0x6E}});
        State->PeerFin = true;
        State->Closed = true;
        State->NativeTerminal.store(true, std::memory_order_release);
        auto Provider = std::make_shared<Prism::Quic::Detail::NativeStream>(
            std::weak_ptr<Prism::Quic::Detail::NativeConnection>{}, State);
        auto Adapter = std::make_shared<Prism::Quic::StreamAdapter>(Executor, Provider);
        AdapterReadOutcome Outcome;
        Outcome.Empty = co_await Adapter->ReadSome(std::span<std::byte>{});
        std::array<std::byte, 3> Buffered{};
        Outcome.Buffered = co_await Adapter->ReadSome(Buffered);
        std::copy(Buffered.begin(), Buffered.end(), Outcome.FirstBuffer.begin());
        std::array<std::byte, 1> TerminalBuffer{};
        Outcome.Terminal = co_await Adapter->ReadSome(TerminalBuffer);
        Outcome.Closed = Adapter->Close().has_value();
        const auto Activity = Adapter->Activity();
        Activity->Seal();
        const auto Drain = co_await Activity->Drain();
        Outcome.Retired = Drain.has_value();
        co_return Outcome;
    }

    [[nodiscard]] auto RunInitialTerminalCase(
        Net::any_io_executor Executor,
        Prism::Fault::Failure Terminal) -> Net::awaitable<InitialTerminalOutcome>
    {
        auto [PeerValue, InnerValue] = Prism::MakeMemoryPair(Executor);
        Prism::SharedTransmission Peer =
            std::make_shared<Prism::MemoryStream>(std::move(PeerValue));
        auto Inner = std::make_shared<Prism::MemoryStream>(std::move(InnerValue));
        auto Provider = std::make_shared<MemoryStreamProvider>(Inner);
        auto Adapter = std::make_shared<Prism::Quic::StreamAdapter>(
            Executor, Provider, Terminal);
        InitialTerminalOutcome Outcome;
        Outcome.EmptyRead = co_await Adapter->ReadSome(std::span<std::byte>{});
        std::array<std::byte, 1> Buffer{};
        Outcome.FirstRead = co_await Adapter->ReadSome(Buffer);
        Outcome.SecondRead = co_await Adapter->ReadSome(Buffer);
        const std::array<std::byte, 1> Payload{std::byte{0x61}};
        Outcome.Write = co_await Adapter->WriteSome(Payload);
        Outcome.Shutdown = (co_await Adapter->WriteShutdown()).has_value();
        Outcome.Closed = Adapter->Close().has_value();
        const auto Activity = Adapter->Activity();
        Activity->Seal();
        Outcome.Retired = (co_await Activity->Drain()).has_value();
        Outcome.ReadCalls = Provider->ReadCalls();
        Outcome.WriteCalls = Provider->WriteCalls();
        Outcome.ShutdownWriteCalls = Provider->ShutdownWriteCalls();
        (void)Peer;
        co_return Outcome;
    }

    template <class Result>
    auto RunCoro(Net::io_context &Io, Net::awaitable<Result> Operation) -> Result
    {
        std::optional<Result> Value;
        std::exception_ptr Failure;
        bool TimedOut = false;
        Net::steady_timer Deadline(Io);
        Deadline.expires_after(std::chrono::seconds{2});
        Deadline.async_wait([&](const boost::system::error_code &Error)
        {
            if (!Error)
            {
                TimedOut = true;
                Io.stop();
            }
        });
        Net::co_spawn(Io, std::move(Operation),
            [&Value, &Failure, &Deadline](std::exception_ptr Error, Result Completed)
            {
                Failure = std::move(Error);
                if (!Failure) Value.emplace(std::move(Completed));
                (void)Deadline.cancel();
            });
        Io.run();
        if (TimedOut) throw std::runtime_error("QUIC adapter relay timed out");
        if (Failure) std::rethrow_exception(Failure);
        if (!Value) throw std::runtime_error("QUIC adapter relay did not finish");
        return std::move(*Value);
    }

    [[nodiscard]] auto BytesEqual(
        const std::vector<std::byte> &Left,
        const std::span<const std::byte> Right) -> bool
    {
        return Left.size() == Right.size() && std::equal(Left.begin(), Left.end(), Right.begin());
    }
}

TEST(QuicStreamAdapterHalfClose, FinReachesRelayAndPreservesReverseResponse)
{
    Net::io_context Io;
    const auto Outcome = RunCoro(Io, RunRelay(Io.get_executor()));
    ASSERT_TRUE(Outcome.Relay.Failure.Succeeded());
    EXPECT_EQ(Outcome.Relay.Total[0], 4U);
    EXPECT_EQ(Outcome.Relay.Total[1], 6U);
    const std::array<std::byte, 4> ExpectedRequest{
        std::byte{0x71}, std::byte{0x75}, std::byte{0x69}, std::byte{0x63}};
    EXPECT_TRUE(BytesEqual(Outcome.Peer.Request, ExpectedRequest));
    const std::array<std::byte, 6> ExpectedResponse{
        std::byte{0x72}, std::byte{0x65}, std::byte{0x73},
        std::byte{0x70}, std::byte{0x6F}, std::byte{0x6E}};
    EXPECT_TRUE(BytesEqual(Outcome.Peer.Response, ExpectedResponse));
}

TEST(QuicStreamAdapterHalfClose, NativeFinMapsToEofAfterBufferedBytes)
{
    Net::io_context Io;
    const auto Outcome = RunCoro(Io, RunNativeAdapterFinRead(Io.get_executor()));
    EXPECT_EQ(Outcome.Empty.Bytes, 0U);
    EXPECT_FALSE(Outcome.Empty.Failure.Failed());
    EXPECT_EQ(Outcome.Buffered.Bytes, 3U);
    EXPECT_FALSE(Outcome.Buffered.Failure.Failed());
    EXPECT_EQ(Outcome.FirstBuffer[0], std::byte{0x66});
    EXPECT_EQ(Outcome.FirstBuffer[1], std::byte{0x69});
    EXPECT_EQ(Outcome.FirstBuffer[2], std::byte{0x6E});
    EXPECT_EQ(Outcome.Terminal.Bytes, 0U);
    EXPECT_EQ(Outcome.Terminal.Failure.Code, Prism::Fault::Code::Eof);
    EXPECT_TRUE(Outcome.Closed);
    EXPECT_TRUE(Outcome.Retired);
}

TEST(QuicStreamAdapterHalfClose, InitialEofIsStickyAndBypassesProviderRead)
{
    Net::io_context Io;
    const auto Outcome = RunCoro(Io, RunInitialTerminalCase(
        Io.get_executor(), Prism::Fault::Failure{Prism::Fault::Code::Eof}));
    EXPECT_EQ(Outcome.EmptyRead.Bytes, 0U);
    EXPECT_FALSE(Outcome.EmptyRead.Failure.Failed());
    EXPECT_EQ(Outcome.FirstRead.Bytes, 0U);
    EXPECT_EQ(Outcome.FirstRead.Failure.Code, Prism::Fault::Code::Eof);
    EXPECT_EQ(Outcome.SecondRead.Bytes, 0U);
    EXPECT_EQ(Outcome.SecondRead.Failure.Code, Prism::Fault::Code::Eof);
    EXPECT_EQ(Outcome.ReadCalls, 0U);
    EXPECT_EQ(Outcome.Write.Bytes, 1U);
    EXPECT_FALSE(Outcome.Write.Failure.Failed());
    EXPECT_EQ(Outcome.WriteCalls, 1U);
    EXPECT_TRUE(Outcome.Shutdown);
    EXPECT_EQ(Outcome.ShutdownWriteCalls, 1U);
    EXPECT_TRUE(Outcome.Closed);
    EXPECT_TRUE(Outcome.Retired);
}

TEST(QuicStreamAdapterHalfClose, InitialNativeFailureIsStickyAndBypassesProviderRead)
{
    Net::io_context Io;
    const auto Native = std::make_error_code(std::errc::connection_reset);
    const auto Outcome = RunCoro(Io, RunInitialTerminalCase(
        Io.get_executor(), Prism::Fault::FromNative(Native)));
    EXPECT_EQ(Outcome.EmptyRead.Bytes, 0U);
    EXPECT_FALSE(Outcome.EmptyRead.Failure.Failed());
    EXPECT_EQ(Outcome.FirstRead.Bytes, 0U);
    EXPECT_EQ(Outcome.FirstRead.Failure.Code, Prism::Fault::Code::ConnectionReset);
    EXPECT_EQ(Outcome.FirstRead.Failure.Native, Native);
    EXPECT_EQ(Outcome.SecondRead.Bytes, 0U);
    EXPECT_EQ(Outcome.SecondRead.Failure.Code, Prism::Fault::Code::ConnectionReset);
    EXPECT_EQ(Outcome.SecondRead.Failure.Native, Native);
    EXPECT_EQ(Outcome.ReadCalls, 0U);
    EXPECT_EQ(Outcome.Write.Bytes, 1U);
    EXPECT_FALSE(Outcome.Write.Failure.Failed());
    EXPECT_EQ(Outcome.WriteCalls, 1U);
    EXPECT_TRUE(Outcome.Shutdown);
    EXPECT_EQ(Outcome.ShutdownWriteCalls, 1U);
    EXPECT_TRUE(Outcome.Closed);
    EXPECT_TRUE(Outcome.Retired);
}
