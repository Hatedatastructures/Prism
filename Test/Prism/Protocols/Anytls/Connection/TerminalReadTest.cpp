/**
 * @file TerminalReadTest.cpp
 * @brief AnyTLS Conn 握手 exact-read 与同次终态顺序回归。
 */
#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/this_coro.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Anytls/Codec.hpp>
#include <Prism/Protocols/Anytls/Conn.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Fault = Prism::Fault;
    using Conn = Prism::Anytls::Conn<>;

    class ScriptedTransmission final : public Prism::Transmission
    {
    public:
        ScriptedTransmission(
            Net::any_io_executor Executor,
            std::vector<std::byte> Input,
            Fault::Failure Terminal)
            : Prism::Transmission(std::move(Executor)),
              Input_(std::move(Input)), Terminal_(std::move(Terminal))
        {
        }

        [[nodiscard]] auto ReadsDone() const noexcept -> std::size_t
        {
            return ReadsDone_;
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
            const auto Failure = Offset_ == Input_.size()
                ? Terminal_ : Fault::Failure{};
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
        std::vector<std::byte> Input_;
        Fault::Failure Terminal_;
        std::size_t Offset_{0};
        std::size_t ReadsDone_{0};
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

    [[nodiscard]] auto CancellationFailure() -> Fault::Failure
    {
        return {Fault::Code::Canceled,
                std::make_error_code(std::errc::operation_canceled)};
    }

    [[nodiscard]] auto BuildAuthBytes(const std::uint16_t PaddingLength)
        -> std::vector<std::byte>
    {
        std::string Frame;
        const auto ErrorValue = Prism::Anytls::BuildAuthFrame(
            "terminal-test", PaddingLength, Frame);
        if (ErrorValue != Prism::Error::None)
        {
            return {};
        }
        const auto Bytes = std::as_bytes(std::span(Frame.data(), Frame.size()));
        return {Bytes.begin(), Bytes.end()};
    }

    auto CloseAndDrain(Prism::Transmission &Carrier) -> Net::awaitable<bool>
    {
        const auto Closed = Carrier.Close();
        const auto Activity = Carrier.Activity();
        if (!Closed || !Activity)
        {
            co_return false;
        }
        const auto Drained = co_await Activity->Drain();
        co_return Drained.has_value();
    }

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

    auto RunCompleteHandshakeTerminal(
        const std::uint16_t PaddingLength,
        Fault::Failure Terminal) -> Net::awaitable<void>
    {
        auto Input = BuildAuthBytes(PaddingLength);
        EXPECT_FALSE(Input.empty());
        if (Input.empty())
        {
            co_return;
        }
        auto Raw = std::make_shared<ScriptedTransmission>(
            co_await Net::this_coro::executor, std::move(Input), Terminal);
        auto Connection = std::make_shared<Conn>(Raw, "terminal-test");

        const auto Handshake = co_await Connection->ReadHandshake();
        EXPECT_TRUE(Handshake);
        if (!Handshake)
        {
            EXPECT_EQ(Handshake.error().Code, Terminal.Code);
            EXPECT_EQ(Handshake.error().Native, Terminal.Native);
        }
        const auto ExpectedReads = PaddingLength == 0U ? 1U : 2U;
        EXPECT_EQ(Raw->ReadsDone(), ExpectedReads);

        std::array<std::byte, 8> Buffer{};
        for (std::size_t Attempt = 0; Attempt != 2U; ++Attempt)
        {
            const auto Read = co_await Connection->ReadSome(Buffer);
            EXPECT_EQ(Read.Bytes, 0U);
            EXPECT_EQ(Read.Failure.Code, Terminal.Code);
            EXPECT_EQ(Read.Failure.Native, Terminal.Native);
            EXPECT_EQ(Raw->ReadsDone(), ExpectedReads);
        }

        EXPECT_TRUE(co_await CloseAndDrain(*Connection));
        EXPECT_TRUE(co_await DrainActivity(*Raw));
    }

    auto RunPartialHeaderTerminal(Fault::Failure Terminal) -> Net::awaitable<void>
    {
        auto Input = BuildAuthBytes(0);
        EXPECT_GT(Input.size(), 16U);
        Input.resize(16U);
        auto Raw = std::make_shared<ScriptedTransmission>(
            co_await Net::this_coro::executor, std::move(Input), Terminal);
        auto Connection = std::make_shared<Conn>(Raw, "terminal-test");

        for (std::size_t Attempt = 0; Attempt != 2U; ++Attempt)
        {
            const auto Handshake = co_await Connection->ReadHandshake();
            EXPECT_FALSE(Handshake);
            if (!Handshake)
            {
                EXPECT_EQ(Handshake.error().Code, Terminal.Code);
                EXPECT_EQ(Handshake.error().Native, Terminal.Native);
            }
            EXPECT_EQ(Raw->ReadsDone(), 1U);
        }

        EXPECT_TRUE(co_await CloseAndDrain(*Connection));
        EXPECT_TRUE(co_await DrainActivity(*Raw));
    }

    auto RunPartialPaddingTerminal(Fault::Failure Terminal) -> Net::awaitable<void>
    {
        auto Input = BuildAuthBytes(2);
        EXPECT_GT(Input.size(), Prism::Anytls::AuthFrameHdrlen);
        Input.resize(Prism::Anytls::AuthFrameHdrlen + 1U);
        auto Raw = std::make_shared<ScriptedTransmission>(
            co_await Net::this_coro::executor, std::move(Input), Terminal);
        auto Connection = std::make_shared<Conn>(Raw, "terminal-test");

        for (std::size_t Attempt = 0; Attempt != 2U; ++Attempt)
        {
            const auto Handshake = co_await Connection->ReadHandshake();
            EXPECT_FALSE(Handshake);
            if (!Handshake)
            {
                EXPECT_EQ(Handshake.error().Code, Terminal.Code);
                EXPECT_EQ(Handshake.error().Native, Terminal.Native);
            }
            EXPECT_EQ(Raw->ReadsDone(), 2U);
        }

        EXPECT_TRUE(co_await CloseAndDrain(*Connection));
        EXPECT_TRUE(co_await DrainActivity(*Raw));
    }

    auto RunCleanBoundaryEof() -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<ScriptedTransmission>(
            co_await Net::this_coro::executor,
            std::vector<std::byte>{}, EofFailure());
        auto Connection = std::make_shared<Conn>(Raw, "terminal-test");

        for (std::size_t Attempt = 0; Attempt != 2U; ++Attempt)
        {
            const auto Handshake = co_await Connection->ReadHandshake();
            EXPECT_FALSE(Handshake);
            if (!Handshake)
            {
                EXPECT_EQ(Handshake.error().Code, Fault::Code::Eof);
            }
            EXPECT_EQ(Raw->ReadsDone(), 1U);
        }

        EXPECT_TRUE(co_await CloseAndDrain(*Connection));
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

    TEST(AnytlsConnTerminalRead, HeaderEofCompletesUnpaddedHandshake)
    {
        RunCoroutine(RunCompleteHandshakeTerminal(0, EofFailure()));
    }

    TEST(AnytlsConnTerminalRead, PaddingResetCompletesHandshakeThenStaysSticky)
    {
        RunCoroutine(RunCompleteHandshakeTerminal(1, ResetFailure()));
    }

    TEST(AnytlsConnTerminalRead, PaddingCancellationIsPreservedAfterHandshake)
    {
        RunCoroutine(RunCompleteHandshakeTerminal(2, CancellationFailure()));
    }

    TEST(AnytlsConnTerminalRead, PartialHeaderResetDoesNotReadAgain)
    {
        RunCoroutine(RunPartialHeaderTerminal(ResetFailure()));
    }

    TEST(AnytlsConnTerminalRead, PartialPaddingEofDoesNotReadAgain)
    {
        RunCoroutine(RunPartialPaddingTerminal(EofFailure()));
    }

    TEST(AnytlsConnTerminalRead, CleanBoundaryEofIsSticky)
    {
        RunCoroutine(RunCleanBoundaryEof());
    }
} // namespace
