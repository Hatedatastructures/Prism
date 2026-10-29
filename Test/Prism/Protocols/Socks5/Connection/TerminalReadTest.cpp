/**
 * @file TerminalReadTest.cpp
 * @brief SOCKS5 完整请求与同次读取终态的顺序回归。
 */
#include <gtest/gtest.h>

#include <boost/asio/any_io_executor.hpp>
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
#include <Prism/Protocols/Socks5/Conn.hpp>
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Fault = Prism::Fault;
    namespace Socks5 = Prism::Socks5;

    class TerminalTransmission final : public Prism::Transmission
    {
    public:
        TerminalTransmission(
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

    [[nodiscard]] auto RequestWire() -> std::vector<std::byte>
    {
        return {
            std::byte{0x05}, std::byte{0x01}, std::byte{0x00},
            std::byte{0x05}, std::byte{0x01}, std::byte{0x00}, std::byte{0x01},
            std::byte{0x7F}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
            std::byte{0x01}, std::byte{0xBB}};
    }

    auto RunHandshakeTerminal(Fault::Failure Terminal, const bool CompleteRequest)
        -> Net::awaitable<void>
    {
        auto Wire = RequestWire();
        if (!CompleteRequest)
        {
            Wire.resize(8U);
        }
        const auto ExpectedReads = 1U;
        auto Raw = std::make_shared<TerminalTransmission>(
            co_await Net::this_coro::executor, std::move(Wire), Terminal);
        auto Connection = std::make_shared<Socks5::Conn<>>(Raw);
        Socks5::ServerConfig Config;
        Config.EnableAuth = false;

        const auto Handshake = co_await Connection->ReadHandshake(Config);
        EXPECT_EQ(static_cast<bool>(Handshake), CompleteRequest);
        EXPECT_EQ(Raw->ReadsDone(), ExpectedReads);
        if (CompleteRequest && Handshake)
        {
            EXPECT_EQ(Handshake->Cmd, Socks5::Command::Connect);
            EXPECT_EQ(Handshake->Target.Type, Socks5::AddressType::Ipv4);
            EXPECT_EQ(Handshake->Target.Host, "127.0.0.1");
            EXPECT_EQ(Handshake->Target.Port, 443U);
        }
        else if (!Handshake)
        {
            EXPECT_EQ(Handshake.error().Code, Terminal.Code);
            EXPECT_EQ(Handshake.error().Native, Terminal.Native);
        }

        const auto Reads = Raw->ReadsDone();
        std::array<std::byte, 8> Buffer{};
        for (std::size_t Attempt = 0; Attempt < 2U; ++Attempt)
        {
            const auto Read = co_await Connection->ReadSome(Buffer);
            EXPECT_EQ(Read.Bytes, 0U);
            EXPECT_EQ(Read.Failure.Code, Terminal.Code);
            EXPECT_EQ(Read.Failure.Native, Terminal.Native);
            EXPECT_EQ(Raw->ReadsDone(), Reads);
        }
        EXPECT_TRUE(co_await CloseAndDrain(*Connection));
        EXPECT_TRUE(co_await DrainActivity(*Raw));
    }

    auto RunCleanBoundaryEof() -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<TerminalTransmission>(
            co_await Net::this_coro::executor, std::vector<std::byte>{}, EofFailure());
        auto Connection = std::make_shared<Socks5::Conn<>>(Raw);
        Socks5::ServerConfig Config;
        Config.EnableAuth = false;

        const auto Handshake = co_await Connection->ReadHandshake(Config);
        EXPECT_FALSE(Handshake);
        if (!Handshake)
        {
            EXPECT_EQ(Handshake.error().Code, Fault::Code::Eof);
        }
        EXPECT_EQ(Raw->ReadsDone(), 1U);
        const auto Reads = Raw->ReadsDone();
        std::array<std::byte, 8> Buffer{};
        const auto Read = co_await Connection->ReadSome(Buffer);
        EXPECT_EQ(Read.Failure.Code, Fault::Code::Eof);
        EXPECT_EQ(Raw->ReadsDone(), Reads);
        EXPECT_TRUE(co_await CloseAndDrain(*Connection));
        EXPECT_TRUE(co_await DrainActivity(*Raw));
    }

    /** @brief 握手前零字节 native reset 后重复读取应返回原错误且不重读。 */
    auto RunZeroByteNativeReset() -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<TerminalTransmission>(
            co_await Net::this_coro::executor, std::vector<std::byte>{}, ResetFailure());
        auto Connection = std::make_shared<Socks5::Conn<>>(Raw);
        Socks5::ServerConfig Config;
        Config.EnableAuth = false;

        const auto Handshake = co_await Connection->ReadHandshake(Config);
        EXPECT_FALSE(Handshake);
        if (!Handshake)
        {
            EXPECT_EQ(Handshake.error().Code, Fault::Code::ConnectionReset);
            EXPECT_EQ(Handshake.error().Native, ResetFailure().Native);
        }
        EXPECT_EQ(Raw->ReadsDone(), 1U);

        std::array<std::byte, 8> Buffer{};
        for (std::size_t Attempt = 0; Attempt != 2U; ++Attempt)
        {
            const auto Read = co_await Connection->ReadSome(Buffer);
            EXPECT_EQ(Read.Bytes, 0U);
            EXPECT_EQ(Read.Failure.Code, Fault::Code::ConnectionReset);
            EXPECT_EQ(Read.Failure.Native, ResetFailure().Native);
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

    TEST(Socks5ConnTerminalRead, CompleteRequestPrecedesReset)
    {
        RunCoroutine(RunHandshakeTerminal(ResetFailure(), true));
    }

    TEST(Socks5ConnTerminalRead, CompleteRequestPrecedesEof)
    {
        RunCoroutine(RunHandshakeTerminal(EofFailure(), true));
    }

    TEST(Socks5ConnTerminalRead, PartialAddressResetIsSticky)
    {
        RunCoroutine(RunHandshakeTerminal(ResetFailure(), false));
    }

    TEST(Socks5ConnTerminalRead, PartialAddressEofIsSticky)
    {
        RunCoroutine(RunHandshakeTerminal(EofFailure(), false));
    }

    TEST(Socks5ConnTerminalRead, ZeroByteNativeResetIsSticky)
    {
        RunCoroutine(RunZeroByteNativeReset());
    }

    TEST(Socks5ConnTerminalRead, CleanBoundaryEofIsStable)
    {
        RunCoroutine(RunCleanBoundaryEof());
    }
} // namespace
