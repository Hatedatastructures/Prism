/**
 * @file TrojanConnTerminalReadTest.cpp
 * @brief Trojan 完整请求与同次读取终态的交付顺序回归。
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
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Protocols/Trojan/AddressCodec.hpp>
#include <Prism/Protocols/Trojan/Conn.hpp>
#include <Prism/Protocols/Trojan/CredentialCodec.hpp>
#include <Prism/Protocols/Trojan/RequestCodec.hpp>
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Fault = Prism::Fault;
    namespace Trojan = Prism::Trojan;

    class TerminalTransmission final : public Prism::Transmission
    {
    public:
        TerminalTransmission(Net::any_io_executor Executor,
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

    auto CloseAndDrain(Prism::Transmission &Carrier) -> Net::awaitable<bool>
    {
        const auto Closed = Carrier.Close();
        if (!Closed)
        {
            co_return false;
        }
        co_return co_await DrainActivity(Carrier);
    }

    [[nodiscard]] auto RequestWire() -> std::vector<std::byte>
    {
        const auto Request = Trojan::BuildRequest(
            Trojan::Credential("terminal-test"), Trojan::Command::Connect,
            Trojan::Address{Trojan::AddressType::Domain, "example.com", 443});
        const auto Bytes = std::as_bytes(std::span(Request));
        return {Bytes.begin(), Bytes.end()};
    }

    auto RunHandshakeTerminal(Fault::Failure Terminal,
                              const bool CompleteRequest) -> Net::awaitable<void>
    {
        auto Wire = RequestWire();
        if (!CompleteRequest)
        {
            Wire.resize(Wire.size() / 2U);
        }
        else
        {
            Wire.push_back(std::byte{0xA5});
        }
        const auto InputBytes = Wire.size();
        const auto ExpectedHandshakeReads = 1U;
        auto Raw = std::make_shared<TerminalTransmission>(
            co_await Net::this_coro::executor, std::move(Wire), Terminal);
        auto Connection = std::make_shared<Trojan::Conn<>>(Raw, "terminal-test");
        const auto Handshake = co_await Connection->ReadHandshake();
        EXPECT_EQ(bool(Handshake), CompleteRequest);
        EXPECT_EQ(Raw->ReadsDone(), ExpectedHandshakeReads);
        if (CompleteRequest && Handshake)
        {
            EXPECT_EQ(Handshake->Cmd, Trojan::Command::Connect);
            EXPECT_EQ(Handshake->Target.Type, Trojan::AddressType::Domain);
            EXPECT_EQ(Handshake->Target.Host, "example.com");
            EXPECT_EQ(Handshake->Target.Port, 443U);
        }
        if (!CompleteRequest && !Handshake)
        {
            EXPECT_EQ(Handshake.error().Code, Terminal.Code);
            EXPECT_EQ(Handshake.error().Native, Terminal.Native);
        }
        std::array<std::byte, 8> Buffer{};
        const auto Reads = Raw->ReadsDone();
        if (CompleteRequest)
        {
            const auto Data = co_await Connection->ReadSome(Buffer);
            EXPECT_EQ(Data.Bytes, 1U);
            EXPECT_FALSE(Data.Failure.Failed());
            EXPECT_EQ(Buffer[0], std::byte{0xA5});
            EXPECT_EQ(Raw->ReadsDone(), Reads);
        }
        const auto Read = co_await Connection->ReadSome(Buffer);
        EXPECT_EQ(Read.Bytes, 0U);
        EXPECT_EQ(Read.Failure.Code, Terminal.Code);
        EXPECT_EQ(Read.Failure.Native, Terminal.Native);
        EXPECT_EQ(Raw->ReadsDone(), ExpectedHandshakeReads);
        EXPECT_TRUE(co_await CloseAndDrain(*Connection));
        EXPECT_TRUE(co_await DrainActivity(*Raw));
    }

    /** @brief 在目标地址字段中断流，并验证原终态保持粘滞且不重读。 */
    auto RunPartialAddressFieldTerminal(Fault::Failure Terminal,
                                        const std::size_t InputBytes) -> Net::awaitable<void>
    {
        auto Wire = RequestWire();
        EXPECT_LT(InputBytes, Wire.size());
        if (InputBytes >= Wire.size())
        {
            co_return;
        }
        Wire.resize(InputBytes);
        const auto ExpectedReads = 1U;
        auto Raw = std::make_shared<TerminalTransmission>(
            co_await Net::this_coro::executor, std::move(Wire), Terminal);
        auto Connection = std::make_shared<Trojan::Conn<>>(Raw, "terminal-test");

        const auto Handshake = co_await Connection->ReadHandshake();
        EXPECT_FALSE(Handshake);
        if (!Handshake)
        {
            EXPECT_EQ(Handshake.error().Code, Terminal.Code);
            EXPECT_EQ(Handshake.error().Native, Terminal.Native);
        }
        EXPECT_EQ(Raw->ReadsDone(), ExpectedReads);

        const auto Reads = Raw->ReadsDone();
        std::array<std::byte, 8> Buffer{};
        for (std::size_t Attempt = 0; Attempt != 2U; ++Attempt)
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
        auto Connection = std::make_shared<Trojan::Conn<>>(Raw, "terminal-test");
        const auto Handshake = co_await Connection->ReadHandshake();
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

    TEST(TrojanConnTerminalRead, CompleteRequestPrecedesReset)
    {
        RunCoroutine(RunHandshakeTerminal(ResetFailure(), true));
    }

    TEST(TrojanConnTerminalRead, CompleteRequestPrecedesEof)
    {
        RunCoroutine(RunHandshakeTerminal(EofFailure(), true));
    }

    TEST(TrojanConnTerminalRead, PartialRequestResetIsSticky)
    {
        RunCoroutine(RunHandshakeTerminal(ResetFailure(), false));
    }

    TEST(TrojanConnTerminalRead, PartialRequestEofIsSticky)
    {
        RunCoroutine(RunHandshakeTerminal(EofFailure(), false));
    }

    TEST(TrojanConnTerminalRead, TerminalBeforeDomainLengthIsSticky)
    {
        constexpr std::size_t PrefixBeforeAddress = Trojan::CredentialLen + 2U + 1U;
        RunCoroutine(RunPartialAddressFieldTerminal(
            EofFailure(), PrefixBeforeAddress + 1U));
    }

    TEST(TrojanConnTerminalRead, PartialDomainContentResetIsSticky)
    {
        constexpr std::size_t PrefixBeforeAddress = Trojan::CredentialLen + 2U + 1U;
        constexpr std::size_t DomainLength = sizeof("example.com") - 1U;
        RunCoroutine(RunPartialAddressFieldTerminal(
            ResetFailure(), PrefixBeforeAddress + 2U + DomainLength - 1U));
    }

    TEST(TrojanConnTerminalRead, PartialPortResetIsSticky)
    {
        constexpr std::size_t PrefixBeforeAddress = Trojan::CredentialLen + 2U + 1U;
        constexpr std::size_t DomainLength = sizeof("example.com") - 1U;
        RunCoroutine(RunPartialAddressFieldTerminal(
            ResetFailure(), PrefixBeforeAddress + 2U + DomainLength + 1U));
    }

    TEST(TrojanConnTerminalRead, CleanBoundaryEofIsStable)
    {
        RunCoroutine(RunCleanBoundaryEof());
    }
} // namespace
