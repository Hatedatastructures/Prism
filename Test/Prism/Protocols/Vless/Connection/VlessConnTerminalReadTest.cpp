/**
 * @file VlessConnTerminalReadTest.cpp
 * @brief VLESS 完整请求与同次读取终态的交付顺序回归。
 */
#include <gtest/gtest.h>

#include <boost/asio/any_io_executor.hpp>
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
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Protocols/Vless/AddressCodec.hpp>
#include <Prism/Protocols/Vless/Conn.hpp>
#include <Prism/Protocols/Vless/RequestCodec.hpp>
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Fault = Prism::Fault;
    namespace Vless = Prism::Vless;

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

    using Uuid = std::array<std::uint8_t, Vless::UuidLen>;

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

    [[nodiscard]] auto TestUuid() -> Uuid
    {
        return {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    }

    [[nodiscard]] auto RequestWire(const Uuid &UuidValue) -> std::vector<std::byte>
    {
        Vless::RequestHeader Request;
        Request.Version = Vless::ProtocolVersion;
        Request.Uuid = UuidValue;
        Request.Cmd = Vless::Command::Tcp;
        Request.Target = Vless::Address{
            Vless::AddressType::Domain, "example.com", 443};
        const auto Wire = Vless::BuildRequest(Request);
        const auto Bytes = std::as_bytes(std::span(Wire));
        return {Bytes.begin(), Bytes.end()};
    }

    auto RunHandshakeTerminal(Fault::Failure Terminal,
                              const bool CompleteRequest) -> Net::awaitable<void>
    {
        const auto UuidValue = TestUuid();
        auto Wire = RequestWire(UuidValue);
        if (!CompleteRequest)
        {
            Wire.resize(Wire.size() / 2U);
        }
        else
        {
            Wire.push_back(std::byte{0xA5});
        }
        const auto InputBytes = Wire.size();
        const auto ExpectedHandshakeReads = CompleteRequest ? InputBytes - 1U : InputBytes;
        auto Raw = std::make_shared<TerminalTransmission>(
            co_await Net::this_coro::executor, std::move(Wire), Terminal);
        auto Connection = std::make_shared<Vless::Conn<>>(Raw, UuidValue);
        const auto Handshake = co_await Connection->ReadHandshake();
        EXPECT_EQ(bool(Handshake), CompleteRequest);
        EXPECT_EQ(Raw->ReadsDone(), ExpectedHandshakeReads);
        if (CompleteRequest && Handshake)
        {
            EXPECT_EQ(Handshake->Version, Vless::ProtocolVersion);
            EXPECT_EQ(Handshake->Uuid, UuidValue);
            EXPECT_EQ(Handshake->Cmd, Vless::Command::Tcp);
            EXPECT_EQ(Handshake->Target.Type, Vless::AddressType::Domain);
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
            EXPECT_EQ(Data.Failure.Code, Terminal.Code);
            EXPECT_EQ(Data.Failure.Native, Terminal.Native);
            EXPECT_EQ(Buffer[0], std::byte{0xA5});
            EXPECT_EQ(Raw->ReadsDone(), Reads + 1U);
        }
        const auto Read = co_await Connection->ReadSome(Buffer);
        EXPECT_EQ(Read.Bytes, 0U);
        EXPECT_EQ(Read.Failure.Code, Terminal.Code);
        EXPECT_EQ(Read.Failure.Native, Terminal.Native);
        EXPECT_EQ(Raw->ReadsDone(), InputBytes);
        EXPECT_TRUE(co_await CloseAndDrain(*Connection));
        EXPECT_TRUE(co_await DrainActivity(*Raw));
    }

    /** @brief 在目标地址字段中断流，并验证原终态保持粘滞且不重读。 */
    auto RunPartialAddressFieldTerminal(Fault::Failure Terminal,
                                        const std::size_t InputBytes) -> Net::awaitable<void>
    {
        auto Wire = RequestWire(TestUuid());
        EXPECT_LT(InputBytes, Wire.size());
        if (InputBytes >= Wire.size())
        {
            co_return;
        }
        Wire.resize(InputBytes);
        const auto ExpectedReads = Wire.size();
        auto Raw = std::make_shared<TerminalTransmission>(
            co_await Net::this_coro::executor, std::move(Wire), Terminal);
        auto Connection = std::make_shared<Vless::Conn<>>(Raw, TestUuid());

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
        auto Connection = std::make_shared<Vless::Conn<>>(Raw, TestUuid());
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

    TEST(VlessConnTerminalRead, CompleteRequestPrecedesReset)
    {
        RunCoroutine(RunHandshakeTerminal(ResetFailure(), true));
    }

    TEST(VlessConnTerminalRead, CompleteRequestPrecedesEof)
    {
        RunCoroutine(RunHandshakeTerminal(EofFailure(), true));
    }

    TEST(VlessConnTerminalRead, PartialRequestResetIsSticky)
    {
        RunCoroutine(RunHandshakeTerminal(ResetFailure(), false));
    }

    TEST(VlessConnTerminalRead, PartialRequestEofIsSticky)
    {
        RunCoroutine(RunHandshakeTerminal(EofFailure(), false));
    }

    TEST(VlessConnTerminalRead, TerminalBeforeDomainLengthIsSticky)
    {
        constexpr std::size_t PrefixBeforePort = 1U + Vless::UuidLen + 1U + 1U;
        constexpr std::size_t PrefixBeforeAddress = PrefixBeforePort + 2U;
        RunCoroutine(RunPartialAddressFieldTerminal(
            ResetFailure(), PrefixBeforeAddress + 1U));
    }

    TEST(VlessConnTerminalRead, PartialDomainContentEofIsSticky)
    {
        constexpr std::size_t PrefixBeforePort = 1U + Vless::UuidLen + 1U + 1U;
        constexpr std::size_t PrefixBeforeAddress = PrefixBeforePort + 2U;
        constexpr std::size_t DomainLength = sizeof("example.com") - 1U;
        RunCoroutine(RunPartialAddressFieldTerminal(
            EofFailure(), PrefixBeforeAddress + 2U + DomainLength - 1U));
    }

    TEST(VlessConnTerminalRead, PartialPortResetIsSticky)
    {
        constexpr std::size_t PrefixBeforePort = 1U + Vless::UuidLen + 1U + 1U;
        RunCoroutine(RunPartialAddressFieldTerminal(ResetFailure(), PrefixBeforePort + 1U));
    }

    TEST(VlessConnTerminalRead, CleanBoundaryEofIsStable)
    {
        RunCoroutine(RunCleanBoundaryEof());
    }
} // namespace
