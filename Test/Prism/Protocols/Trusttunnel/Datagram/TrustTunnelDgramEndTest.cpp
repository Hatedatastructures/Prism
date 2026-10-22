/**
 * @file TrustTunnelDgramEndTest.cpp
 * @brief Trusttunnel datagram 字段与同读终态的顺序回归。
 * @details 固定字段按长度判断完整性；payload 没有长度字段，一次正字节 ReadSome
 *          即构成完整 datagram。完成 datagram 与终态同读时先交付 datagram，随后保持终态。
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
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Trusttunnel/TransportTypes.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Fault = Prism::Fault;
    namespace Trusttunnel = Prism::Trusttunnel;

    class ScriptedDatagramTransmission final : public Prism::Transmission
    {
    public:
        ScriptedDatagramTransmission(
            ExecutorType Executor,
            std::vector<std::byte> Input,
            Fault::Failure Terminal)
            : Transmission(Executor), Executor_(std::move(Executor)),
              Input_(std::move(Input)), Terminal_(std::move(Terminal))
        {
        }

        [[nodiscard]] auto ReadCount() const noexcept -> std::size_t
        {
            return ReadCount_;
        }

        [[nodiscard]] auto CloseCount() const noexcept -> std::size_t
        {
            return CloseCount_;
        }

        [[nodiscard]] auto WriteShutdownCount() const noexcept -> std::size_t
        {
            return WriteShutdownCount_;
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Executor_;
        }

    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadCount_;
            const auto Count = (std::min)(Buffer.size(), Input_.size() - Offset_);
            if (Count != 0U)
            {
                std::memcpy(Buffer.data(), Input_.data() + Offset_, Count);
                Offset_ += Count;
            }
            auto Failure = Fault::Failure{};
            if (Offset_ == Input_.size() && !TerminalDelivered_)
            {
                Failure = Terminal_;
                TerminalDelivered_ = true;
            }
            else if (TerminalDelivered_)
            {
                Failure = {Fault::Code::WouldBlock};
            }
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), {Count, Failure});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), {Buffer.size(), {}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            ++WriteShutdownCount_;
            Prism::Transmission::PostResult(Executor_, std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            ++CloseCount_;
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        ExecutorType Executor_;
        std::vector<std::byte> Input_;
        Fault::Failure Terminal_;
        std::size_t Offset_{0};
        std::size_t ReadCount_{0};
        std::size_t CloseCount_{0};
        std::size_t WriteShutdownCount_{0};
        bool TerminalDelivered_{false};
    };

    struct DatagramTerminalOutcome final
    {
        bool FirstSucceeded{false};
        Fault::Failure FirstFailure{};
        std::string Host;
        std::uint16_t Port{0};
        std::vector<std::uint8_t> Payload;
        std::array<bool, 2> RetrySucceeded{};
        std::array<Fault::Failure, 2> RetryFailure{};
        std::size_t ReadsAfterFirst{0};
        std::size_t ReadsAfterRetries{0};
        std::size_t RawCloseCount{0};
        bool DatagramDrainSucceeded{false};
        bool RawDrainSucceeded{false};
    };

    struct DatagramTerminalRequest final
    {
        std::vector<std::byte> Wire;
        Fault::Failure Terminal;
        DatagramTerminalOutcome *Outcome{nullptr};
    };

    struct DatagramTerminalExpectation final
    {
        bool FirstSucceeded{false};
        Fault::Failure Terminal;
        std::string Host;
        std::uint16_t Port{0};
        std::vector<std::uint8_t> Payload;
        std::size_t RawReads{0};
    };

    struct DatagramHalfCloseOutcome final
    {
        bool ShutdownSucceeded{false};
        Fault::Failure ShutdownFailure{};
        bool ReceiveSucceeded{false};
        Fault::Failure ReceiveFailure{};
        std::string Host;
        std::uint16_t Port{0};
        std::vector<std::uint8_t> Payload;
        Fault::Failure RetryFailure{};
        std::size_t ReadsAfterReceive{0};
        std::size_t ReadsAfterRetry{0};
        std::size_t WriteShutdownCount{0};
        std::size_t CloseCountBeforeClose{0};
        std::size_t CloseCountAfterClose{0};
        bool CloseSucceeded{false};
        bool DatagramDrainSucceeded{false};
        bool RawDrainSucceeded{false};
    };

    [[nodiscard]] auto MakeCompleteDatagramWire() -> std::vector<std::byte>
    {
        constexpr std::string_view Host = "dns.google";
        constexpr std::string_view Payload = "dns-query";
        std::vector<std::byte> Wire;
        Wire.reserve(1U + Host.size() + 2U + Payload.size());
        Wire.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(Host.size())));
        for (const auto Character : Host)
        {
            Wire.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(Character)));
        }
        Wire.push_back(std::byte{0});
        Wire.push_back(std::byte{53});
        for (const auto Character : Payload)
        {
            Wire.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(Character)));
        }
        return Wire;
    }

    [[nodiscard]] auto MakeAddressOnlyWire() -> std::vector<std::byte>
    {
        auto Wire = MakeCompleteDatagramWire();
        Wire.resize(1U + std::string_view{"dns.google"}.size() + 2U);
        return Wire;
    }

    [[nodiscard]] auto ToU8(std::string_view Text) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Bytes;
        Bytes.reserve(Text.size());
        for (const auto Character : Text)
        {
            Bytes.push_back(static_cast<std::uint8_t>(Character));
        }
        return Bytes;
    }

    auto RunDatagramTerminal(DatagramTerminalRequest Request) -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<ScriptedDatagramTransmission>(
            co_await Net::this_coro::executor, std::move(Request.Wire),
            std::move(Request.Terminal));
        auto Created = Trusttunnel::Dgram::Create(
            Trusttunnel::DgramRequest{Raw});
        EXPECT_TRUE(Created);
        if (!Created)
        {
            Request.Outcome->FirstFailure = Created.error();
            co_return;
        }
        auto Datagram = std::move(*Created);
        auto &Outcome = *Request.Outcome;
        const auto First = co_await Datagram->AsyncReceiveFrom(
            Outcome.Host, Outcome.Port, Outcome.Payload);
        Outcome.FirstSucceeded = static_cast<bool>(First);
        if (!First)
        {
            Outcome.FirstFailure = First.error();
        }
        Outcome.ReadsAfterFirst = Raw->ReadCount();

        for (std::size_t Index = 0; Index < Outcome.RetryFailure.size(); ++Index)
        {
            std::string Host;
            std::uint16_t Port = 0;
            std::vector<std::uint8_t> Payload;
            const auto Retry = co_await Datagram->AsyncReceiveFrom(Host, Port, Payload);
            Outcome.RetrySucceeded[Index] = static_cast<bool>(Retry);
            if (!Retry)
            {
                Outcome.RetryFailure[Index] = Retry.error();
            }
        }
        Outcome.ReadsAfterRetries = Raw->ReadCount();
        const auto Closed = Datagram->Close();
        const auto DatagramActivity = Datagram->Activity();
        bool DatagramDrainSucceeded = false;
        if (DatagramActivity)
        {
            const auto Drained = co_await DatagramActivity->Drain();
            DatagramDrainSucceeded = static_cast<bool>(Drained);
        }
        Outcome.DatagramDrainSucceeded = Closed.has_value() && DatagramDrainSucceeded;
        Outcome.RawCloseCount = Raw->CloseCount();
        const auto RawActivity = Raw->Activity();
        if (RawActivity)
        {
            const auto RawDrain = co_await RawActivity->Drain();
            Outcome.RawDrainSucceeded = static_cast<bool>(RawDrain);
        }
    }

    auto RunDatagramHalfClose(DatagramHalfCloseOutcome &Outcome) -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<ScriptedDatagramTransmission>(
            co_await Net::this_coro::executor, MakeCompleteDatagramWire(),
            Fault::Failure{Fault::Code::Eof});
        auto Created = Trusttunnel::Dgram::Create(Trusttunnel::DgramRequest{Raw});
        EXPECT_TRUE(Created);
        if (!Created) co_return;
        auto Datagram = std::move(*Created);

        const auto Shutdown = co_await Datagram->WriteShutdown();
        Outcome.ShutdownSucceeded = static_cast<bool>(Shutdown);
        if (!Shutdown) Outcome.ShutdownFailure = Shutdown.error();
        Outcome.WriteShutdownCount = Raw->WriteShutdownCount();

        const auto Received = co_await Datagram->AsyncReceiveFrom(
            Outcome.Host, Outcome.Port, Outcome.Payload);
        Outcome.ReceiveSucceeded = static_cast<bool>(Received);
        if (!Received) Outcome.ReceiveFailure = Received.error();
        Outcome.ReadsAfterReceive = Raw->ReadCount();

        std::string RetryHost;
        std::uint16_t RetryPort = 0;
        std::vector<std::uint8_t> RetryPayload;
        const auto Retry = co_await Datagram->AsyncReceiveFrom(
            RetryHost, RetryPort, RetryPayload);
        if (!Retry) Outcome.RetryFailure = Retry.error();
        Outcome.ReadsAfterRetry = Raw->ReadCount();
        Outcome.CloseCountBeforeClose = Raw->CloseCount();

        const auto Closed = Datagram->Close();
        Outcome.CloseSucceeded = Closed.has_value();
        const auto DatagramActivity = Datagram->Activity();
        if (DatagramActivity)
        {
            const auto Drained = co_await DatagramActivity->Drain();
            Outcome.DatagramDrainSucceeded = static_cast<bool>(Drained);
        }
        Outcome.CloseCountAfterClose = Raw->CloseCount();
        const auto RawActivity = Raw->Activity();
        if (RawActivity)
        {
            const auto Drained = co_await RawActivity->Drain();
            Outcome.RawDrainSucceeded = static_cast<bool>(Drained);
        }
    }

    auto RunCoroutine(Net::awaitable<void> Operation) -> void
    {
        Net::io_context Io;
        std::exception_ptr Failure;
        Net::co_spawn(Io, std::move(Operation),
            [&Failure](std::exception_ptr ErrorValue) { Failure = std::move(ErrorValue); });
        Io.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    auto ExpectDatagramTerminal(
        const DatagramTerminalOutcome &Outcome,
        const DatagramTerminalExpectation &Expected) -> void
    {
        EXPECT_EQ(Outcome.FirstSucceeded, Expected.FirstSucceeded);
        if (Expected.FirstSucceeded)
        {
            EXPECT_EQ(Outcome.Host, Expected.Host);
            EXPECT_EQ(Outcome.Port, Expected.Port);
            EXPECT_EQ(Outcome.Payload, Expected.Payload);
            EXPECT_TRUE(Outcome.FirstFailure.Succeeded());
        }
        else
        {
            EXPECT_EQ(Outcome.FirstFailure.Code, Expected.Terminal.Code);
            EXPECT_EQ(Outcome.FirstFailure.Native, Expected.Terminal.Native);
            EXPECT_EQ(Outcome.Host, Expected.Host);
            EXPECT_EQ(Outcome.Port, Expected.Port);
            EXPECT_EQ(Outcome.Payload, Expected.Payload);
        }
        for (std::size_t Index = 0; Index < Outcome.RetryFailure.size(); ++Index)
        {
            EXPECT_FALSE(Outcome.RetrySucceeded[Index]);
            EXPECT_EQ(Outcome.RetryFailure[Index].Code, Expected.Terminal.Code);
            EXPECT_EQ(Outcome.RetryFailure[Index].Native, Expected.Terminal.Native);
        }
        EXPECT_EQ(Outcome.ReadsAfterFirst, Expected.RawReads);
        EXPECT_EQ(Outcome.ReadsAfterRetries, Expected.RawReads);
        EXPECT_EQ(Outcome.RawCloseCount, 1U);
        EXPECT_TRUE(Outcome.DatagramDrainSucceeded);
        EXPECT_TRUE(Outcome.RawDrainSucceeded);
    }

    TEST(TrusttunnelDgramTerminalRead, CompletePayloadPrecedesEof)
    {
        const Fault::Failure Eof{Fault::Code::Eof};
        DatagramTerminalOutcome Outcome;
        RunCoroutine(RunDatagramTerminal({MakeCompleteDatagramWire(), Eof, &Outcome}));
        ExpectDatagramTerminal(Outcome, {true, Eof, "dns.google", 53U, ToU8("dns-query"), 4U});
    }

    TEST(TrusttunnelDgramTerminalRead, CompletePayloadPrecedesNativeReset)
    {
        const Fault::Failure Reset{Fault::Code::ConnectionReset,
                                   std::make_error_code(std::errc::connection_reset)};
        DatagramTerminalOutcome Outcome;
        RunCoroutine(RunDatagramTerminal({MakeCompleteDatagramWire(), Reset, &Outcome}));
        ExpectDatagramTerminal(Outcome, {true, Reset, "dns.google", 53U, ToU8("dns-query"), 4U});
    }

    TEST(TrusttunnelDgramTerminalRead, PartialHostFieldEofIsSticky)
    {
        const Fault::Failure Eof{Fault::Code::Eof};
        DatagramTerminalOutcome Outcome;
        RunCoroutine(RunDatagramTerminal({
            {std::byte{3}, std::byte{0x64}}, Eof, &Outcome}));
        ExpectDatagramTerminal(Outcome, {false, Eof, {}, 0U, {}, 2U});
    }

    TEST(TrusttunnelDgramTerminalRead, PartialHostFieldNativeResetIsSticky)
    {
        const Fault::Failure Reset{Fault::Code::ConnectionReset,
                                   std::make_error_code(std::errc::connection_reset)};
        DatagramTerminalOutcome Outcome;
        RunCoroutine(RunDatagramTerminal({
            {std::byte{3}, std::byte{0x64}}, Reset, &Outcome}));
        ExpectDatagramTerminal(Outcome, {false, Reset, {}, 0U, {}, 2U});
    }

    TEST(TrusttunnelDgramTerminalRead, CompleteHostLengthKeepsEofSticky)
    {
        const Fault::Failure Eof{Fault::Code::Eof};
        DatagramTerminalOutcome Outcome;
        RunCoroutine(RunDatagramTerminal({{std::byte{0}}, Eof, &Outcome}));
        ExpectDatagramTerminal(Outcome, {false, Eof, {}, 0U, {}, 1U});
    }

    TEST(TrusttunnelDgramTerminalRead, CompletePortFieldKeepsEofSticky)
    {
        const Fault::Failure Eof{Fault::Code::Eof};
        DatagramTerminalOutcome Outcome;
        RunCoroutine(RunDatagramTerminal({MakeAddressOnlyWire(), Eof, &Outcome}));
        ExpectDatagramTerminal(Outcome, {false, Eof, "dns.google", 53U, {}, 3U});
    }

    TEST(TrusttunnelDgramHalfClose, WriteShutdownLeavesReadDirectionOpen)
    {
        DatagramHalfCloseOutcome Outcome;
        RunCoroutine(RunDatagramHalfClose(Outcome));

        EXPECT_TRUE(Outcome.ShutdownSucceeded);
        EXPECT_TRUE(Outcome.ShutdownFailure.Succeeded());
        EXPECT_EQ(Outcome.WriteShutdownCount, 1U);
        EXPECT_TRUE(Outcome.ReceiveSucceeded);
        EXPECT_EQ(Outcome.Host, "dns.google");
        EXPECT_EQ(Outcome.Port, 53U);
        EXPECT_EQ(Outcome.Payload, ToU8("dns-query"));
        EXPECT_EQ(Outcome.ReadsAfterReceive, 4U);
        EXPECT_EQ(Outcome.RetryFailure.Code, Fault::Code::Eof);
        EXPECT_EQ(Outcome.ReadsAfterRetry, 4U);
        EXPECT_EQ(Outcome.CloseCountBeforeClose, 0U);
        EXPECT_TRUE(Outcome.CloseSucceeded);
        EXPECT_EQ(Outcome.CloseCountAfterClose, 1U);
        EXPECT_TRUE(Outcome.DatagramDrainSucceeded);
        EXPECT_TRUE(Outcome.RawDrainSucceeded);
    }
} // namespace
