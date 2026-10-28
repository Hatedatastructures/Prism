/**
 * @file EndTest.cpp
 * @brief Trojan 公共数据报会话的终态边界回归。
 */

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Net/HostText.hpp>
#include <Prism/Protocols/Trojan/Dgram.hpp>
#include <Prism/Protocols/Trojan/Datagram/Session.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Trojan = Prism::Trojan;
    using Udp = Net::ip::udp;

    /** @brief 在指定 executor 上异步交付脚本化载体结果。 */
    class ScriptedCarrier final : public Prism::Transmission
    {
    public:
        ScriptedCarrier(Net::any_io_executor Executor, std::vector<std::uint8_t> Wire,
            Prism::Fault::Failure Terminal = {Prism::Fault::Code::Eof})
            : Prism::Transmission(std::move(Executor)), Wire_(std::move(Wire)),
              Terminal_(Terminal)
        {
        }

        [[nodiscard]] auto ReadCalls() const noexcept -> std::size_t
        {
            return ReadCalls_;
        }

        [[nodiscard]] auto IsClosed() const noexcept -> bool
        {
            return Closed_;
        }

        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Type::Tcp;
        }

    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadCalls_;
            const auto Available = Wire_.size() - Offset_;
            const auto Count = (std::min)(Buffer.size(), Available);
            if (Count != 0U)
            {
                std::memcpy(Buffer.data(), Wire_.data() + Offset_, Count);
                Offset_ += Count;
            }
            const auto Failure = Offset_ == Wire_.size()
                ? Terminal_ : Prism::Fault::Failure{};
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), Prism::IoResult{Count, Failure});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), Prism::IoResult{Buffer.size(), {}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), Prism::IoResult{0, {}});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Closed_ = true;
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        std::vector<std::uint8_t> Wire_;
        std::size_t Offset_{0};
        std::size_t ReadCalls_{0};
        Prism::Fault::Failure Terminal_{Prism::Fault::Code::Eof};
        bool Closed_{false};
    };

    struct CompletePacketTerminalScenario final
    {
        Prism::Fault::Failure CarrierTerminal;
        Prism::Fault::Failure SessionResult;
    };

    /** @brief 构造 Trojan IPv4 数据报帧。 */
    auto MakeFrame(std::span<const std::uint8_t> Payload) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Wire{
            0x01, 127, 0, 0, 1, 0, 53,
            static_cast<std::uint8_t>(Payload.size() >> 8),
            static_cast<std::uint8_t>(Payload.size()), '\r', '\n'};
        Wire.insert(Wire.end(), Payload.begin(), Payload.end());
        return Wire;
    }

    /** @brief 构造声明四字节载荷、实际仅带两字节并同读 EOF 的帧。 */
    auto MakePartialPayloadFrame() -> std::vector<std::uint8_t>
    {
        return {0x01, 127, 0, 0, 1, 0, 53, 0, 4, '\r', '\n', 0x41, 0x42};
    }

    /** @brief 构造数据报测试使用的原生连接重置。 */
    [[nodiscard]] auto ResetFailure() -> Prism::Fault::Failure
    {
        return {Prism::Fault::Code::ConnectionReset,
            std::make_error_code(std::errc::connection_reset)};
    }

    /** @brief 接收一次 UDP egress；超时分支让缺包回归有界失败。 */
    auto ReceiveOne(Udp::socket& Socket, std::vector<std::uint8_t>& Payload)
        -> Net::awaitable<bool>
    {
        std::array<std::uint8_t, 64> Buffer{};
        Udp::endpoint Sender;
        const auto Count = co_await Socket.async_receive_from(
            Net::buffer(Buffer), Sender, Net::use_awaitable);
        Payload.assign(Buffer.begin(), Buffer.begin() + static_cast<std::ptrdiff_t>(Count));
        co_return true;
    }

    /** @brief 仅用于封闭 egress 接收等待，不修改会话的处理期限。 */
    auto WaitForTimeout(Net::steady_timer& Timer) -> Net::awaitable<bool>
    {
        co_await Timer.async_wait(Net::use_awaitable);
        co_return false;
    }

    /** @brief 在接收或固定 deadline 先完成时返回对应分支。 */
    auto ReceiveOneBeforeDeadline(
        Udp::socket& Socket,
        Net::steady_timer& Timer,
        std::vector<std::uint8_t>& Payload) -> Net::awaitable<bool>
    {
        using Net::experimental::awaitable_operators::operator||;
        const auto Outcome = co_await (
            ReceiveOne(Socket, Payload) || WaitForTimeout(Timer));
        co_return Outcome.index() == 0U && std::get<0>(Outcome);
    }

    /** @brief 完整 packet 先进入真实 UDP egress，随后保留载体终态。 */
    auto RunCompletePacketBeforeTerminal(
        Net::io_context& IoContext,
        CompletePacketTerminalScenario Scenario) -> Net::awaitable<void>
    {
        const std::array<std::uint8_t, 4> ExpectedPayload{0x41, 0x00, 0xFE, 0x7F};
        auto Carrier = std::make_shared<ScriptedCarrier>(
            IoContext.get_executor(), MakeFrame(ExpectedPayload), Scenario.CarrierTerminal);
        Udp::socket Sink(IoContext,
            Udp::endpoint(Net::ip::address_v4::loopback(), 0));
        const auto SinkEndpoint = Sink.local_endpoint();
        Net::steady_timer ReceiveDeadline(IoContext);
        ReceiveDeadline.expires_after(std::chrono::milliseconds(250));

        std::size_t ResolveCalls = 0;
        std::string ResolvedHost;
        std::uint16_t ResolvedPort = 0;
        Trojan::DatagramSession::Options Options;
        Options.Services.IdleTimeout = std::chrono::milliseconds(100);
        Options.Services.Resolve = [&ResolveCalls, &ResolvedHost, &ResolvedPort, SinkEndpoint](
            Prism::Network::Target Target)
            -> Net::awaitable<std::expected<Udp::endpoint, Prism::Fault::Failure>>
        {
            ++ResolveCalls;
            const auto TargetText = Prism::Network::ToText(Target.Host);
            ResolvedHost = std::string(TargetText.View());
            ResolvedPort = Target.Port;
            co_return SinkEndpoint;
        };

        auto Datagram = std::make_shared<Trojan::Dgram<>>(Carrier);
        auto Created = Trojan::DatagramSession::Create(Datagram, std::move(Options));
        EXPECT_TRUE(Created.has_value());
        if (!Created)
        {
            co_return;
        }
        auto Session = std::move(*Created);
        std::vector<std::uint8_t> ReceivedPayload;
        using Net::experimental::awaitable_operators::operator&&;
        const auto [RunResult, Received] = co_await (
            Session->Run() &&
            ReceiveOneBeforeDeadline(Sink, ReceiveDeadline, ReceivedPayload));

        EXPECT_EQ(RunResult.has_value(), !Scenario.SessionResult.Failed());
        if (Scenario.SessionResult.Failed() && !RunResult)
        {
            EXPECT_EQ(RunResult.error().Code, Scenario.SessionResult.Code);
            EXPECT_EQ(RunResult.error().Native, Scenario.SessionResult.Native);
        }
        EXPECT_TRUE(Received);
        EXPECT_EQ(ResolveCalls, 1U);
        EXPECT_EQ(ResolvedHost, "127.0.0.1");
        EXPECT_EQ(ResolvedPort, 53U);
        EXPECT_TRUE(std::equal(
            ReceivedPayload.begin(), ReceivedPayload.end(),
            ExpectedPayload.begin(), ExpectedPayload.end()));
        EXPECT_EQ(ReceivedPayload.size(), ExpectedPayload.size());
        EXPECT_EQ(Carrier->ReadCalls(), 5U);

        Session->Close();
        const auto SessionDrain = co_await Session->Activity()->Drain();
        EXPECT_TRUE(SessionDrain.has_value());
        EXPECT_TRUE(Session->Activity()->IsRetired());
        EXPECT_TRUE(Carrier->IsClosed());
        const auto CarrierDrain = co_await Carrier->Activity()->Drain();
        EXPECT_TRUE(CarrierDrain.has_value());
        EXPECT_TRUE(Carrier->Activity()->IsRetired());
    }

    /** @brief partial 载荷不交付 packet，且下一次读取保持原终态。 */
    auto RunPartialPayloadTerminalIsSticky(
        Net::io_context& IoContext,
        Prism::Fault::Failure Terminal) -> Net::awaitable<void>
    {
        auto Carrier = std::make_shared<ScriptedCarrier>(
            IoContext.get_executor(), MakePartialPayloadFrame(), Terminal);
        auto Datagram = std::make_shared<Trojan::Dgram<>>(Carrier);
        Trojan::Address Source;
        std::vector<std::uint8_t> Payload;
        const auto ExpectedFailure = Terminal.Code == Prism::Fault::Code::Eof
            ? Prism::Fault::Failure{Prism::Fault::Code::BadMessage}
            : Terminal;

        const auto First = co_await Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(First.PayloadBytes, 0U);
        EXPECT_EQ(First.WireBytes, 13U);
        EXPECT_EQ(First.Failure.Code, ExpectedFailure.Code);
        EXPECT_EQ(First.Failure.Native, ExpectedFailure.Native);
        EXPECT_TRUE(Payload.empty());
        EXPECT_EQ(Carrier->ReadCalls(), 5U);

        const auto Retry = co_await Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(Retry.PayloadBytes, 0U);
        EXPECT_EQ(Retry.WireBytes, 0U);
        EXPECT_EQ(Retry.Failure.Code, ExpectedFailure.Code);
        EXPECT_EQ(Retry.Failure.Native, ExpectedFailure.Native);
        EXPECT_TRUE(Payload.empty());
        EXPECT_EQ(Carrier->ReadCalls(), 5U);

        const auto DatagramClose = Datagram->Close();
        EXPECT_TRUE(DatagramClose.has_value());
        const auto DatagramDrain = co_await Datagram->Activity()->Drain();
        EXPECT_TRUE(DatagramDrain.has_value());
        EXPECT_TRUE(Carrier->IsClosed());
        const auto CarrierDrain = co_await Carrier->Activity()->Drain();
        EXPECT_TRUE(CarrierDrain.has_value());
    }

    /** @brief 使用完整 coroutine 调度推进一次测试操作。 */
    auto RunCoroutine(Net::io_context& IoContext, Net::awaitable<void> Operation) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, std::move(Operation),
            [&Exception](std::exception_ptr Error)
            {
                Exception = std::move(Error);
            });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }
} // namespace

TEST(TrojanDatagramSessionTerminal, CompletePacketPrecedesEof)
{
    Net::io_context IoContext;
    RunCoroutine(IoContext, RunCompletePacketBeforeTerminal(IoContext, {
        {Prism::Fault::Code::Eof}, {}}));
}

TEST(TrojanDatagramSessionTerminal, CompletePacketPrecedesNativeReset)
{
    Net::io_context IoContext;
    const auto Reset = Prism::Fault::FromNative(
        std::make_error_code(std::errc::connection_reset));
    RunCoroutine(IoContext, RunCompletePacketBeforeTerminal(IoContext, {Reset, Reset}));
}

TEST(TrojanDatagramSessionTerminal, CompletePacketPrecedesCanceledTerminal)
{
    Net::io_context IoContext;
    const Prism::Fault::Failure Canceled{
        Prism::Fault::Code::Canceled,
        std::make_error_code(std::errc::operation_canceled)};
    RunCoroutine(IoContext, RunCompletePacketBeforeTerminal(IoContext, {Canceled, Canceled}));
}

TEST(TrojanDatagramSessionTerminal, PartialPayloadEofIsSticky)
{
    Net::io_context IoContext;
    RunCoroutine(IoContext, RunPartialPayloadTerminalIsSticky(
        IoContext, {Prism::Fault::Code::Eof}));
}

TEST(TrojanDatagramSessionTerminal, PartialPayloadNativeResetIsSticky)
{
    Net::io_context IoContext;
    RunCoroutine(IoContext, RunPartialPayloadTerminalIsSticky(
        IoContext, ResetFailure()));
}
