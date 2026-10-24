/**
 * @file VlessUdpTunnelTerminalTest.cpp
 * @brief VLESS UDP 长度帧与同次读取终态的顺序回归。
 */
#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/this_coro.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <exception>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Vless/Conn.hpp>
#include <Prism/Protocols/Vless/UdpTunnelFrames.hpp>
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

    struct ReadScenario final
    {
        std::vector<std::byte> Input;
        Fault::Failure Terminal;
        bool CompleteFrame{false};
        Fault::Code FirstCode{Fault::Code::IoError};
        std::size_t FirstTransferred{0};
        std::size_t ExpectedReads{0};
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

    /** @brief 关闭测试载体并等待它自己的 I/O 预约退出。 */
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

    /** @brief 等待已由协议载体关闭的底层测试传输退出。 */
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

    [[nodiscard]] auto CompleteFrameWire() -> std::vector<std::byte>
    {
        return {
            std::byte{0x00}, std::byte{0x02},
            std::byte{0xA1}, std::byte{0xA2}};
    }

    auto RunScenario(ReadScenario Scenario) -> Net::awaitable<void>
    {
        const auto Executor = co_await Net::this_coro::executor;
        auto Raw = std::make_shared<TerminalTransmission>(
            Executor,
            std::move(Scenario.Input), Scenario.Terminal);
        const auto Uuid = std::array<std::uint8_t, Vless::UuidLen>{};
        auto Stream = std::make_shared<Vless::Conn<>>(Raw, Uuid);
        Vless::UdpTunnelFrames Frames(
            Stream, std::chrono::milliseconds::zero(), Executor);

        const auto First = co_await Frames.Read();
        EXPECT_EQ(static_cast<bool>(First), Scenario.CompleteFrame);
        if (First)
        {
            EXPECT_TRUE(Scenario.CompleteFrame);
            EXPECT_EQ(*First, (std::vector<std::uint8_t>{0x00, 0x02, 0xA1, 0xA2}));
        }
        else
        {
            EXPECT_FALSE(Scenario.CompleteFrame);
            EXPECT_EQ(First.error().Cause.Code, Scenario.FirstCode);
            EXPECT_EQ(First.error().Cause.Native, Scenario.Terminal.Native);
            EXPECT_EQ(First.error().Transferred, Scenario.FirstTransferred);
        }

        const auto Reads = Raw->ReadsDone();
        EXPECT_EQ(Reads, Scenario.ExpectedReads);
        const auto Next = co_await Frames.Read();
        EXPECT_FALSE(Next);
        if (!Next)
        {
            EXPECT_EQ(Next.error().Cause.Code, Scenario.Terminal.Code);
            EXPECT_EQ(Next.error().Cause.Native, Scenario.Terminal.Native);
            EXPECT_EQ(Next.error().Transferred, 0U);
        }
        EXPECT_EQ(Raw->ReadsDone(), Reads);
        EXPECT_TRUE(co_await CloseAndDrain(*Stream));
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

    TEST(VlessUdpTunnelTerminalRead, CompleteFramePrecedesEof)
    {
        RunCoroutine(RunScenario({CompleteFrameWire(), EofFailure(), true,
                                  Fault::Code::IoError, 0U, 2U}));
    }

    TEST(VlessUdpTunnelTerminalRead, CompleteFramePrecedesReset)
    {
        RunCoroutine(RunScenario({CompleteFrameWire(), ResetFailure(), true,
                                  Fault::Code::IoError, 0U, 2U}));
    }

    TEST(VlessUdpTunnelTerminalRead, PartialHeaderEofIsSticky)
    {
        RunCoroutine(RunScenario({{std::byte{0x00}}, EofFailure(), false,
                                  Fault::Code::BadMessage, 1U, 1U}));
    }

    TEST(VlessUdpTunnelTerminalRead, PartialHeaderResetIsSticky)
    {
        RunCoroutine(RunScenario({{std::byte{0x00}}, ResetFailure(), false,
                                  Fault::Code::ConnectionReset, 1U, 1U}));
    }

    TEST(VlessUdpTunnelTerminalRead, PartialPayloadEofIsSticky)
    {
        RunCoroutine(RunScenario({
            {std::byte{0x00}, std::byte{0x02}, std::byte{0xA1}},
            EofFailure(), false, Fault::Code::BadMessage, 1U, 2U}));
    }

    TEST(VlessUdpTunnelTerminalRead, PartialPayloadResetIsSticky)
    {
        RunCoroutine(RunScenario({
            {std::byte{0x00}, std::byte{0x02}, std::byte{0xA1}},
            ResetFailure(), false, Fault::Code::ConnectionReset, 1U, 2U}));
    }

    TEST(VlessUdpTunnelTerminalRead, CleanBoundaryEofIsStable)
    {
        RunCoroutine(RunScenario({{}, EofFailure(), false, Fault::Code::Eof, 0U, 1U}));
    }
} // namespace
